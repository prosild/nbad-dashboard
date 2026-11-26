#!/bin/bash
# 포트폴리오 스택 체험 계정 초기화 서비스(T33). compose.portfolio.yml의 sandbox-reset(상주)이 실행한다.
#   bash sandbox-reset.sh          # 상주: 주기 경계(기본 60분 = 매시 정각, UTC·KST 모두 정각)마다 한 번. 시작할 때는 돌리지 않는다.
#   bash sandbox-reset.sh --once   # 한 번만(운영자 확인용)
# 한 번 = zeekad의 sandbox.reset_pipeline() 다음 zeekad_dashboard의 sandbox.reset_assignments()와 sandbox.reset_response_actions(). 결과(표마다
# 지운·넣은·되돌린 행 수, 해제한 담당 수, 지운 대응 조치 기록 수)를 한 줄로 남긴다. 실패하면 남기고 다음 경계에 다시 한다. 함수가 아직 없으면(sandbox-setup 전) 오류가 아니라 NOT_CONFIGURED.
# 대응 조치(T56): 기준선 뒤에 덧붙은 기록을 매 주기 지운다(responses[...] 칸). 함수가 없거나 실행 권한이 없으면 NOT_CONFIGURED이고 전체 상태를 바꾸지 않는다
# (새 스크립트가 sandbox-setup 재실행보다 먼저 도는 반영 틈). 호출이 실패하면(기준선 표식 없음 포함) ERROR다.
# 두 DB는 따로 초기화되므로 그 사이(밀리초)에 들어온 쓰기는 다음 경계까지 어긋날 수 있다(docs/security-verification-report.md 남은 위험).
# 감사 로그 보관 기한(T58): SANDBOX_AUDIT_RETENTION_DAYS(정수 30~3650)가 있으면 하루에 한 번(서비스가 뜬 뒤 첫 주기와 UTC 날짜가 바뀐 뒤
# 첫 주기. --once는 늘) 앱 DB의 public.purge_expired_audit_logs(<일>)를 불러 기한이 지난 감사 행을 지운다. 비었거나 0이면 지우지 않는다(audit[OFF]).
# 그날 몫은 결과가 OK일 때만 쓴 것으로 친다(ERROR·NOT_CONFIGURED면 다음 주기에 다시 부른다). 결과는 같은 줄 끝의 audit[...] 칸에 남긴다.
# 접속 계정은 zeekad_sandbox_reset(초기화 함수 셋과 위 삭제 함수 EXECUTE만. 표 권한 없음). 비밀번호는 환경 변수로만 받고 출력하지 않는다.
set -uo pipefail

ONCE=0
for arg in "$@"; do
    case "$arg" in
        --once) ONCE=1 ;;
        *) echo "sandbox-reset: unknown argument '$arg' (only --once)" >&2; exit 2 ;;
    esac
done

INTERVAL="${SANDBOX_RESET_INTERVAL_MINUTES:-60}"
case "$INTERVAL" in
    ''|*[!0-9]*) echo "sandbox-reset: SANDBOX_RESET_INTERVAL_MINUTES must be a positive integer (got '$INTERVAL')" >&2; exit 2 ;;
esac
if [ "$INTERVAL" -lt 1 ] || [ "$INTERVAL" -gt 1440 ]; then
    echo "sandbox-reset: SANDBOX_RESET_INTERVAL_MINUTES must be 1..1440 (got $INTERVAL)" >&2; exit 2
fi

# 감사 로그 보관 기한(일). 비었거나 0이면 삭제 단계를 돌지 않는다. 아래 검사를 통과한 정수만 SQL에 넣는다.
AUDIT_DAYS="${SANDBOX_AUDIT_RETENTION_DAYS:-}"
case "$AUDIT_DAYS" in
    '') AUDIT_DAYS=0 ;;
    *[!0-9]*) echo "sandbox-reset: SANDBOX_AUDIT_RETENTION_DAYS must be empty, 0 or an integer 30..3650 (got '$AUDIT_DAYS')" >&2; exit 2 ;;
esac
# 자릿수를 먼저 본다(긴 숫자·앞자리 0을 산술 비교에 넣지 않는다).
if [ "$AUDIT_DAYS" != 0 ]; then
    case "$AUDIT_DAYS" in
        [1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;;
        *) echo "sandbox-reset: SANDBOX_AUDIT_RETENTION_DAYS must be empty, 0 or an integer 30..3650 (got '$AUDIT_DAYS')" >&2; exit 2 ;;
    esac
    if [ "$AUDIT_DAYS" -lt 30 ] || [ "$AUDIT_DAYS" -gt 3650 ]; then
        echo "sandbox-reset: SANDBOX_AUDIT_RETENTION_DAYS must be empty, 0 or an integer 30..3650 (got $AUDIT_DAYS)" >&2; exit 2
    fi
fi

export PGHOST="${PGHOST:-postgres}" PGPORT="${PGPORT:-5432}" PGUSER=zeekad_sandbox_reset
export PGPASSWORD="${SANDBOX_RESET_DB_PASSWORD:-}" PGCONNECT_TIMEOUT=10 PGAPPNAME=sandbox-reset

say() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) sandbox-reset: $*"; }
oneline() { tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//' | cut -c1-400; }

# 함수 하나 부르기: 출력 한 줄을 돌려주고, 상태는 OK / NOT_CONFIGURED / ERROR
call() { # call <db> <function> <select list>
    local db="$1" fn="$2" cols="$3" out rc
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" -c "SELECT to_regprocedure('$fn()') IS NOT NULL" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=NOT_CONFIGURED_OR_LOGIN_FAILED; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    if [ "$out" != "t" ]; then
        STATE=NOT_CONFIGURED; RESULT="$fn() is missing (run sandbox-setup)"; return
    fi
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" -c "SELECT $cols FROM $fn()" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=ERROR; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    STATE=OK; RESULT="$(printf '%s' "$out" | oneline)"
}

RESPONSES_FN='sandbox.reset_response_actions()'

# 대응 조치 초기화 함수 부르기(T56): 상태는 OK / NOT_CONFIGURED / ERROR. 함수가 있고 이 계정에 EXECUTE가 있을 때만 부른다
# (새 스크립트가 sandbox-setup 재실행보다 먼저 도는 틈에 ERROR 줄이 생기지 않게 한다).
# 확인 쿼리 자체가 실패하면(역할 없음·로그인 실패·DB 내려감) 미설정으로 본다(그 사정은 앞 칸의 글에 남는다).
# 함수가 실패하면(기준선 표식 없음, 잠금 시간 초과 등) ERROR다.
responses_call() {
    local out rc
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d zeekad_dashboard -c "SELECT CASE WHEN to_regprocedure('$RESPONSES_FN') IS NULL THEN 'missing' WHEN has_function_privilege(current_user, to_regprocedure('$RESPONSES_FN')::oid, 'EXECUTE') THEN 'ok' ELSE 'no_execute' END" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=NOT_CONFIGURED; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    case "$out" in
        ok) ;;
        missing) STATE=NOT_CONFIGURED; RESULT="$RESPONSES_FN is missing (run sandbox-setup)"; return ;;
        *) STATE=NOT_CONFIGURED; RESULT="no EXECUTE on $RESPONSES_FN (run sandbox-setup)"; return ;;
    esac
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d zeekad_dashboard -c "SELECT format('removed=%s', removed) FROM sandbox.reset_response_actions()" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=ERROR; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    STATE=OK; RESULT="$(printf '%s' "$out" | oneline)"
}

# 감사 로그 삭제를 이번 주기에 부를지: CALL 또는 SKIP을 찍는다.
#   audit_purge_decision <오늘 UTC 날짜> <마지막으로 부른 UTC 날짜(없으면 빈 값)> <그때 결과(없으면 빈 값)>
# 같은 날 이미 OK였을 때만 SKIP이다. 처음, 날짜가 바뀐 뒤, 지난 결과가 OK가 아닐 때(ERROR·NOT_CONFIGURED)는 CALL.
audit_purge_decision() {
    local today="$1" last_date="${2:-}" last_state="${3:-}"
    if [ -n "$last_date" ] && [ "$last_date" = "$today" ] && [ "$last_state" = OK ]; then
        echo SKIP
    else
        echo CALL
    fi
}

AUDIT_FN='public.purge_expired_audit_logs(integer)'
AUDIT_LAST_DATE=""
AUDIT_LAST_STATE=""

# 삭제 함수 부르기: 상태는 OK / NOT_CONFIGURED / ERROR. 함수가 있고 이 계정에 EXECUTE가 있을 때만 부른다
# (앱이 V4를 적용한 뒤 sandbox-setup이 실행 권한을 주기 전의 틈에 ERROR 줄이 생기지 않게 한다).
# 확인 쿼리 자체가 실패하면(역할 없음·로그인 실패·DB 내려감) 앞의 두 칸과 같은 뜻으로 미설정으로 본다(그 사정은 앞 칸의 글에 남는다).
audit_call() {
    local out rc
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d zeekad_dashboard -c "SELECT CASE WHEN to_regprocedure('$AUDIT_FN') IS NULL THEN 'missing' WHEN has_function_privilege(current_user, to_regprocedure('$AUDIT_FN')::oid, 'EXECUTE') THEN 'ok' ELSE 'no_execute' END" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=NOT_CONFIGURED; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    case "$out" in
        ok) ;;
        missing) STATE=NOT_CONFIGURED; RESULT="$AUDIT_FN is missing (start the app with migration V4 first)"; return ;;
        *) STATE=NOT_CONFIGURED; RESULT="no EXECUTE on $AUDIT_FN (run sandbox-setup)"; return ;;
    esac
    out="$(psql -X -q -At -v ON_ERROR_STOP=1 -d zeekad_dashboard -c "SELECT format('purged=%s cutoff=%s', deleted, to_char(cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')) FROM public.purge_expired_audit_logs($AUDIT_DAYS)" 2>&1)"; rc=$?
    if [ $rc -ne 0 ]; then
        STATE=ERROR; RESULT="$(printf '%s' "$out" | oneline)"; return
    fi
    STATE=OK; RESULT="$(printf '%s' "$out" | oneline)"
}

# 이번 주기의 감사 칸을 정한다: OFF(기한 설정 없음) / SKIP(오늘 몫을 이미 OK로 씀) / audit_call의 결과
audit_step() {
    if [ "$AUDIT_DAYS" = 0 ]; then
        STATE=OFF; RESULT=""; return
    fi
    local today; today="$(date -u +%Y-%m-%d)"
    if [ "$ONCE" != "1" ] && [ "$(audit_purge_decision "$today" "$AUDIT_LAST_DATE" "$AUDIT_LAST_STATE")" = SKIP ]; then
        STATE=SKIP; RESULT=""; return
    fi
    audit_call
    AUDIT_LAST_DATE="$today"; AUDIT_LAST_STATE="$STATE"
}

run_once() {
    if [ -z "$PGPASSWORD" ]; then
        say "NOT_CONFIGURED (SANDBOX_RESET_DB_PASSWORD is empty)"
        return 0
    fi
    call zeekad sandbox.reset_pipeline \
        "string_agg(format('%s(-%s +%s ~%s)', table_name, deleted, inserted, reverted), ' ' ORDER BY table_name)"
    local p_state="$STATE" p_result="$RESULT"
    call zeekad_dashboard sandbox.reset_assignments "format('released=%s history+=%s', released, history_rows)"
    local a_state="$STATE" a_result="$RESULT"
    responses_call
    local s_state="$STATE" s_result="$RESULT"
    audit_step
    local r_state="$STATE" r_result="$RESULT"
    local overall=OK
    # 설정 전(역할·함수 없음)은 오류가 아니라 미설정이다. 역할이 없으면 로그인이 실패하므로 비밀번호 불일치와 구별하지 못한다.
    if [ "${p_state#NOT_CONFIGURED}" != "$p_state" ] && [ "${a_state#NOT_CONFIGURED}" != "$a_state" ]; then
        overall="$p_state"
    elif [ "$p_state" != OK ] || [ "$a_state" != OK ]; then
        overall=ERROR
    fi
    # 대응 조치 칸과 감사 칸은 ERROR일 때만 전체를 ERROR로 만든다. OFF·SKIP·NOT_CONFIGURED는 전체 상태를 바꾸지 않는다(줄에는 남는다).
    # "앞의 두 칸이 모두 미설정이면 전체 미설정"은 위처럼 두 칸(pipeline, assignments)만 본다.
    [ "$s_state" = ERROR ] && overall=ERROR
    [ "$r_state" = ERROR ] && overall=ERROR
    say "$overall pipeline[$p_state] $p_result; assignments[$a_state] $a_result; responses[$s_state]${s_result:+ $s_result}; audit[$r_state]${r_result:+ $r_result}"
    [ "$overall" = ERROR ] && return 1
    return 0
}

# 다른 스크립트가 함수만 쓰려고 source하면(판정 함수 시험: scripts/sandbox-reset-daily-test.sh) 여기서 끝낸다.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

if [ "$ONCE" = "1" ]; then
    run_once
    exit $?
fi

trap 'say "stopping"; exit 0' TERM INT
PERIOD=$((INTERVAL * 60))
say "started (every $INTERVAL min at epoch-aligned boundaries; first run at the next boundary)"
while true; do
    now=$(date -u +%s)
    next=$(( (now / PERIOD + 1) * PERIOD ))
    sleep $((next - now)) &
    wait $!
    run_once || true
done
