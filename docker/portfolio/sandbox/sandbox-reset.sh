#!/bin/bash
# 포트폴리오 스택 체험 계정 초기화 서비스(T33). compose.portfolio.yml의 sandbox-reset(상주)이 실행한다.
#   bash sandbox-reset.sh          # 상주: 주기 경계(기본 60분 = 매시 정각, UTC·KST 모두 정각)마다 한 번. 시작할 때는 돌리지 않는다.
#   bash sandbox-reset.sh --once   # 한 번만(운영자 확인용)
# 한 번 = zeekad의 sandbox.reset_pipeline() 다음 zeekad_dashboard의 sandbox.reset_assignments(). 결과(표마다 지운·넣은·되돌린 행 수,
# 해제한 담당 수)를 한 줄로 남긴다. 실패하면 남기고 다음 경계에 다시 한다. 함수가 아직 없으면(sandbox-setup 전) 오류가 아니라 NOT_CONFIGURED.
# 두 DB는 따로 초기화되므로 그 사이(밀리초)에 들어온 쓰기는 다음 경계까지 어긋날 수 있다(docs/security-verification-report.md 남은 위험).
# 접속 계정은 zeekad_sandbox_reset(두 함수 EXECUTE만). 비밀번호는 환경 변수로만 받고 출력하지 않는다.
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
    local overall=OK
    # 설정 전(역할·함수 없음)은 오류가 아니라 미설정이다. 역할이 없으면 로그인이 실패하므로 비밀번호 불일치와 구별하지 못한다.
    if [ "${p_state#NOT_CONFIGURED}" != "$p_state" ] && [ "${a_state#NOT_CONFIGURED}" != "$a_state" ]; then
        overall="$p_state"
    elif [ "$p_state" != OK ] || [ "$a_state" != OK ]; then
        overall=ERROR
    fi
    say "$overall pipeline[$p_state] $p_result; assignments[$a_state] $a_result"
    [ "$overall" = ERROR ] && return 1
    return 0
}

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
