#!/bin/bash
# sandbox-reset.sh의 감사 로그 삭제 단계(T58) 시험. DB 없이 돈다(psql은 함수로 흉내 낸다).
#   bash scripts/sandbox-reset-daily-test.sh [sandbox-reset.sh 경로]
# 보는 것:
#   A. 하루 한 번 판정 함수 audit_purge_decision(오늘 날짜, 마지막으로 부른 날짜, 그때 결과)
#   B. 주기를 이어 돌릴 때의 호출 여부(같은 날 OK 뒤에는 SKIP, 실패한 날은 다음 주기에 다시, 날짜가 바뀌면 다시, --once는 늘, 기한 없음은 OFF)
#   C. 한 줄 로그의 감사 칸과 전체 상태(감사 칸은 ERROR일 때만 전체를 ERROR로), 칸마다 400자 자르기
#   D. SANDBOX_AUDIT_RETENTION_DAYS 검사(비었거나 0 또는 정수 30~3650, 아니면 exit 2)
# 줄마다 PASS 또는 FAIL을 찍고 FAIL이 있으면 종료 코드 1.
set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker/portfolio/sandbox/sandbox-reset.sh}"
set --
if [ ! -f "$SCRIPT" ]; then
    echo "sandbox-reset-daily-test: $SCRIPT not found" >&2
    exit 2
fi

FAILS=0
CHECKS=0
check() { # check <이름> <기대> <실제>
    CHECKS=$((CHECKS + 1))
    if [ "$2" = "$3" ]; then
        echo "PASS $1 (= $3)"
    else
        echo "FAIL $1 (expected '$2', got '$3')"
        FAILS=$((FAILS + 1))
    fi
}

# 함수만 가져온다(스크립트는 source되면 주기 실행 전에 끝난다). 기한 값은 90으로 둔다.
export SANDBOX_AUDIT_RETENTION_DAYS=90 SANDBOX_RESET_DB_PASSWORD=not-used-by-this-test
# shellcheck disable=SC1090
source "$SCRIPT"
set +e

echo "# A. audit_purge_decision <today> <last date> <last state>"
check "A1 first cycle after start (no previous call)" CALL "$(audit_purge_decision 2026-11-26 '' '')"
check "A2 same day, previous OK" SKIP "$(audit_purge_decision 2026-11-26 2026-11-26 OK)"
check "A3 date changed, previous OK" CALL "$(audit_purge_decision 2026-11-27 2026-11-26 OK)"
check "A4 same day, previous ERROR" CALL "$(audit_purge_decision 2026-11-26 2026-11-26 ERROR)"
check "A5 same day, previous NOT_CONFIGURED" CALL "$(audit_purge_decision 2026-11-26 2026-11-26 NOT_CONFIGURED)"
check "A6 date changed, previous ERROR" CALL "$(audit_purge_decision 2026-11-27 2026-11-26 ERROR)"

echo "# B. cycles (audit_step with a fake clock and a fake audit_call)"
FAKE_TODAY=2026-11-26
FAKE_NEXT_STATE=OK
CALLS=0
date() { # audit_step은 date -u +%Y-%m-%d만 쓴다
    if [ "${2:-}" = "+%Y-%m-%d" ]; then echo "$FAKE_TODAY"; else command date "$@"; fi
}
audit_call() { CALLS=$((CALLS + 1)); STATE="$FAKE_NEXT_STATE"; RESULT="fake"; }
cycle() { # cycle <이름> <이번에 부르면 나올 결과> <기대 칸> <기대 누적 호출 수>
    FAKE_NEXT_STATE="$2"
    audit_step
    check "$1" "$3 calls=$4" "$STATE calls=$CALLS"
}
ONCE=0; AUDIT_DAYS=90; AUDIT_LAST_DATE=""; AUDIT_LAST_STATE=""
cycle "B1 day 1, cycle 1: first cycle calls (result ERROR)" ERROR ERROR 1
cycle "B2 day 1, cycle 2: called again after a failure (result NOT_CONFIGURED)" NOT_CONFIGURED NOT_CONFIGURED 2
cycle "B3 day 1, cycle 3: called again (result OK)" OK OK 3
cycle "B4 day 1, cycle 4: SKIP after OK on the same day" OK SKIP 3
cycle "B5 day 1, cycle 5: still SKIP" ERROR SKIP 3
FAKE_TODAY=2026-11-27
cycle "B6 day 2, cycle 1: date changed, called (result OK)" OK OK 4
cycle "B7 day 2, cycle 2: SKIP" OK SKIP 4
ONCE=1
cycle "B8 --once always calls even after OK on the same day" OK OK 5
ONCE=0; AUDIT_DAYS=0
cycle "B9 no retention configured: OFF, not called" OK OFF 5
AUDIT_DAYS=90

echo "# C. one-line log (run_once with a fake psql)"
FAKE_AUDIT_CHECK=ok
FAKE_AUDIT_RC=0
FAKE_AUDIT_OUT="purged=3 cutoff=2026-08-28T00:00:00Z"
unset -f audit_call date
# 스크립트의 원래 audit_call을 다시 가져온다.
source "$SCRIPT"
set +e
psql() {
    case "$*" in
        *has_function_privilege*) echo "$FAKE_AUDIT_CHECK" ;;
        *"FROM public.purge_expired_audit_logs("*) printf '%s\n' "$FAKE_AUDIT_OUT"; return "$FAKE_AUDIT_RC" ;;
        *to_regprocedure*) echo t ;;
        *sandbox.reset_pipeline*) echo "analyst_review(-0 +0 ~0) incident_status(-0 +0 ~0) incident_status_history(-0 +0 ~0)" ;;
        *sandbox.reset_assignments*) echo "released=0 history+=0" ;;
        *) echo "unexpected psql call: $*"; return 1 ;;
    esac
}
strip_time() { sed -e 's/^[0-9TZ:-]* //'; }
BASE="pipeline[OK] analyst_review(-0 +0 ~0) incident_status(-0 +0 ~0) incident_status_history(-0 +0 ~0); assignments[OK] released=0 history+=0"
ONCE=1; AUDIT_DAYS=90
line="$(run_once | strip_time)"; rc=$?
check "C1 audit OK" "sandbox-reset: OK $BASE; audit[OK] purged=3 cutoff=2026-08-28T00:00:00Z" "$line"
run_once > /dev/null; check "C1 exit code" 0 "$?"

FAKE_AUDIT_CHECK=no_execute
line="$(run_once | strip_time)"
check "C2 no EXECUTE yet: NOT_CONFIGURED, overall stays OK" \
    "sandbox-reset: OK $BASE; audit[NOT_CONFIGURED] no EXECUTE on public.purge_expired_audit_logs(integer) (run sandbox-setup)" "$line"
run_once > /dev/null; check "C2 exit code" 0 "$?"

FAKE_AUDIT_CHECK=missing
line="$(run_once | strip_time)"
check "C3 function missing: NOT_CONFIGURED, overall stays OK" \
    "sandbox-reset: OK $BASE; audit[NOT_CONFIGURED] public.purge_expired_audit_logs(integer) is missing (start the app with migration V4 first)" "$line"

FAKE_AUDIT_CHECK=ok; FAKE_AUDIT_RC=1
FAKE_AUDIT_OUT="ERROR:  audit_logs is append-only: DELETE is forbidden $(printf 'x%.0s' $(seq 1 900))"
line="$(run_once | strip_time)"
case "$line" in
    "sandbox-reset: ERROR $BASE; audit[ERROR] ERROR: audit_logs is append-only: DELETE is forbidden x"*) got=yes ;;
    *) got="no: $line" ;;
esac
check "C4 audit ERROR makes the whole line ERROR" yes "$got"
audit_part="${line##*; audit\[ERROR\] }"
check "C4 audit cell is cut at 400 characters (per cell, the marker survives)" 400 "${#audit_part}"
run_once > /dev/null; check "C4 exit code" 1 "$?"

FAKE_AUDIT_RC=0; FAKE_AUDIT_OUT="purged=0 cutoff=2026-08-28T00:00:00Z"
AUDIT_DAYS=0
line="$(run_once | strip_time)"
check "C5 no retention configured" "sandbox-reset: OK $BASE; audit[OFF]" "$line"
AUDIT_DAYS=90; ONCE=0; AUDIT_LAST_DATE=""; AUDIT_LAST_STATE=""
line1="$(run_once | strip_time)"
check "C6 resident mode, first cycle" "sandbox-reset: OK $BASE; audit[OK] purged=0 cutoff=2026-08-28T00:00:00Z" "$line1"
# 위는 $( ) 안(하위 셸)에서 돌아 상태가 남지 않는다. 상태를 남기려고 한 번은 이 셸에서 돌린다.
run_once > /dev/null
line2="$(run_once | strip_time)"
check "C7 resident mode, second cycle on the same day" "sandbox-reset: OK $BASE; audit[SKIP]" "$line2"

echo "# D. SANDBOX_AUDIT_RETENTION_DAYS validation (the script itself, --once, empty DB password so nothing is called)"
run_env() { # run_env <값> -> 종료 코드
    SANDBOX_AUDIT_RETENTION_DAYS="$1" SANDBOX_RESET_DB_PASSWORD="" bash "$SCRIPT" --once > /dev/null 2>&1
    echo $?
}
for v in "" 0 30 90 365 3650; do
    check "D accepted value '$v'" 0 "$(run_env "$v")"
done
for v in 1 29 3651 99999 -1 090 00 9.5 1e2 abc "90 " " 90" "90;SELECT 1" "90)--"; do
    check "D rejected value '$v'" 2 "$(run_env "$v")"
done
unset_rc="$(env -u SANDBOX_AUDIT_RETENTION_DAYS SANDBOX_RESET_DB_PASSWORD="" bash "$SCRIPT" --once > /dev/null 2>&1; echo $?)"
check "D variable not set at all" 0 "$unset_rc"

if [ "$FAILS" -eq 0 ]; then
    echo "RESULT: PASS ($CHECKS checks)"
    exit 0
fi
echo "RESULT: FAIL ($FAILS of $CHECKS checks failed)"
exit 1
