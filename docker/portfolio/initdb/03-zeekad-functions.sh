#!/bin/bash
# 포트폴리오 스택 PostgreSQL 초기화 3단계(T53): 대시보드가 부르는 zeek_AD 함수 가운데 스냅샷(2단계가 복원한 zeekad DB)에 없는 것을 넣는다.
# - 지금은 zeek_AD migration 018 하나다(dashboard.reopen_incident, 종결한 사건 다시 열기). 2026-11-23 스냅샷에는 이 함수가 없다.
#   zeek_AD는 스냅샷 복원 DB에 이 파일 하나만 실행하면 된다고 적었다(다시 실행해도 결과가 같다).
# - 사본은 하위 폴더 zeekad-sql/에 바이트 그대로 둔다. 이 폴더 맨 위의 *.sql은 공식 이미지가 postgres DB에 자동 실행하기 때문이다
#   (하위 폴더는 보지 않는다). 출처(zeek_AD commit)와 sha256은 zeekad-sql/SOURCE.md에 있다.
# - 스냅샷에 dashboard.reopen_incident라는 이름의 함수가 하나라도 있으면 건너뛴다(서명까지 보지 않는다). 새로 뜬 스냅샷이
#   더 새 함수를 담고 있을 때 옛 사본이 덮거나 겹치지 않게 한다.
# - 실패하면 2단계가 남긴 복원 표지 파일을 지우고 0이 아닌 값으로 끝낸다. 초기화가 멈추고, 다시 시작해도 상태 확인이 healthy가 되지 않는다.
# - 공식 이미지는 실행 권한이 없는 *.sh를 source로 읽는다. 그래도 되게 exit 0과 trap을 쓰지 않고(건너뛸 때도 끝까지 흘러간다),
#   이름은 zeekad_ 접두로 둔다.
set -euo pipefail

ZEEKAD_FUNCTIONS_MARKER="$PGDATA/portfolio-restore.ok"
ZEEKAD_REOPEN_SQL=/docker-entrypoint-initdb.d/zeekad-sql/018_incident_reopen.sql

zeekad_functions_fail() {
    echo "portfolio-functions: $1; removing restore marker $ZEEKAD_FUNCTIONS_MARKER" >&2
    rm -f "$ZEEKAD_FUNCTIONS_MARKER"
    exit 1
}

if ! zeekad_reopen_count=$(psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zeekad -At -c \
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dashboard' AND p.proname = 'reopen_incident'"); then
    zeekad_functions_fail "could not look up dashboard.reopen_incident in zeekad"
fi

if [ "$zeekad_reopen_count" != "0" ]; then
    echo "portfolio-functions: dashboard.reopen_incident already exists in zeekad (functions: $zeekad_reopen_count); skipping $ZEEKAD_REOPEN_SQL"
else
    if [ ! -f "$ZEEKAD_REOPEN_SQL" ]; then
        zeekad_functions_fail "$ZEEKAD_REOPEN_SQL is missing"
    fi
    echo "portfolio-functions: applying $ZEEKAD_REOPEN_SQL to zeekad (single transaction)"
    if ! psql -v ON_ERROR_STOP=1 --single-transaction --username "$POSTGRES_USER" --dbname zeekad -f "$ZEEKAD_REOPEN_SQL" 2>&1 \
            | sed 's/^/portfolio-functions: /'; then
        zeekad_functions_fail "applying $ZEEKAD_REOPEN_SQL failed"
    fi
    echo "portfolio-functions: dashboard.reopen_incident created"
fi
