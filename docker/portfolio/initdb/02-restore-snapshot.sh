#!/bin/bash
# 포트폴리오 스택 PostgreSQL 초기화 2단계: zeek_AD 스냅샷(scripts/portfolio-snapshot.ps1의 zeekad.dump)을 복원한다.
# - 소유자·권한(GRANT)까지 복원한다(--no-owner·--no-privileges를 쓰지 않는다). 역할은 01단계가 만들었다.
# - superuser(postgres)로 복원하므로 superuser가 필요한 vector 확장도 덤프의 CREATE EXTENSION으로 만들어진다.
# - 오류가 하나라도 나면 멈춘다(--exit-on-error). 성공했을 때만 데이터 폴더에 표지 파일을 남기고,
#   컨테이너 헬스체크가 이 표지를 확인한다. 그래서 복원이 중간에 실패한 데이터 폴더로 재시작돼도 healthy가 되지 않는다.
set -euo pipefail

SNAPSHOT_DIR=/snapshot
MARKER="$PGDATA/portfolio-restore.ok"

if [ ! -f "$SNAPSHOT_DIR/zeekad.dump" ] || [ ! -f "$SNAPSHOT_DIR/zeekad.dump.sha256" ]; then
    echo "portfolio-restore: $SNAPSHOT_DIR/zeekad.dump or zeekad.dump.sha256 is missing" >&2
    exit 1
fi

echo "portfolio-restore: verifying snapshot checksum"
(cd "$SNAPSHOT_DIR" && sha256sum -c zeekad.dump.sha256)

echo "portfolio-restore: pg_restore --exit-on-error into zeekad (owners and privileges included)"
pg_restore --username "$POSTGRES_USER" --dbname zeekad --exit-on-error --verbose "$SNAPSHOT_DIR/zeekad.dump" 2>&1 \
    | sed 's/^/portfolio-restore: /'

# 복원 직후에는 플래너 통계가 없어 행 수 추정이 어긋난다(T35에서 큐가 느려진 일). 자동 통계를 기다리지 않고 바로 만든다(T39).
echo "portfolio-restore: ANALYZE zeekad"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zeekad -c "ANALYZE" | sed 's/^/portfolio-restore: /'

echo "portfolio-restore: incidents per capture (dashboard.latest_incident_queue)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zeekad -AtF ' = ' \
    -c "SELECT capture_id, count(*) FROM dashboard.latest_incident_queue GROUP BY capture_id ORDER BY capture_id" \
    | sed 's/^/portfolio-restore:   /'

cut -d' ' -f1 "$SNAPSHOT_DIR/zeekad.dump.sha256" > "$MARKER"
echo "portfolio-restore: done (marker $MARKER)"
