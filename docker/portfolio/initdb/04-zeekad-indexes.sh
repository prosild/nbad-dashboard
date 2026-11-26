#!/bin/bash
# 포트폴리오 스택 PostgreSQL 초기화 4단계(T57): 스냅샷(2단계가 복원한 zeekad DB)에 대시보드가 읽는 계약 뷰를 빠르게 하는 인덱스를 더한다.
# - 계약 뷰 dashboard.latest_incident_queue는 행마다 "그 인시던트의 가장 최근 리포트"를
#   zeekad.agent_report에서 incident_id로 찾는다(LATERAL ... WHERE r.incident_id = q.incident_id ORDER BY r.job_id DESC LIMIT 1).
#   그 표의 인덱스는 기본 키 (job_id, incident_id)뿐이라 찾을 때마다 인덱스 전체를 훑는다. 2026-11-26 스냅샷(T66)에서
#   숨김 캡처 lab-20261123의 리포트가 늘어 agent_report가 333 -> 2,857행이 되자 목록·상세·이웃 응답이 약 3배 느려졌다
#   (handoff/T57/evidence/slowdown-diagnosis.md). 이 인덱스는 결과를 바꾸지 않는다(같은 질의의 결과가 인덱스 앞뒤로 같다).
# - 탐지 저장소의 표에 더하는 것이지만 볼륨 안에서만 생긴다(스냅샷 덤프는 읽기만 한다). 이미 있으면(새 스냅샷이 담고 있으면) 그대로 둔다.
# - 실패하면 2단계가 남긴 복원 표지 파일을 지우고 0이 아닌 값으로 끝낸다. 초기화가 멈추고, 다시 시작해도 상태 확인이 healthy가 되지 않는다.
# - 공식 이미지는 실행 권한이 없는 *.sh를 source로 읽는다. 그래도 되게 exit 0과 trap을 쓰지 않고, 이름은 zeekad_ 접두로 둔다(3단계와 같은 꼴).
set -euo pipefail

ZEEKAD_INDEXES_MARKER="$PGDATA/portfolio-restore.ok"

zeekad_indexes_fail() {
    echo "portfolio-indexes: $1; removing restore marker $ZEEKAD_INDEXES_MARKER" >&2
    rm -f "$ZEEKAD_INDEXES_MARKER"
    exit 1
}

if ! zeekad_index_before=$(psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zeekad -At -c \
        "SELECT to_regclass('zeekad.agent_report_incident_job_idx') IS NOT NULL"); then
    zeekad_indexes_fail "could not look up zeekad.agent_report_incident_job_idx"
fi

if ! psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname zeekad -q \
        -c "CREATE INDEX IF NOT EXISTS agent_report_incident_job_idx ON zeekad.agent_report (incident_id, job_id DESC);" \
        -c "ANALYZE zeekad.agent_report;"; then
    zeekad_indexes_fail "creating agent_report_incident_job_idx failed"
fi

if [ "$zeekad_index_before" = "t" ]; then
    echo "portfolio-indexes: agent_report_incident_job_idx already exists"
else
    echo "portfolio-indexes: agent_report_incident_job_idx created"
fi
