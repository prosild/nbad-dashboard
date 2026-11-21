-- T27 인시던트 번호: 인시던트마다 바뀌지 않는 번호(전역 순서, 추가만).
-- zeekad DB는 바꾸지 않는다. 번호는 대시보드가 zeekad 최신 큐 값으로 매긴다.

CREATE TABLE incident_refs (
    incident_no BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(255) NOT NULL UNIQUE,
    -- 매길 때의 캡처(incident_id 접두와 같다)
    capture_id VARCHAR(128) NOT NULL,
    -- 매길 때의 탐지 시각(그 incident_id가 든 성공 작업 중 가장 이른 완료 시각). 순서 확인용
    detected_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE OR REPLACE FUNCTION prevent_incident_refs_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'incident_refs is append-only: % is forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incident_refs_immutable
BEFORE UPDATE OR DELETE ON incident_refs
FOR EACH ROW
EXECUTE FUNCTION prevent_incident_refs_mutation();
