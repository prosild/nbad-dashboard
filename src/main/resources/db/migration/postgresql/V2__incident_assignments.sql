-- T25 담당자: 현재 값(인시던트당 한 행)과 추가만 하는 변경 이력.
-- 담당자는 대시보드 사용자(users)를 가리키므로 대시보드 자체 DB에 둔다(zeekad DB는 바꾸지 않는다).

CREATE TABLE incident_assignments (
    incident_id VARCHAR(255) PRIMARY KEY,
    -- 지정할 때의 캡처(incident_id 접두와 같고 바뀌지 않는다). 담당 목록을 미리 줄이는 데만 쓴다.
    capture_id VARCHAR(128) NOT NULL,
    -- 해제하면 NULL. 행은 지우지 않는다.
    assignee_user_id BIGINT REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL,
    assigned_by VARCHAR(100) NOT NULL,
    version INT NOT NULL
);

CREATE INDEX idx_incident_assignments_assignee ON incident_assignments (assignee_user_id);
CREATE INDEX idx_incident_assignments_capture ON incident_assignments (capture_id);

CREATE TABLE incident_assignment_history (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(255) NOT NULL,
    capture_id VARCHAR(128) NOT NULL,
    job_id BIGINT,
    from_user_id BIGINT REFERENCES users(id),
    to_user_id BIGINT REFERENCES users(id),
    actor_username VARCHAR(100) NOT NULL,
    reason VARCHAR(32) NOT NULL CHECK (reason IN ('manual', 'auto_on_start')),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_incident_assignment_history_incident ON incident_assignment_history (incident_id, changed_at DESC);

CREATE OR REPLACE FUNCTION prevent_assignment_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'incident_assignment_history is append-only: % is forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incident_assignment_history_immutable
BEFORE UPDATE OR DELETE ON incident_assignment_history
FOR EACH ROW
EXECUTE FUNCTION prevent_assignment_history_mutation();
