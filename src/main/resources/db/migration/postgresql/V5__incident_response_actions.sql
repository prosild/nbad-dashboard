-- T56 대응 조치 기록: 분석가가 인시던트에 어떤 조치를 했다고 적은 기록(누가 언제 무엇을). 이 콘솔은 차단·격리를 실행하지 않는다.
-- 조치는 종결 전에 여러 번 일어나므로 인시던트마다 여러 행을 덧붙인다. 대시보드 사용자가 쓰는 글이라 대시보드 자체 DB에 둔다.
-- 기록은 고칠 수 없다.
-- - UPDATE와 TRUNCATE는 어떤 경우에도 거부한다.
-- - DELETE는 표식 dashboard.response_actions_reset = 'on'일 때만 통과한다. 공개 데모의 초기화 함수(sandbox.reset_response_actions,
--   배포 도구 sandbox-setup.sh가 만든다)가 트랜잭션 안에서만 켠다. 앱 코드에는 이 표를 고치거나 지우는 문장이 없다.
-- - 표식은 권한 경계가 아니라 실수 방지다(V4의 감사 로그와 같은 꼴). 사용자 정의 설정은 어느 역할이든 세션에서 켤 수 있다.
--   권한 경계는 표 소유권이다(표에 DELETE 권한이 있는 역할은 소유자 dashboard_app뿐).

CREATE TABLE incident_response_actions (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(255) NOT NULL,
    -- 기록할 때의 캡처와 작업. 인시던트가 다시 분석돼 순위나 작업이 바뀌어도 기록은 incident_id로 따라간다.
    capture_id VARCHAR(128) NOT NULL,
    job_id BIGINT NOT NULL,
    action_type VARCHAR(32) NOT NULL CHECK (action_type IN (
        'block_ip', 'isolate_host', 'lock_account', 'handover', 'monitor', 'none', 'other')),
    -- 메모(앱이 500 코드 포인트로 막는다). none·other는 앱이 필수로 받는다.
    note VARCHAR(500),
    actor_username VARCHAR(100) NOT NULL,
    -- 조치한 시각이 아니라 기록한 시각이다.
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_incident_response_actions_incident ON incident_response_actions (incident_id);

CREATE OR REPLACE FUNCTION prevent_response_action_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- TG_OP를 먼저 본다: 문장 수준(TRUNCATE) 호출에는 OLD가 없다.
    IF TG_OP = 'DELETE' THEN
        IF current_setting('dashboard.response_actions_reset', true) = 'on' THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'incident_response_actions is append-only: % is forbidden', TG_OP;
END;
$$;

CREATE TRIGGER trg_incident_response_actions_immutable
BEFORE UPDATE OR DELETE ON incident_response_actions
FOR EACH ROW
EXECUTE FUNCTION prevent_response_action_mutation();

CREATE TRIGGER trg_incident_response_actions_no_truncate
BEFORE TRUNCATE ON incident_response_actions
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_response_action_mutation();
