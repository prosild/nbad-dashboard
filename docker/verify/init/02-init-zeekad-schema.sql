\connect zeekad

CREATE SCHEMA IF NOT EXISTS dashboard;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA dashboard FROM PUBLIC;
GRANT USAGE ON SCHEMA dashboard TO dashboard_ro;
GRANT USAGE ON SCHEMA dashboard TO dashboard_rw;

CREATE TABLE dashboard.raw_scoring_jobs (
    job_id BIGINT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    error TEXT,
    incident_count INTEGER
);

CREATE TABLE dashboard.raw_model_bundles (
    bundle_id TEXT PRIMARY KEY,
    registry_name TEXT NOT NULL,
    registry_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    thresholds JSONB NOT NULL
);

CREATE TABLE dashboard.raw_incident_queue (
    job_id BIGINT NOT NULL,
    capture_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    queue_rank INTEGER NOT NULL,
    incident_id TEXT NOT NULL,
    host_ip TEXT NOT NULL,
    zeekad_role TEXT NOT NULL,
    event_start TIMESTAMPTZ NOT NULL,
    event_end TIMESTAMPTZ NOT NULL,
    zeekad_picked_by TEXT NOT NULL,
    zeekad_also_flagged_by TEXT[],
    connection_count BIGINT NOT NULL,
    host_name TEXT[],
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE dashboard.raw_incident_model_scores (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    zeekad_model TEXT NOT NULL,
    max_score DOUBLE PRECISION NOT NULL,
    candidate_windows INTEGER NOT NULL,
    windows INTEGER NOT NULL,
    PRIMARY KEY (job_id, incident_id, zeekad_model)
);

CREATE TABLE dashboard.raw_asset_names (
    capture_id TEXT NOT NULL,
    host_ip TEXT NOT NULL,
    kerberos_user TEXT,
    ntlm_user TEXT,
    source_log TEXT,
    observation_count INTEGER,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ
);

CREATE TABLE dashboard.raw_incident_reports (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    zeekad_report_kind TEXT NOT NULL,
    zeekad_report_version TEXT NOT NULL,
    zeekad_input_version TEXT,
    zeekad_report JSONB NOT NULL,
    zeekad_verification_passed BOOLEAN,
    zeekad_verification_reason TEXT,
    zeekad_verification_problems JSONB,
    llm_model_requested TEXT,
    llm_model_version TEXT,
    llm_seconds DOUBLE PRECISION,
    llm_input_tokens INTEGER,
    llm_output_tokens INTEGER,
    llm_thinking_tokens INTEGER,
    llm_error TEXT,
    zeekad_attack_candidates JSONB,
    zeekad_source_run TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    zeekad_facts JSONB,
    zeekad_pseudonyms JSONB,
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE dashboard.raw_send_decisions (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    zeekad_would_send BOOLEAN NOT NULL,
    zeekad_decided_by TEXT NOT NULL,
    policy_id TEXT,
    policy_choice TEXT,
    policy_mandatory BOOLEAN,
    policy_reasons JSONB,
    llm_choice TEXT,
    decision_model TEXT,
    decision_model_choice TEXT,
    decision_model_confidence DOUBLE PRECISION,
    decision_model_probabilities JSONB,
    decision_model_error TEXT,
    zeekad_source_run TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE dashboard.raw_slack_deliveries (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    zeekad_message_kind TEXT NOT NULL,
    zeekad_message_version TEXT,
    zeekad_delivery_mode TEXT NOT NULL,
    zeekad_delivery_status TEXT NOT NULL,
    slack_payload JSONB NOT NULL,
    slack_ts TEXT,
    delivered_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE dashboard.raw_slack_summaries (
    job_id BIGINT NOT NULL,
    capture_id TEXT NOT NULL,
    zeekad_message_version TEXT NOT NULL,
    zeekad_delivery_mode TEXT NOT NULL,
    zeekad_delivery_status TEXT NOT NULL,
    slack_payload JSONB NOT NULL,
    slack_ts TEXT,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE dashboard.raw_incident_status (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    zeekad_status TEXT NOT NULL,
    zeekad_resolution TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (incident_id)
);

CREATE TABLE dashboard.raw_incident_status_history (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    zeekad_resolution TEXT,
    actor TEXT NOT NULL,
    reason TEXT,
    changed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE dashboard.raw_analyst_review_queue (
    job_id BIGINT NOT NULL,
    incident_id TEXT NOT NULL,
    queue_rank INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    zeekad_role TEXT NOT NULL,
    zeekad_review_reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    zeekad_review_action TEXT,
    analyst TEXT,
    decided_at TIMESTAMPTZ,
    PRIMARY KEY (job_id, incident_id)
);

CREATE OR REPLACE VIEW dashboard.scoring_jobs AS SELECT * FROM dashboard.raw_scoring_jobs;
CREATE OR REPLACE VIEW dashboard.model_bundles AS SELECT * FROM dashboard.raw_model_bundles;
CREATE OR REPLACE VIEW dashboard.incident_queue AS SELECT * FROM dashboard.raw_incident_queue;
CREATE OR REPLACE VIEW dashboard.incident_model_scores AS SELECT * FROM dashboard.raw_incident_model_scores;
CREATE OR REPLACE VIEW dashboard.asset_names AS SELECT * FROM dashboard.raw_asset_names;
CREATE OR REPLACE VIEW dashboard.incident_reports AS SELECT * FROM dashboard.raw_incident_reports;
CREATE OR REPLACE VIEW dashboard.send_decisions AS SELECT * FROM dashboard.raw_send_decisions;
CREATE OR REPLACE VIEW dashboard.slack_deliveries AS SELECT * FROM dashboard.raw_slack_deliveries;
CREATE OR REPLACE VIEW dashboard.slack_summaries AS SELECT * FROM dashboard.raw_slack_summaries;
CREATE OR REPLACE VIEW dashboard.incident_status AS SELECT * FROM dashboard.raw_incident_status;
CREATE OR REPLACE VIEW dashboard.incident_status_history AS SELECT * FROM dashboard.raw_incident_status_history;
CREATE OR REPLACE VIEW dashboard.analyst_review_queue AS SELECT * FROM dashboard.raw_analyst_review_queue;

CREATE OR REPLACE VIEW dashboard.latest_incident_queue AS
WITH latest_jobs AS (
    SELECT capture_id, MAX(job_id) AS job_id
    FROM dashboard.scoring_jobs
    WHERE status = 'succeeded'
    GROUP BY capture_id
),
first_reports AS (
    SELECT incident_id, MIN(job_id) AS report_job_id
    FROM dashboard.incident_reports
    GROUP BY incident_id
)
SELECT q.job_id,
       q.capture_id,
       q.bundle_id,
       q.queue_rank,
       q.incident_id,
       q.host_ip,
       q.zeekad_role,
       q.event_start,
       q.event_end,
       q.zeekad_picked_by,
       q.zeekad_also_flagged_by,
       q.connection_count,
       q.host_name,
       fr.report_job_id AS zeekad_report_job_id,
       ir.zeekad_report_kind,
       sd.zeekad_would_send,
       COALESCE(ist.zeekad_status, 'open') AS zeekad_status,
       ist.zeekad_resolution,
       ist.updated_at AS status_updated_at,
       arq.zeekad_review_action,
       CASE
           WHEN arq.incident_id IS NOT NULL AND arq.zeekad_review_action IS NULL THEN TRUE
           ELSE FALSE
       END AS zeekad_review_pending
FROM dashboard.incident_queue q
JOIN latest_jobs lj
  ON lj.capture_id = q.capture_id
 AND lj.job_id = q.job_id
LEFT JOIN first_reports fr
  ON fr.incident_id = q.incident_id
LEFT JOIN dashboard.incident_reports ir
  ON ir.job_id = fr.report_job_id
 AND ir.incident_id = q.incident_id
LEFT JOIN dashboard.send_decisions sd
  ON sd.job_id = fr.report_job_id
 AND sd.incident_id = q.incident_id
LEFT JOIN dashboard.incident_status ist
  ON ist.incident_id = q.incident_id
LEFT JOIN dashboard.analyst_review_queue arq
  ON arq.job_id = fr.report_job_id
 AND arq.incident_id = q.incident_id;

GRANT SELECT ON
    dashboard.scoring_jobs,
    dashboard.model_bundles,
    dashboard.incident_queue,
    dashboard.incident_model_scores,
    dashboard.asset_names,
    dashboard.incident_reports,
    dashboard.send_decisions,
    dashboard.slack_deliveries,
    dashboard.slack_summaries,
    dashboard.incident_status,
    dashboard.incident_status_history,
    dashboard.analyst_review_queue,
    dashboard.latest_incident_queue
TO dashboard_ro;

CREATE OR REPLACE FUNCTION dashboard.transition_incident(
    p_job BIGINT,
    p_incident TEXT,
    p_to TEXT,
    p_actor TEXT,
    p_reason TEXT,
    p_resolution TEXT DEFAULT NULL
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = dashboard, pg_temp
AS $$
DECLARE
    v_target TEXT;
    v_actor TEXT;
    v_reason TEXT;
    v_resolution TEXT;
    v_current TEXT;
    v_row_exists BOOLEAN;
BEGIN
    IF p_job IS NULL OR NULLIF(BTRIM(p_incident), '') IS NULL
       OR NULLIF(BTRIM(p_to), '') IS NULL OR NULLIF(BTRIM(p_actor), '') IS NULL THEN
        RAISE EXCEPTION '상태 변경 필수 파라미터(p_job, p_incident, p_to, p_actor)가 누락되었습니다.'
            USING ERRCODE = '22023';
    END IF;

    v_reason := BTRIM(COALESCE(p_reason, ''));
    IF v_reason = '' THEN
        RAISE EXCEPTION '상태 변경 사유를 입력해야 합니다.'
            USING ERRCODE = '22023';
    END IF;

    v_target := LOWER(BTRIM(p_to));
    IF v_target NOT IN ('investigating', 'closed') THEN
        RAISE EXCEPTION '허용되지 않는 목표 상태입니다: %', v_target
            USING ERRCODE = '22023';
    END IF;

    v_actor := BTRIM(p_actor);
    v_resolution := NULLIF(LOWER(BTRIM(COALESCE(p_resolution, ''))), '');
    IF v_target = 'closed' THEN
        IF v_resolution IS NULL OR v_resolution NOT IN ('true_positive', 'false_positive', 'benign') THEN
            RAISE EXCEPTION '사건 종료(closed) 시에는 유효한 결론(true_positive, false_positive, benign)을 선택해야 합니다.'
                USING ERRCODE = '22023';
        END IF;
    ELSE
        v_resolution := NULL;
    END IF;

    PERFORM 1 FROM dashboard.raw_incident_queue
    WHERE job_id = p_job AND incident_id = p_incident;
    IF NOT FOUND THEN
        RAISE EXCEPTION '요청한 사건을 찾을 수 없습니다.'
            USING ERRCODE = '02000';
    END IF;

    SELECT zeekad_status INTO v_current
    FROM dashboard.raw_incident_status
    WHERE incident_id = p_incident
    FOR UPDATE;

    v_row_exists := FOUND;
    IF NOT v_row_exists THEN
        v_current := 'open';
    END IF;

    IF v_current = v_target THEN
        RAISE EXCEPTION '이미 ''%'' 상태로 변경되었습니다. 화면을 새로고침하여 최신 상태를 확인해 주세요.', v_target
            USING ERRCODE = '22023';
    ELSIF v_current = 'closed' THEN
        RAISE EXCEPTION '이미 종료(closed)된 사건은 상태를 되돌리거나 변경할 수 없습니다.'
            USING ERRCODE = '22023';
    ELSIF NOT ((v_current = 'open' AND v_target = 'investigating')
               OR (v_current = 'investigating' AND v_target = 'closed')) THEN
        RAISE EXCEPTION '현재 상태(%)에서 ''%''(으)로 건너뛰거나 되돌릴 수 없습니다.', v_current, v_target
            USING ERRCODE = '22023';
    END IF;

    IF NOT v_row_exists THEN
        BEGIN
            INSERT INTO dashboard.raw_incident_status
                (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
            VALUES
                (p_job, p_incident, v_target, v_resolution, NOW(), v_actor);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION '다른 사용자가 먼저 사건 상태를 변경했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.'
                USING ERRCODE = '22023';
        END;
    ELSE
        UPDATE dashboard.raw_incident_status
        SET job_id = p_job,
            zeekad_status = v_target,
            zeekad_resolution = v_resolution,
            updated_at = NOW(),
            updated_by = v_actor
        WHERE incident_id = p_incident AND zeekad_status = v_current;
        IF NOT FOUND THEN
            RAISE EXCEPTION '다른 사용자가 먼저 사건 상태를 변경했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.'
                USING ERRCODE = '22023';
        END IF;
    END IF;

    INSERT INTO dashboard.raw_incident_status_history
        (job_id, incident_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at)
    VALUES
        (p_job, p_incident, v_current, v_target, v_resolution, v_actor, v_reason, NOW());

    RETURN v_target;
END;
$$;

REVOKE ALL ON FUNCTION dashboard.transition_incident(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dashboard.transition_incident(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT) TO dashboard_rw;

INSERT INTO dashboard.raw_model_bundles (bundle_id, registry_name, registry_version, manifest_sha256, registered_at, thresholds)
VALUES (
    'zeekad-fusion/1',
    'zeekad-ad-models',
    'v1.4.0',
    'sha256-ab12cd34ef567890',
    TIMESTAMPTZ '2026-11-16 01:00:00Z',
    '{"iforest": 0.72, "autoencoder": 0.85, "hbos": 0.68}'::jsonb
);

INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
VALUES
    (100, 'cic17-wed', 'zeekad-fusion/1', 'failed',
     TIMESTAMPTZ '2026-11-16 02:00:00Z', TIMESTAMPTZ '2026-11-16 02:03:00Z',
     'previous batch aborted cleanly', 0),
    (101, 'cic17-wed', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMPTZ '2026-11-16 03:00:00Z', TIMESTAMPTZ '2026-11-16 03:08:00Z',
     NULL, 3),
    (201, 'syn1-tue', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMPTZ '2026-11-16 04:00:00Z', TIMESTAMPTZ '2026-11-16 04:05:00Z',
     NULL, 1),
    (501, 'lab-20261118', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMPTZ '2026-11-18 00:05:00Z', TIMESTAMPTZ '2026-11-18 00:06:00Z',
     NULL, 1),
    (502, 'lab-20261118', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMPTZ '2026-11-18 00:10:00Z', TIMESTAMPTZ '2026-11-18 00:11:00Z',
     NULL, 2);

INSERT INTO dashboard.raw_incident_queue (
    job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
    event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name
) VALUES
    (101, 'cic17-wed', 'zeekad-fusion/1', 1, 'cic17-wed|192.168.10.50|originator|1700000000',
     '192.168.10.50', 'originator',
     TIMESTAMPTZ '2026-11-16 02:10:00Z', TIMESTAMPTZ '2026-11-16 02:35:00Z',
     'iforest', ARRAY['autoencoder', 'hbos'], 412, ARRAY['dc01.corp.local', 'ad-primary']),
    (101, 'cic17-wed', 'zeekad-fusion/1', 2, 'cic17-wed|10.20.30.40|responder|1700000300',
     '10.20.30.40', 'responder',
     TIMESTAMPTZ '2026-11-16 02:20:00Z', TIMESTAMPTZ '2026-11-16 02:30:00Z',
     'autoencoder', ARRAY[]::TEXT[], 85, ARRAY['filesrv02.corp.local']),
    (101, 'cic17-wed', 'zeekad-fusion/1', 3, 'cic17-wed|172.16.5.99|originator|1700000600',
     '172.16.5.99', 'originator',
     TIMESTAMPTZ '2026-11-16 02:40:00Z', TIMESTAMPTZ '2026-11-16 02:55:00Z',
     'hbos', NULL, 24, NULL),
    (201, 'syn1-tue', 'zeekad-fusion/1', 1, 'syn1-tue|10.99.88.77|originator|1700001000',
     '10.99.88.77', 'originator',
     TIMESTAMPTZ '2026-11-16 03:40:00Z', TIMESTAMPTZ '2026-11-16 03:55:00Z',
     'iforest', ARRAY['autoencoder'], 320, ARRAY['syn-dc01.internal']),
    (501, 'lab-20261118', 'zeekad-fusion/1', 1, 'lab-20261118|10.20.0.15|originator|1763424000',
     '10.20.0.15', 'originator',
     TIMESTAMPTZ '2026-11-18 00:00:00Z', TIMESTAMPTZ '2026-11-18 00:05:00Z',
     'iforest', ARRAY['autoencoder'], 150, ARRAY['lab-client01.lab.local']),
    (502, 'lab-20261118', 'zeekad-fusion/1', 1, 'lab-20261118|10.20.0.25|responder|1763424300',
     '10.20.0.25', 'responder',
     TIMESTAMPTZ '2026-11-18 00:05:00Z', TIMESTAMPTZ '2026-11-18 00:10:00Z',
     'hbos', NULL, 42, ARRAY['lab-srv02.lab.local']),
    (502, 'lab-20261118', 'zeekad-fusion/1', 2, 'lab-20261118|10.20.0.15|originator|1763424000',
     '10.20.0.15', 'originator',
     TIMESTAMPTZ '2026-11-18 00:00:00Z', TIMESTAMPTZ '2026-11-18 00:10:00Z',
     'iforest', ARRAY['autoencoder', 'hbos'], 290, ARRAY['lab-client01.lab.local']);

INSERT INTO dashboard.raw_incident_model_scores (job_id, incident_id, zeekad_model, max_score, candidate_windows, windows)
VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'iforest', 0.91, 4, 6),
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'autoencoder', 0.94, 3, 6),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'autoencoder', 0.87, 2, 4),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 'iforest', 0.89, 3, 5),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 'iforest', 0.86, 2, 4),
    (502, 'lab-20261118|10.20.0.25|responder|1763424300', 'hbos', 0.79, 1, 3),
    (502, 'lab-20261118|10.20.0.15|originator|1763424000', 'iforest', 0.93, 5, 6),
    (502, 'lab-20261118|10.20.0.15|originator|1763424000', 'autoencoder', 0.88, 4, 6);

INSERT INTO dashboard.raw_asset_names (capture_id, host_ip, kerberos_user, ntlm_user, source_log, observation_count, first_seen, last_seen)
VALUES
    ('cic17-wed', '192.168.10.50', 'admin', 'svc_ad_sync', 'kerberos', 14,
     TIMESTAMPTZ '2026-11-16 02:05:00Z', TIMESTAMPTZ '2026-11-16 02:34:00Z'),
    ('cic17-wed', '10.20.30.40', 'x', 'backup_op', 'ntlm', 5,
     TIMESTAMPTZ '2026-11-16 02:18:00Z', TIMESTAMPTZ '2026-11-16 02:29:00Z'),
    ('syn1-tue', '10.99.88.77', 'synadmin', NULL, 'kerberos', 9,
     TIMESTAMPTZ '2026-11-16 03:40:00Z', TIMESTAMPTZ '2026-11-16 03:54:00Z'),
    ('lab-20261118', '10.20.0.15', 'labuser1', 'lab_ntlm1', 'kerberos', 6,
     TIMESTAMPTZ '2026-11-18 00:01:00Z', TIMESTAMPTZ '2026-11-18 00:09:00Z');

INSERT INTO dashboard.raw_incident_reports (
    job_id, incident_id, zeekad_report_kind, zeekad_report_version, zeekad_input_version,
    zeekad_report, zeekad_verification_passed, zeekad_verification_reason, zeekad_verification_problems,
    llm_model_requested, llm_model_version, llm_seconds, llm_input_tokens, llm_output_tokens, llm_thinking_tokens,
    llm_error, zeekad_attack_candidates, zeekad_source_run, created_at, zeekad_facts, zeekad_pseudonyms
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'llm', 'llm-report.v1', 'evidence.v1',
     '{"observation_summary": "H에서 X1로 비정상 Kerberos 연결 급증", "claims": [{"claim": "짧은 시간 내 다수 티켓 요청", "fact_ids": ["F1"]}]}'::jsonb,
     TRUE, 'verified', '[]'::jsonb,
     'gemini-2.5-pro', 'gemini-2.5-pro-001', 2.4, 1500, 420, 300,
     NULL, '[{"attack_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactics": ["Credential Access"]}]'::jsonb,
     'run-101', TIMESTAMPTZ '2026-11-16 03:09:00Z',
     '[{"id": "F1", "name": "connection_count", "value": "412"}]'::jsonb,
     '{"H": "192.168.10.50", "X1": "203.0.113.45"}'::jsonb),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'template', 'template.v1', 'evidence.v1',
     '{"observation_summary": "H의 SMB 응답 트래픽 증가"}'::jsonb,
     TRUE, 'template_ok', '[]'::jsonb,
     NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, '[]'::jsonb,
     'run-101', TIMESTAMPTZ '2026-11-16 03:09:30Z',
     '[{"id": "F1", "name": "resp_bytes", "value": "524288"}]'::jsonb,
     '{"H": "10.20.30.40"}'::jsonb),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 'llm', 'llm-report.v1', 'evidence.v1',
     '{"observation_summary": "H에서 I1로 측면 이동 의심"}'::jsonb,
     TRUE, 'verified', '[]'::jsonb,
     'gemini-2.5-pro', 'gemini-2.5-pro-001', 1.8, 1200, 350, 200,
     NULL, '[{"attack_id": "T1021", "name": "Remote Services", "tactics": ["Lateral Movement"]}]'::jsonb,
     'run-201', TIMESTAMPTZ '2026-11-16 04:06:00Z',
     '[{"id": "F1", "name": "smb_count", "value": "120"}]'::jsonb,
     '{"H": "10.99.88.77", "I1": "10.99.88.10"}'::jsonb),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 'llm', 'llm-report.v1', 'evidence.v1',
     '{"observation_summary": "실습망 H에서 I1로 비정상 인증 시도", "claims": [{"claim": "짧은 시간 내 다수 인증 요청", "fact_ids": ["F1"]}]}'::jsonb,
     TRUE, 'verified', '[]'::jsonb,
     'gemini-2.5-pro', 'gemini-2.5-pro-001', 1.9, 1100, 310, 150,
     NULL, '[{"attack_id": "T1110", "name": "Brute Force", "tactics": ["Credential Access"]}]'::jsonb,
     'run-501', TIMESTAMPTZ '2026-11-18 00:06:30Z',
     '[{"id": "F1", "name": "lab_conn_count", "value": "150"}]'::jsonb,
     '{"H": "10.20.0.15", "I1": "10.20.0.99"}'::jsonb);

INSERT INTO dashboard.raw_send_decisions (
    job_id, incident_id, zeekad_would_send, zeekad_decided_by, policy_id, policy_choice,
    policy_mandatory, policy_reasons, llm_choice, decision_model, decision_model_choice,
    decision_model_confidence, decision_model_probabilities, decision_model_error, zeekad_source_run, created_at
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', TRUE, 'policy', 'POL-01', 'send',
     TRUE, '["다중 모델 탐지 및 높은 연결 수"]'::jsonb, 'send', 'gemini-decision-1', 'send',
     0.84, '{"send": 0.84, "hold": 0.10, "analyst_review": 0.04, "need_more_evidence": 0.02}'::jsonb,
     NULL, 'run-101', TIMESTAMPTZ '2026-11-16 03:10:00Z'),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', FALSE, 'policy', 'POL-02', 'hold',
     FALSE, '["단일 모델 탐지 보류"]'::jsonb, 'analyst_review', 'gemini-decision-1', 'hold',
     0.67, '{"send": 0.21, "hold": 0.67, "analyst_review": 0.10, "need_more_evidence": 0.02}'::jsonb,
     NULL, 'run-101', TIMESTAMPTZ '2026-11-16 03:10:30Z'),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', TRUE, 'policy', 'POL-01', 'send',
     TRUE, '["신규 합성 공격 탐지"]'::jsonb, 'send', 'gemini-decision-1', 'send',
     0.91, '{"send": 0.91, "hold": 0.05, "analyst_review": 0.03, "need_more_evidence": 0.01}'::jsonb,
     NULL, 'run-201', TIMESTAMPTZ '2026-11-16 04:07:00Z'),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', TRUE, 'policy', 'POL-01', 'send',
     TRUE, '["실습망 다중 모델 탐지"]'::jsonb, 'send', 'gemini-decision-1', 'send',
     0.89, '{"send": 0.89, "hold": 0.06, "analyst_review": 0.03, "need_more_evidence": 0.02}'::jsonb,
     NULL, 'run-501', TIMESTAMPTZ '2026-11-18 00:07:00Z');

INSERT INTO dashboard.raw_slack_deliveries (
    job_id, incident_id, zeekad_message_kind, zeekad_message_version, zeekad_delivery_mode,
    zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'incident', 'incident.v1', 'dry_run', 'recorded',
     '{"channel": "#sec-alerts", "text": "경보: 192.168.10.50 -> 203.0.113.45"}'::jsonb,
     NULL, NULL, NULL, TIMESTAMPTZ '2026-11-16 03:11:00Z'),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 'incident', 'incident.v1', 'dry_run', 'recorded',
     '{"channel": "#lab-alerts", "text": "실습망 경보: 10.20.0.15 -> 10.20.0.99"}'::jsonb,
     NULL, NULL, NULL, TIMESTAMPTZ '2026-11-18 00:07:30Z');

INSERT INTO dashboard.raw_slack_summaries (
    job_id, capture_id, zeekad_message_version, zeekad_delivery_mode, zeekad_delivery_status,
    slack_payload, slack_ts, delivered_at, created_at
) VALUES
    (101, 'cic17-wed', 'daily-summary.v1', 'dry_run', 'recorded',
     '{"channel": "#sec-daily", "text": "cic17-wed 요약: 주요 호스트 192.168.10.50 외 3건"}'::jsonb,
     NULL, NULL, TIMESTAMPTZ '2026-11-16 03:12:00Z'),
    (201, 'syn1-tue', 'daily-summary.v1', 'live', 'delivered',
     '{"channel": "#sec-daily", "text": "syn1-tue 요약: 주요 호스트 10.99.88.77 외 1건"}'::jsonb,
     '1700001234.000100', TIMESTAMPTZ '2026-11-16 04:08:00Z',
     TIMESTAMPTZ '2026-11-16 04:08:00Z');

INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'investigating', NULL,
     TIMESTAMPTZ '2026-11-16 05:00:00Z', 'analyst1'),
    (101, 'cic17-wed|172.16.5.99|originator|1700000600', 'closed', 'benign',
     TIMESTAMPTZ '2026-11-16 05:30:00Z', 'analyst1'),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 'investigating', NULL,
     TIMESTAMPTZ '2026-11-18 00:08:00Z', 'admin');

INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at)
VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'open', 'investigating', NULL, 'analyst1',
     'SMB 응답 패턴 추가 확인 중', TIMESTAMPTZ '2026-11-16 05:00:00Z'),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 'open', 'investigating', NULL, 'admin',
     '실습망 초기 조사 시작', TIMESTAMPTZ '2026-11-18 00:08:00Z');

INSERT INTO dashboard.raw_analyst_review_queue (
    job_id, incident_id, queue_rank, host_ip, zeekad_role, zeekad_review_reason,
    requested_at, zeekad_review_action, analyst, decided_at
) VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 2, '10.20.30.40', 'responder',
     'LLM 판단(analyst_review)과 정책(hold) 불일치', TIMESTAMPTZ '2026-11-16 03:11:00Z',
     NULL, NULL, NULL),
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 1, '192.168.10.50', 'originator',
     '고위험 도메인 컨트롤러 초기 검토', TIMESTAMPTZ '2026-11-16 03:10:30Z',
     'confirm', 'analyst1', TIMESTAMPTZ '2026-11-16 04:00:00Z'),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 1, '10.99.88.77', 'originator',
     '합성 캡처 내 측면 이동 검토 대기', TIMESTAMPTZ '2026-11-16 04:07:30Z',
     NULL, NULL, NULL),
    (501, 'lab-20261118|10.20.0.15|originator|1763424000', 1, '10.20.0.15', 'originator',
     '실습망 재계산 사건 검토 대기', TIMESTAMPTZ '2026-11-18 00:07:30Z',
     NULL, NULL, NULL);
