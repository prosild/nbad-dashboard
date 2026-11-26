CREATE SCHEMA IF NOT EXISTS dashboard;

CREATE TABLE IF NOT EXISTS dashboard.raw_scoring_jobs (
    job_id BIGINT PRIMARY KEY,
    capture_id VARCHAR(128) NOT NULL,
    bundle_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE,
    error TEXT,
    incident_count INTEGER
);

CREATE TABLE IF NOT EXISTS dashboard.raw_model_bundles (
    bundle_id VARCHAR(128) PRIMARY KEY,
    registry_name VARCHAR(128) NOT NULL,
    registry_version VARCHAR(64) NOT NULL,
    manifest_sha256 VARCHAR(128) NOT NULL,
    registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    thresholds JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS dashboard.raw_incident_queue (
    job_id BIGINT NOT NULL,
    capture_id VARCHAR(128) NOT NULL,
    bundle_id VARCHAR(128) NOT NULL,
    queue_rank INTEGER NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    host_ip VARCHAR(64) NOT NULL,
    zeekad_role VARCHAR(32) NOT NULL,
    event_start TIMESTAMP WITH TIME ZONE NOT NULL,
    event_end TIMESTAMP WITH TIME ZONE NOT NULL,
    zeekad_picked_by VARCHAR(64) NOT NULL,
    zeekad_also_flagged_by VARCHAR(64) ARRAY,
    connection_count BIGINT NOT NULL,
    host_name VARCHAR(255) ARRAY,
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_incident_model_scores (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    zeekad_model VARCHAR(64) NOT NULL,
    max_score DOUBLE PRECISION NOT NULL,
    candidate_windows INTEGER NOT NULL,
    windows INTEGER NOT NULL,
    PRIMARY KEY (job_id, incident_id, zeekad_model)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_asset_names (
    capture_id VARCHAR(128) NOT NULL,
    host_ip VARCHAR(64) NOT NULL,
    kerberos_user VARCHAR(128),
    ntlm_user VARCHAR(128),
    source_log VARCHAR(64),
    observation_count INTEGER,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    -- T46: 운영 뷰의 관측 계정 이름 열(화면 '관측 계정'이 먼저 읽는 값)
    zeekad_name VARCHAR(128),
    zeekad_name_kind VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_incident_reports (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    zeekad_report_kind VARCHAR(32) NOT NULL,
    zeekad_report_version VARCHAR(64) NOT NULL,
    zeekad_input_version VARCHAR(64),
    zeekad_report JSON NOT NULL,
    zeekad_verification_passed BOOLEAN,
    zeekad_verification_reason TEXT,
    zeekad_verification_problems JSON,
    llm_model_requested VARCHAR(128),
    llm_model_version VARCHAR(128),
    llm_seconds DOUBLE PRECISION,
    llm_input_tokens INTEGER,
    llm_output_tokens INTEGER,
    llm_thinking_tokens INTEGER,
    llm_error TEXT,
    zeekad_attack_candidates JSON,
    zeekad_source_run VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    zeekad_facts JSON,
    zeekad_pseudonyms JSON,
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_send_decisions (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    zeekad_would_send BOOLEAN NOT NULL,
    zeekad_decided_by VARCHAR(64) NOT NULL,
    policy_id VARCHAR(128),
    policy_choice VARCHAR(64),
    policy_mandatory BOOLEAN,
    policy_reasons JSON,
    llm_choice VARCHAR(64),
    decision_model VARCHAR(128),
    decision_model_choice VARCHAR(64),
    decision_model_confidence DOUBLE PRECISION,
    decision_model_probabilities JSON,
    decision_model_error TEXT,
    zeekad_source_run VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (job_id, incident_id)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_slack_deliveries (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    zeekad_message_kind VARCHAR(32) NOT NULL,
    zeekad_message_version VARCHAR(64),
    zeekad_delivery_mode VARCHAR(32) NOT NULL,
    zeekad_delivery_status VARCHAR(32) NOT NULL,
    slack_payload JSON NOT NULL,
    slack_ts VARCHAR(64),
    delivered_at TIMESTAMP WITH TIME ZONE,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    zeekad_thread_parent VARCHAR(255),
    zeekad_reply_broadcast BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS dashboard.raw_slack_summaries (
    job_id BIGINT NOT NULL,
    capture_id VARCHAR(128) NOT NULL,
    zeekad_message_version VARCHAR(64) NOT NULL,
    zeekad_delivery_mode VARCHAR(32) NOT NULL,
    zeekad_delivery_status VARCHAR(32) NOT NULL,
    slack_payload JSON NOT NULL,
    slack_ts VARCHAR(64),
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS dashboard.raw_incident_status (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    zeekad_status VARCHAR(32) NOT NULL,
    zeekad_resolution VARCHAR(64),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_by VARCHAR(100) NOT NULL,
    PRIMARY KEY (incident_id)
);

CREATE TABLE IF NOT EXISTS dashboard.raw_incident_status_history (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    zeekad_resolution VARCHAR(64),
    actor VARCHAR(100) NOT NULL,
    reason TEXT,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS dashboard.raw_analyst_review_queue (
    job_id BIGINT NOT NULL,
    incident_id VARCHAR(255) NOT NULL,
    queue_rank INTEGER NOT NULL,
    host_ip VARCHAR(64) NOT NULL,
    zeekad_role VARCHAR(32) NOT NULL,
    zeekad_review_reason TEXT NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
    zeekad_review_action VARCHAR(32),
    analyst VARCHAR(100),
    decided_at TIMESTAMP WITH TIME ZONE,
    zeekad_review_resumed_at TIMESTAMP WITH TIME ZONE,
    zeekad_review_resume_failed BOOLEAN DEFAULT FALSE,
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
latest_reports AS (
    SELECT incident_id, MAX(job_id) AS report_job_id
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
       lr.report_job_id AS zeekad_report_job_id,
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
LEFT JOIN latest_reports lr
  ON lr.incident_id = q.incident_id
LEFT JOIN dashboard.incident_reports ir
  ON ir.job_id = lr.report_job_id
 AND ir.incident_id = q.incident_id
LEFT JOIN dashboard.send_decisions sd
  ON sd.job_id = lr.report_job_id
 AND sd.incident_id = q.incident_id
LEFT JOIN dashboard.incident_status ist
  ON ist.incident_id = q.incident_id
LEFT JOIN dashboard.analyst_review_queue arq
  ON arq.job_id = lr.report_job_id
 AND arq.incident_id = q.incident_id;

CREATE OR REPLACE VIEW dashboard.feedback_summary AS
WITH q AS (
    -- T21: zeek_AD 원본과 같은 alerted 식(사건 알림 Slack 기록, 상태 후속 알림 status:* 제외). 이전에는 would_send로 셌다.
    SELECT l.capture_id,
           l.bundle_id,
           l.zeekad_picked_by,
           l.zeekad_status,
           l.zeekad_resolution,
           CASE WHEN EXISTS (
               SELECT 1
               FROM dashboard.slack_deliveries d
               WHERE d.incident_id = l.incident_id
                 AND d.zeekad_message_version IS NOT NULL
                 AND d.zeekad_message_version NOT LIKE 'status:%'
           ) THEN TRUE ELSE FALSE END AS alerted_flag
    FROM dashboard.latest_incident_queue l
),
grouped AS (
    SELECT capture_id,
           bundle_id,
           zeekad_picked_by,
           COUNT(*) AS incidents,
           SUM(CASE WHEN alerted_flag = TRUE THEN 1 ELSE 0 END) AS alerted,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution IS NOT NULL THEN 1 ELSE 0 END) AS resolved,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'true_positive' THEN 1 ELSE 0 END) AS true_positive,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'false_positive' THEN 1 ELSE 0 END) AS false_positive,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'benign' THEN 1 ELSE 0 END) AS benign,
           SUM(CASE WHEN alerted_flag = TRUE
                         AND zeekad_status = 'closed'
                         AND zeekad_resolution IS NOT NULL THEN 1 ELSE 0 END) AS alerted_resolved,
           SUM(CASE WHEN alerted_flag = TRUE
                         AND zeekad_status = 'closed'
                         AND zeekad_resolution = 'true_positive' THEN 1 ELSE 0 END) AS alerted_true_positive
    FROM q
    GROUP BY capture_id, bundle_id, zeekad_picked_by
    UNION ALL
    SELECT capture_id,
           bundle_id,
           'all' AS zeekad_picked_by,
           COUNT(*) AS incidents,
           SUM(CASE WHEN alerted_flag = TRUE THEN 1 ELSE 0 END) AS alerted,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution IS NOT NULL THEN 1 ELSE 0 END) AS resolved,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'true_positive' THEN 1 ELSE 0 END) AS true_positive,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'false_positive' THEN 1 ELSE 0 END) AS false_positive,
           SUM(CASE WHEN zeekad_status = 'closed' AND zeekad_resolution = 'benign' THEN 1 ELSE 0 END) AS benign,
           SUM(CASE WHEN alerted_flag = TRUE
                         AND zeekad_status = 'closed'
                         AND zeekad_resolution IS NOT NULL THEN 1 ELSE 0 END) AS alerted_resolved,
           SUM(CASE WHEN alerted_flag = TRUE
                         AND zeekad_status = 'closed'
                         AND zeekad_resolution = 'true_positive' THEN 1 ELSE 0 END) AS alerted_true_positive
    FROM q
    GROUP BY capture_id, bundle_id
)
SELECT capture_id,
       bundle_id,
       zeekad_picked_by,
       incidents,
       alerted,
       resolved,
       true_positive,
       false_positive,
       benign,
       CASE WHEN resolved > 0 THEN CAST(true_positive AS DOUBLE PRECISION) / resolved ELSE NULL END AS zeekad_precision,
       CASE WHEN alerted_resolved > 0 THEN CAST(alerted_true_positive AS DOUBLE PRECISION) / alerted_resolved ELSE NULL END AS zeekad_alert_precision,
       CASE WHEN alerted > 0 THEN CAST(alerted_resolved AS DOUBLE PRECISION) / alerted ELSE NULL END AS zeekad_alert_resolved_rate
FROM grouped;

CREATE ALIAS IF NOT EXISTS dashboard.transition_incident FOR "com.zeekad.dashboard.testsupport.H2ZeekadTransitionFunctions.transitionIncident";
CREATE ALIAS IF NOT EXISTS dashboard.decide_review FOR "com.zeekad.dashboard.testsupport.H2ZeekadTransitionFunctions.decideReview";
-- T53 종결한 사건 다시 열기(zeek_AD migration 018의 대역)
CREATE ALIAS IF NOT EXISTS dashboard.reopen_incident FOR "com.zeekad.dashboard.testsupport.H2ZeekadTransitionFunctions.reopenIncident";
