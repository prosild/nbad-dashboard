INSERT INTO dashboard.raw_model_bundles (bundle_id, registry_name, registry_version, manifest_sha256, registered_at, thresholds)
VALUES (
    'zeekad-fusion/1',
    'zeekad-ad-models',
    'v1.4.0',
    'sha256-ab12cd34ef567890',
    TIMESTAMP WITH TIME ZONE '2026-11-16 01:00:00Z',
    '{"iforest": 0.72, "autoencoder": 0.85, "hbos": 0.68}' FORMAT JSON
);

INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
VALUES
    (100, 'cic17-wed', 'zeekad-fusion/1', 'failed',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:00:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:03:00Z',
     'previous batch aborted cleanly', 0),
    (101, 'cic17-wed', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMP WITH TIME ZONE '2026-11-16 03:00:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 03:08:00Z',
     NULL, 3),
    (201, 'syn1-tue', 'zeekad-fusion/1', 'succeeded',
     TIMESTAMP WITH TIME ZONE '2026-11-16 04:00:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 04:05:00Z',
     NULL, 1);

INSERT INTO dashboard.raw_incident_queue (
    job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
    event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name
) VALUES
    (100, 'cic17-wed', 'zeekad-fusion/1', 1, 'cic17-wed|192.168.10.99|originator|1700000000',
     '192.168.10.99', 'originator',
     TIMESTAMP WITH TIME ZONE '2026-11-16 01:50:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:00:00Z',
     'hbos', NULL, 12, ARRAY['old-node.corp.local']),
    (101, 'cic17-wed', 'zeekad-fusion/1', 1, 'cic17-wed|192.168.10.50|originator|1700000000',
     '192.168.10.50', 'originator',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:10:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:35:00Z',
     'iforest', ARRAY['autoencoder', 'hbos'], 412, ARRAY['dc01.corp.local', 'ad-primary']),
    (101, 'cic17-wed', 'zeekad-fusion/1', 2, 'cic17-wed|10.20.30.40|responder|1700000300',
     '10.20.30.40', 'responder',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:20:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:30:00Z',
     'autoencoder', ARRAY[]::VARCHAR ARRAY, 85, ARRAY['filesrv02.corp.local']),
    (101, 'cic17-wed', 'zeekad-fusion/1', 3, 'cic17-wed|172.16.5.99|originator|1700000600',
     '172.16.5.99', 'originator',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:40:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:55:00Z',
     'hbos', NULL, 24, NULL),
    (201, 'syn1-tue', 'zeekad-fusion/1', 1, 'syn1-tue|10.99.88.77|originator|1700001000',
     '10.99.88.77', 'originator',
     TIMESTAMP WITH TIME ZONE '2026-11-16 03:40:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 03:55:00Z',
     'iforest', ARRAY['autoencoder'], 320, ARRAY['syn-dc01.internal']);

INSERT INTO dashboard.raw_incident_model_scores (job_id, incident_id, zeekad_model, max_score, candidate_windows, windows)
VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'iforest', 0.91, 4, 6),
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'autoencoder', 0.94, 3, 6),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'autoencoder', 0.87, 2, 4),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 'iforest', 0.89, 3, 5);

INSERT INTO dashboard.raw_asset_names (capture_id, host_ip, kerberos_user, ntlm_user, source_log, observation_count, first_seen, last_seen)
VALUES
    ('cic17-wed', '192.168.10.50', 'admin', 'svc_ad_sync', 'kerberos', 14,
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:05:00Z', TIMESTAMP WITH TIME ZONE '2026-11-16 02:34:00Z'),
    ('cic17-wed', '10.20.30.40', 'x', 'backup_op', 'ntlm', 5,
     TIMESTAMP WITH TIME ZONE '2026-11-16 02:18:00Z', TIMESTAMP WITH TIME ZONE '2026-11-16 02:29:00Z'),
    ('syn1-tue', '10.99.88.77', 'synadmin', NULL, 'kerberos', 9,
     TIMESTAMP WITH TIME ZONE '2026-11-16 03:40:00Z', TIMESTAMP WITH TIME ZONE '2026-11-16 03:54:00Z');

INSERT INTO dashboard.raw_incident_reports (
    job_id, incident_id, zeekad_report_kind, zeekad_report_version, zeekad_input_version,
    zeekad_report, zeekad_verification_passed, zeekad_verification_reason, zeekad_verification_problems,
    llm_model_requested, llm_model_version, llm_seconds, llm_input_tokens, llm_output_tokens, llm_thinking_tokens,
    llm_error, zeekad_attack_candidates, zeekad_source_run, created_at, zeekad_facts, zeekad_pseudonyms
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'llm', 'llm-report.v1', 'evidence.v1',
     '{"observation_summary": "H에서 X1로 비정상 Kerberos 연결 급증", "claims": [{"claim": "짧은 시간 내 다수 티켓 요청", "fact_ids": ["F1"]}]}' FORMAT JSON,
     TRUE, 'verified', '[]' FORMAT JSON,
     'gemini-2.5-pro', 'gemini-2.5-pro-001', 2.4, 1500, 420, 300,
     NULL, '[{"attack_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactics": ["Credential Access"]}]' FORMAT JSON,
     'run-101', TIMESTAMP WITH TIME ZONE '2026-11-16 03:09:00Z',
     '[{"id": "F1", "name": "connection_count", "value": "412"}]' FORMAT JSON,
     '{"H": "192.168.10.50", "X1": "203.0.113.45"}' FORMAT JSON),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'template', 'template.v1', 'evidence.v1',
     '{"observation_summary": "H의 SMB 응답 트래픽 증가"}' FORMAT JSON,
     TRUE, 'template_ok', '[]' FORMAT JSON,
     NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, '[]' FORMAT JSON,
     'run-101', TIMESTAMP WITH TIME ZONE '2026-11-16 03:09:30Z',
     '[{"id": "F1", "name": "resp_bytes", "value": "524288"}]' FORMAT JSON,
     '{"H": "10.20.30.40"}' FORMAT JSON),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 'llm', 'llm-report.v1', 'evidence.v1',
     '{"observation_summary": "H에서 I1로 측면 이동 의심"}' FORMAT JSON,
     TRUE, 'verified', '[]' FORMAT JSON,
     'gemini-2.5-pro', 'gemini-2.5-pro-001', 1.8, 1200, 350, 200,
     NULL, '[{"attack_id": "T1021", "name": "Remote Services", "tactics": ["Lateral Movement"]}]' FORMAT JSON,
     'run-201', TIMESTAMP WITH TIME ZONE '2026-11-16 04:06:00Z',
     '[{"id": "F1", "name": "smb_count", "value": "120"}]' FORMAT JSON,
     '{"H": "10.99.88.77", "I1": "10.99.88.10"}' FORMAT JSON);

INSERT INTO dashboard.raw_send_decisions (
    job_id, incident_id, zeekad_would_send, zeekad_decided_by, policy_id, policy_choice,
    policy_mandatory, policy_reasons, llm_choice, decision_model, decision_model_choice,
    decision_model_confidence, decision_model_probabilities, decision_model_error, zeekad_source_run, created_at
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', TRUE, 'policy', 'POL-01', 'send',
     TRUE, '["다중 모델 탐지 및 높은 연결 수"]' FORMAT JSON, 'send', 'gemini-decision-1', 'send',
     0.84, '{"send": 0.84, "hold": 0.10, "analyst_review": 0.04, "need_more_evidence": 0.02}' FORMAT JSON,
     NULL, 'run-101', TIMESTAMP WITH TIME ZONE '2026-11-16 03:10:00Z'),
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', FALSE, 'policy', 'POL-02', 'hold',
     FALSE, '["단일 모델 탐지 보류"]' FORMAT JSON, 'analyst_review', 'gemini-decision-1', 'hold',
     0.67, '{"send": 0.21, "hold": 0.67, "analyst_review": 0.10, "need_more_evidence": 0.02}' FORMAT JSON,
     NULL, 'run-101', TIMESTAMP WITH TIME ZONE '2026-11-16 03:10:30Z'),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', TRUE, 'policy', 'POL-01', 'send',
     TRUE, '["신규 합성 공격 탐지"]' FORMAT JSON, 'send', 'gemini-decision-1', 'send',
     0.91, '{"send": 0.91, "hold": 0.05, "analyst_review": 0.03, "need_more_evidence": 0.01}' FORMAT JSON,
     NULL, 'run-201', TIMESTAMP WITH TIME ZONE '2026-11-16 04:07:00Z');

INSERT INTO dashboard.raw_slack_deliveries (
    job_id, incident_id, zeekad_message_kind, zeekad_message_version, zeekad_delivery_mode,
    zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at
) VALUES
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 'incident', 'incident.v1', 'dry_run', 'recorded',
     '{"channel": "#sec-alerts", "text": "경보: 192.168.10.50 -> 203.0.113.45"}' FORMAT JSON,
     NULL, NULL, NULL, TIMESTAMP WITH TIME ZONE '2026-11-16 03:11:00Z');

INSERT INTO dashboard.raw_slack_summaries (
    job_id, capture_id, zeekad_message_version, zeekad_delivery_mode, zeekad_delivery_status,
    slack_payload, slack_ts, delivered_at, created_at
) VALUES
    (101, 'cic17-wed', 'daily-summary.v1', 'dry_run', 'recorded',
     '{"channel": "#sec-daily", "text": "cic17-wed 요약: 주요 호스트 192.168.10.50 외 3건"}' FORMAT JSON,
     NULL, NULL, TIMESTAMP WITH TIME ZONE '2026-11-16 03:12:00Z'),
    (201, 'syn1-tue', 'daily-summary.v1', 'live', 'delivered',
     '{"channel": "#sec-daily", "text": "syn1-tue 요약: 주요 호스트 10.99.88.77 외 1건"}' FORMAT JSON,
     '1700001234.000100', TIMESTAMP WITH TIME ZONE '2026-11-16 04:08:00Z',
     TIMESTAMP WITH TIME ZONE '2026-11-16 04:08:00Z');

INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'investigating', NULL,
     TIMESTAMP WITH TIME ZONE '2026-11-16 05:00:00Z', 'analyst1'),
    (101, 'cic17-wed|172.16.5.99|originator|1700000600', 'closed', 'benign',
     TIMESTAMP WITH TIME ZONE '2026-11-16 05:30:00Z', 'analyst1');

INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at)
VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 'open', 'investigating', NULL, 'analyst1',
     'SMB 응답 패턴 추가 확인 중', TIMESTAMP WITH TIME ZONE '2026-11-16 05:00:00Z');

INSERT INTO dashboard.raw_analyst_review_queue (
    job_id, incident_id, queue_rank, host_ip, zeekad_role, zeekad_review_reason,
    requested_at, zeekad_review_action, analyst, decided_at
) VALUES
    (101, 'cic17-wed|10.20.30.40|responder|1700000300', 2, '10.20.30.40', 'responder',
     'LLM 판단(analyst_review)과 정책(hold) 불일치', TIMESTAMP WITH TIME ZONE '2026-11-16 03:11:00Z',
     NULL, NULL, NULL),
    (101, 'cic17-wed|192.168.10.50|originator|1700000000', 1, '192.168.10.50', 'originator',
     '고위험 도메인 컨트롤러 초기 검토', TIMESTAMP WITH TIME ZONE '2026-11-16 03:10:30Z',
     'confirm', 'analyst1', TIMESTAMP WITH TIME ZONE '2026-11-16 04:00:00Z'),
    (201, 'syn1-tue|10.99.88.77|originator|1700001000', 1, '10.99.88.77', 'originator',
     '합성 캡처 내 측면 이동 검토 대기', TIMESTAMP WITH TIME ZONE '2026-11-16 04:07:30Z',
     NULL, NULL, NULL);
