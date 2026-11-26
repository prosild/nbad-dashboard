package com.zeekad.dashboard.testsupport;

import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;

/**
 * T51 통합 큐 시험 자료(작업 97101~97129). 기준 시각은 {@link #NOW}(now 모드)다.
 *  - {@link #LIVE}(실습망 = 착수 지연 판정 대상): 작업 다섯(완료 10-01 / 11-05 / 11-16 / 11-20 12:00 / 11-20 23:30).
 *    최신 작업 97105에 T23과 같은 조합 표 108행(상태 6 × 교차 탐지 3 × 리포트 상태 6)이 있고, 행마다 순위 % 5번째 작업부터 나와
 *    탐지 시각이 30일 밖 / 30일 안 / 7일 안 / 24시간 안 / 1시간 안(착수 목표 경계 23:30)으로 갈린다.
 *    순위 % 4 == 0은 사건 알림 Slack 기록(경보 발송), 순위 % 9 == 0은 상태 후속 알림(status:*)만(경보 발송 아님),
 *    순위 8이 알림 묶음 머리이고 12·16이 답글, 리포트가 있고 순위 % 3 == 0이면 ATT&amp;CK 후보 T1059.
 *  - {@link #IMPORTED}(가져온 데이터): 작업 97110(완료 11-20 06:00) 12행.
 *  - {@link #NO_DETECT}(가져온 데이터): 성공 작업 97120에 완료 시각이 없어 탐지 시각이 NULL인 5행.
 */
public final class T51QueueSeed {

    public static final Instant NOW = Instant.parse("2026-11-21T00:00:00Z");
    public static final String LIVE = "lab-t51a";
    public static final String IMPORTED = "t51i-cap";
    public static final String NO_DETECT = "t51n-cap";
    /** 세 캡처를 모두 허용하는 패턴 */
    public static final String PATTERNS = "lab-t51*,t51i-*,t51n-*";
    public static final long LATEST_LIVE_JOB = 97105L;
    public static final long IMPORTED_JOB = 97110L;
    public static final long NO_DETECT_JOB = 97120L;
    public static final int COMBINATIONS = 108;
    public static final int IMPORTED_ROWS = 12;
    public static final int NO_DETECT_ROWS = 5;

    private static final long[] LIVE_JOBS = {97101L, 97102L, 97103L, 97104L, LATEST_LIVE_JOB};
    private static final String[] LIVE_FINISHED = {
            "2026-10-01 00:00:00Z", "2026-11-05 00:00:00Z", "2026-11-16 00:00:00Z",
            "2026-11-20 12:00:00Z", "2026-11-20 23:30:00Z"};
    private static final String RANGE = "job_id BETWEEN 97101 AND 97129";

    private T51QueueSeed() {
    }

    public static String liveId(int rank) {
        return LIVE + "|10.51." + ((rank - 1) / 18) + "." + rank + "|t51|" + rank;
    }

    public static String liveHost(int rank) {
        return "10.51." + ((rank - 1) / 18) + "." + rank;
    }

    public static void delete(JdbcTemplate jdbc) {
        for (String table : new String[]{"raw_slack_deliveries", "raw_analyst_review_queue", "raw_send_decisions",
                "raw_incident_reports", "raw_incident_status", "raw_incident_queue", "raw_scoring_jobs"}) {
            jdbc.update("DELETE FROM dashboard." + table + " WHERE " + RANGE);
        }
    }

    public static void insert(JdbcTemplate jdbc) {
        for (int j = 0; j < LIVE_JOBS.length; j++) {
            job(jdbc, LIVE_JOBS[j], LIVE, LIVE_FINISHED[j]);
        }
        String[] statuses = {null, "", "open", "INVESTIGATING", " Closed ", "archived"};
        String[] also = {"null", "empty", "one"};
        String[] reports = {"none", "only", "hold", "send", "pending", "decided"};
        int rank = 0;
        for (String status : statuses) {
            for (String a : also) {
                for (String rep : reports) {
                    rank++;
                    String id = liveId(rank);
                    String alsoSql = switch (a) {
                        case "null" -> "NULL";
                        case "empty" -> "ARRAY[]::VARCHAR ARRAY";
                        default -> "ARRAY['autoencoder']";
                    };
                    String hostNameSql = rank % 2 == 1 ? "ARRAY['t51-host-" + rank + "']" : "NULL";
                    int first = rank % 5;
                    for (int j : first == 4 ? new int[]{4} : new int[]{first, 4}) {
                        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), "
                                        + "TIMESTAMP WITH TIME ZONE '2026-11-20 06:00:00Z', ?, " + alsoSql + ", ?, " + hostNameSql + ")",
                                LIVE_JOBS[j], LIVE, rank, id, liveHost(rank), rank % 2 == 0 ? "originator" : "responder",
                                String.format("2026-11-19 %02d:00:00Z", rank % 5), rank % 3 == 0 ? "iforest" : "hbos",
                                (long) (rank % 7) * 10);
                    }
                    if (status != null) {
                        jdbc.update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                                + "VALUES (?, ?, ?, NULL, TIMESTAMP WITH TIME ZONE '2026-11-20 23:40:00Z', 't51')", LATEST_LIVE_JOB, id, status);
                    }
                    if (!"none".equals(rep)) {
                        String candidates = rank % 3 == 0
                                ? "'[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Execution\"]}]' FORMAT JSON" : "NULL";
                        jdbc.update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                                + "zeekad_report, zeekad_verification_passed, zeekad_attack_candidates, created_at) VALUES (?, ?, ?, 'report.v1', "
                                + "'{}' FORMAT JSON, ?, " + candidates + ", TIMESTAMP WITH TIME ZONE '2026-11-20 23:31:00Z')",
                                LATEST_LIVE_JOB, id, rank % 2 == 0 ? "llm" : "template", rank % 4 == 1 ? null : rank % 4 != 3);
                    }
                    if ("hold".equals(rep) || "send".equals(rep)) {
                        jdbc.update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                                + "VALUES (?, ?, ?, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-20 23:32:00Z')",
                                LATEST_LIVE_JOB, id, "send".equals(rep));
                    }
                    if ("pending".equals(rep) || "decided".equals(rep)) {
                        jdbc.update("INSERT INTO dashboard.raw_analyst_review_queue (job_id, incident_id, queue_rank, host_ip, zeekad_role, "
                                + "zeekad_review_reason, requested_at, zeekad_review_action) VALUES (?, ?, ?, ?, 'originator', 't51', "
                                + "TIMESTAMP WITH TIME ZONE '2026-11-20 23:32:00Z', ?)", LATEST_LIVE_JOB, id, rank, liveHost(rank),
                                "decided".equals(rep) ? "confirm" : null);
                    }
                    if (rank % 4 == 0) {
                        slack(jdbc, LATEST_LIVE_JOB, id, "incident.v2", rank == 12 || rank == 16 ? liveId(8) : null);
                    }
                    if (rank % 9 == 0) {
                        slack(jdbc, LATEST_LIVE_JOB, id, "status:closed", null);
                    }
                }
            }
        }
        job(jdbc, IMPORTED_JOB, IMPORTED, "2026-11-20 06:00:00Z");
        for (int k = 1; k <= IMPORTED_ROWS; k++) {
            plainIncident(jdbc, IMPORTED_JOB, IMPORTED, k, "10.52.0." + k);
        }
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-19 00:00:00Z', NULL, NULL, 0)",
                NO_DETECT_JOB, NO_DETECT);
        for (int k = 1; k <= NO_DETECT_ROWS; k++) {
            plainIncident(jdbc, NO_DETECT_JOB, NO_DETECT, k, "10.53.0." + k);
        }
    }

    private static void job(JdbcTemplate jdbc, long jobId, String capture, String finished) {
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-09-30 00:00:00Z', "
                + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)", jobId, capture, finished);
    }

    private static void plainIncident(JdbcTemplate jdbc, long jobId, String capture, int rank, String ip) {
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-19 20:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-19 20:05:00Z', 'hbos', NULL, ?, NULL)",
                jobId, capture, rank, capture + "|" + ip + "|t51|" + rank, ip, 100L - rank);
    }

    private static void slack(JdbcTemplate jdbc, long jobId, String incidentId, String version, String parent) {
        jdbc.update("INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version, "
                        + "zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at, "
                        + "zeekad_thread_parent, zeekad_reply_broadcast) VALUES (?, ?, 'incident', ?, 'dry_run', 'recorded', "
                        + "'{}' FORMAT JSON, NULL, NULL, NULL, TIMESTAMP WITH TIME ZONE '2026-11-20 23:35:00Z', ?, FALSE)",
                jobId, incidentId, version, parent);
    }
}
