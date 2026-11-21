package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.IncidentModelScore;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.IncidentReport;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.model.zeekad.IncidentStatusHistory;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SendDecision;
import com.zeekad.dashboard.model.zeekad.SlackDelivery;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class ZeekadReadMapperTest {

    @Autowired
    private ZeekadReadMapper zeekadReadMapper;

    @Autowired
    private IncidentQueryService incidentQueryService;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    @Test
    void queriesAllThirteenContractViewsWithArrayAndJsonbTypeHandlers() {
        // v1: scoring_jobs & default latest succeeded job selection
        List<String> captures = zeekadReadMapper.findDistinctCaptureIds();
        // T21: 결정 반영 예시 캡처 syn1-wed 추가
        assertThat(captures).containsExactly("cic17-wed", "lab-20261118", "lab-fusion-v2", "syn1-tue", "syn1-wed");

        ScoringJob latestCic17 = zeekadReadMapper.findLatestSucceededJobByCaptureId("cic17-wed");
        assertThat(latestCic17).isNotNull();
        assertThat(latestCic17.getJobId()).isEqualTo(101L);
        assertThat(latestCic17.getStatus()).isEqualTo("succeeded");

        // v1: model_bundles (jsonb thresholds)
        List<ModelBundle> bundles = zeekadReadMapper.findAllModelBundles();
        assertThat(bundles).hasSize(3);
        assertThat(bundles).extracting(ModelBundle::getBundleId)
                .containsExactly("zeekad-fusion/3", "zeekad-fusion/2", "zeekad-fusion/1");
        ModelBundle fusion1 = zeekadReadMapper.findModelBundleById("zeekad-fusion/1");
        assertThat(fusion1.getThresholds().get("iforest").asDouble()).isEqualTo(0.72);
        assertThat(fusion1.getThresholdEntries()).containsEntry("autoencoder", "0.85");

        // v1: incident_queue + LEFT JOIN v2 (incident_status, incident_reports, send_decisions)
        List<IncidentQueueItem> queue = zeekadReadMapper.findIncidentQueue(101L, null, null, null, null, null);
        assertThat(queue).hasSize(3);

        IncidentQueueItem rank1 = queue.get(0);
        assertThat(rank1.getQueueRank()).isEqualTo(1);
        assertThat(rank1.getZeekadAlsoFlaggedBy()).containsExactly("autoencoder", "hbos");
        assertThat(rank1.getHostName()).containsExactly("dc01.corp.local", "ad-primary");
        // T21: 반영된 승인(계약) → 분석 중
        assertThat(rank1.getZeekadStatus()).isEqualTo("investigating");
        assertThat(rank1.isHasReport()).isTrue();
        assertThat(rank1.isZeekadWouldSend()).isTrue();

        IncidentQueueItem rank3 = queue.get(2);
        assertThat(rank3.getQueueRank()).isEqualTo(3);
        assertThat(rank3.getZeekadAlsoFlaggedBy()).isEmpty();
        assertThat(rank3.getHostName()).isEmpty();
        assertThat(rank3.getZeekadStatus()).isEqualTo("closed");
        assertThat(rank3.isHasReport()).isFalse();
        assertThat(rank3.isZeekadWouldSend()).isFalse();

        // v1: incident_model_scores
        List<IncidentModelScore> scores = zeekadReadMapper.findModelScores(101L, rank1.getIncidentId());
        assertThat(scores).hasSize(2);
        assertThat(scores.get(0).getWindowRatioLabel()).contains(" / ");

        // v1: asset_names (SELECT * -> DTO + extra attributes)
        List<AssetNameRecord> assets = incidentQueryService.findAssetNames("cic17-wed", "192.168.10.50", UserRole.ANALYST);
        assertThat(assets).hasSize(1);
        assertThat(assets.get(0).getKerberosUser()).isEqualTo("admin");
        assertThat(assets.get(0).getNtlmUser()).isEqualTo("svc_ad_sync");
        assertThat(assets.get(0).getExtraAttributes()).containsEntry("source_log", "kerberos");
        assertThat(assets.get(0).getExtraAttributes()).containsEntry("observation_count", 14);

        // v2: incident_reports
        IncidentReport report = zeekadReadMapper.findIncidentReport(101L, rank1.getIncidentId());
        assertThat(report).isNotNull();
        assertThat(report.getZeekadReportKind()).isEqualTo("llm");
        assertThat(report.getZeekadReport().get("observation_summary").asText()).contains("Kerberos");
        assertThat(report.getZeekadFacts().isArray()).isTrue();
        assertThat(report.getZeekadPseudonyms().get("H").asText()).isEqualTo("192.168.10.50");
        assertThat(report.getZeekadAttackCandidates().get(0).get("attack_id").asText()).isEqualTo("T1558");

        // v2: send_decisions
        SendDecision decision = zeekadReadMapper.findSendDecision(101L, rank1.getIncidentId());
        assertThat(decision).isNotNull();
        assertThat(decision.getZeekadWouldSend()).isTrue();
        assertThat(decision.getPolicyReasons().get(0).asText()).contains("다중 모델");
        assertThat(decision.getDecisionModelProbabilities().get("send").asDouble()).isEqualTo(0.84);

        // v2 + migration 014~016: slack_deliveries (incident_id 단독 + 스레드 열) & slack_summaries
        List<SlackDelivery> deliveries = zeekadReadMapper.findSlackDeliveries(rank1.getIncidentId());
        assertThat(deliveries).hasSize(2);
        assertThat(deliveries.get(0).isDryRunOrRecorded()).isTrue();
        assertThat(deliveries.get(0).getZeekadThreadParent()).isNull();
        assertThat(deliveries.get(0).isReplyBroadcast()).isFalse();
        assertThat(deliveries.get(0).getSlackPayload().get("channel").asText()).isEqualTo("#sec-alerts");
        assertThat(deliveries.get(1).getZeekadThreadParent()).isEqualTo(rank1.getIncidentId());
        assertThat(deliveries.get(1).isReplyBroadcast()).isTrue();

        List<SlackSummary> summaries = zeekadReadMapper.findSlackSummaries("cic17-wed");
        assertThat(summaries).hasSize(1);
        assertThat(summaries.get(0).isDryRunOrRecorded()).isTrue();

        // v2 · v2.1: incident_status & incident_status_history (incident_id 기준)
        String rank2Id = queue.get(1).getIncidentId();
        IncidentStatus status = zeekadReadMapper.findIncidentStatus(rank2Id);
        assertThat(status).isNotNull();
        assertThat(status.getZeekadStatus()).isEqualTo("investigating");

        List<IncidentStatusHistory> history = zeekadReadMapper.findIncidentStatusHistory(rank2Id);
        assertThat(history).hasSize(1);
        assertThat(history.get(0).getToStatus()).isEqualTo("investigating");

        // v2: analyst_review_queue
        List<AnalystReviewItem> allReviews = zeekadReadMapper.findAnalystReviewQueue("cic17-wed", false);
        assertThat(allReviews).hasSize(2);
        List<AnalystReviewItem> pendingReviews = zeekadReadMapper.findAnalystReviewQueue("cic17-wed", true);
        assertThat(pendingReviews).hasSize(1);
        assertThat(pendingReviews.get(0).isPending()).isTrue();
    }

    @Test
    void queueSqlFiltersWorkAccurately() {
        assertThat(zeekadReadMapper.findIncidentQueue(101L, "iforest", null, null, null, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1);
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, "responder", null, null, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(2);
        // T21: rank 1은 반영된 승인(계약)대로 분석 중이다. 열림은 없다.
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, "open", null, null)).isEmpty();
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, "investigating", null, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1, 2);
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, null, false, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(3);
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, null, null, true))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1);
    }

    @Test
    void queriesLatestIncidentQueueAndV21LabMultiJobRules() {
        ScoringJob latestLabJob = zeekadReadMapper.findLatestSucceededJobByCaptureId("lab-20261118");
        assertThat(latestLabJob).isNotNull();
        assertThat(latestLabJob.getJobId()).isEqualTo(502L);

        List<IncidentQueueItem> latestLabQueue = zeekadReadMapper.findLatestIncidentQueue(
                "lab-20261118", null, null, null, null, null);
        assertThat(latestLabQueue).hasSize(2);

        // rank 1: job 502에서 새로 등장, 보고서 없음
        IncidentQueueItem labRank1 = latestLabQueue.get(0);
        assertThat(labRank1.getJobId()).isEqualTo(502L);
        assertThat(labRank1.getQueueRank()).isEqualTo(1);
        assertThat(labRank1.getZeekadReportJobId()).isNull();
        assertThat(labRank1.isHasReport()).isFalse();
        assertThat(labRank1.getZeekadStatus()).isEqualTo("open");
        assertThat(labRank1.isZeekadReviewPending()).isFalse();

        // rank 2: job 502에서 재계산, 보고서·판단·Slack·검토대기는 job 501, 상태는 501에서 승계
        IncidentQueueItem labRank2 = latestLabQueue.get(1);
        assertThat(labRank2.getJobId()).isEqualTo(502L);
        assertThat(labRank2.getQueueRank()).isEqualTo(2);
        assertThat(labRank2.getZeekadReportJobId()).isEqualTo(501L);
        assertThat(labRank2.isHasReport()).isTrue();
        assertThat(labRank2.getZeekadReportKind()).isEqualTo("llm");
        assertThat(labRank2.getZeekadVerificationPassed()).isTrue();
        assertThat(labRank2.isZeekadWouldSend()).isTrue();
        assertThat(labRank2.getZeekadStatus()).isEqualTo("investigating");
        assertThat(labRank2.getStatusUpdatedAt()).isNotNull();
        assertThat(labRank2.getZeekadReviewAction()).isNull();
        assertThat(labRank2.isZeekadReviewPending()).isTrue();

        // latest_incident_queue 필터 검증
        assertThat(zeekadReadMapper.findLatestIncidentQueue("lab-20261118", null, null, null, false, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1);
        assertThat(zeekadReadMapper.findLatestIncidentQueue("lab-20261118", null, null, null, true, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(2);
        assertThat(zeekadReadMapper.findLatestIncidentQueue("lab-20261118", null, null, "investigating", null, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(2);
        assertThat(zeekadReadMapper.findLatestIncidentQueue("lab-20261118", null, null, null, null, true))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(2);

        // (zeekad_report_job_id, incident_id) 조인 규칙 vs 큐 job_id 모델 점수 vs incident_id 단독 Slack 조회
        String labIncId = labRank2.getIncidentId();
        assertThat(zeekadReadMapper.findIncidentReport(502L, labIncId)).isNull();
        assertThat(zeekadReadMapper.findIncidentReport(501L, labIncId)).isNotNull();
        assertThat(zeekadReadMapper.findSendDecision(501L, labIncId)).isNotNull();
        assertThat(zeekadReadMapper.findSlackDeliveries(labIncId)).hasSize(1);
        assertThat(zeekadReadMapper.findModelScores(502L, labIncId)).hasSize(2);

        // analyst_review_queue가 최신 큐(job 502, rank 2) 링크 및 reviewJobId(501)와 연계됨
        List<AnalystReviewItem> labReviews = zeekadReadMapper.findAnalystReviewQueue("lab-20261118", true);
        assertThat(labReviews).hasSize(1);
        assertThat(labReviews.get(0).getJobId()).isEqualTo(502L);
        assertThat(labReviews.get(0).getReviewJobId()).isEqualTo(501L);
        assertThat(labReviews.get(0).getQueueRank()).isEqualTo(2);
        assertThat(labReviews.get(0).isPending()).isTrue();

        // 결합 v2(zeekad-fusion/3, 45분 사건, 보고서 재생성 601->602, Slack은 601 단독, 검토는 602만 노출)
        List<IncidentQueueItem> fusionQueue = zeekadReadMapper.findLatestIncidentQueue(
                "lab-fusion-v2", null, null, null, null, null);
        assertThat(fusionQueue).hasSize(3);
        IncidentQueueItem fusionRank1 = fusionQueue.get(0);
        assertThat(fusionRank1.getJobId()).isEqualTo(602L);
        assertThat(fusionRank1.getBundleId()).isEqualTo("zeekad-fusion/3");
        assertThat(fusionRank1.getZeekadReportJobId()).isEqualTo(602L);
        assertThat(zeekadReadMapper.findSlackDeliveries(fusionRank1.getIncidentId()))
                .hasSize(1)
                .extracting(SlackDelivery::getJobId)
                .containsExactly(601L);

        List<AnalystReviewItem> fusionReviews = zeekadReadMapper.findAnalystReviewQueue("lab-fusion-v2", false);
        assertThat(fusionReviews).hasSize(3);
        assertThat(fusionReviews).extracting(AnalystReviewItem::getReviewJobId).containsOnly(602L);
        assertThat(fusionReviews).extracting(AnalystReviewItem::getResumeStatusLabel)
                .containsExactlyInAnyOrder("에스컬레이션 대기", "반영 중", "반영 실패(관리자 확인 필요)");
        AnalystReviewItem singleReview = zeekadReadMapper.findAnalystReviewByJobAndIncident(
                602L, fusionRank1.getIncidentId());
        assertThat(singleReview).isNotNull();
        assertThat(singleReview.getReviewJobId()).isEqualTo(602L);

        // 과거 실패 작업(job 100) fallback 조회 확인
        List<IncidentQueueItem> failedJobQueue = zeekadReadMapper.findIncidentQueue(100L, null, null, null, null, null);
        assertThat(failedJobQueue).hasSize(1);
        assertThat(failedJobQueue.get(0).isHasReport()).isFalse();
        assertThat(failedJobQueue.get(0).getZeekadStatus()).isEqualTo("open");
    }

    @Test
    void queriesFeedbackSummaryViewWithAllAndPerModelAggregation() {
        List<FeedbackSummaryRecord> cic17Summaries = zeekadReadMapper.findRawFeedbackSummaries("cic17-wed")
                .stream()
                .map(FeedbackSummaryRecord::fromRawMap)
                .toList();
        assertThat(cic17Summaries).hasSize(4);

        FeedbackSummaryRecord cicAll = cic17Summaries.stream()
                .filter(FeedbackSummaryRecord::isAllModel)
                .findFirst()
                .orElseThrow();
        assertThat(cicAll.getBundleId()).isEqualTo("zeekad-fusion/1");
        assertThat(cicAll.getIncidents()).isEqualTo(3L);
        // T21: alerted는 zeek_AD 원본처럼 사건 알림 Slack 기록으로 센다(10.20.30.40 스레드 답글 사건 알림 포함, 발송 판단과 별개)
        assertThat(cicAll.getAlerted()).isEqualTo(2L);
        assertThat(cicAll.getResolved()).isEqualTo(1L);
        assertThat(cicAll.getTruePositive()).isEqualTo(0L);
        assertThat(cicAll.getFalsePositive()).isEqualTo(0L);
        assertThat(cicAll.getBenign()).isEqualTo(1L);
        assertThat(cicAll.getZeekadPrecision()).isEqualTo(0.0d);
        assertThat(cicAll.getZeekadAlertPrecision()).isNull();
        assertThat(cicAll.getZeekadAlertResolvedRate()).isEqualTo(0.0d);
        assertThat(cicAll.getPrecisionSummaryText()).isEqualTo("표본 부족 · 판정 1/3건(33.3%)");
        assertThat(cicAll.getAlertPrecisionSummaryText()).isEqualTo("판정 없음 · 경보 2건");

        // 판정 0건 캡처(lab-fusion-v2)는 정탐률 null 처리
        List<FeedbackSummaryRecord> fusionSummaries = zeekadReadMapper.findRawFeedbackSummaries("lab-fusion-v2")
                .stream()
                .map(FeedbackSummaryRecord::fromRawMap)
                .toList();
        FeedbackSummaryRecord fusionAll = fusionSummaries.stream()
                .filter(FeedbackSummaryRecord::isAllModel)
                .findFirst()
                .orElseThrow();
        assertThat(fusionAll.getBundleId()).isEqualTo("zeekad-fusion/3");
        assertThat(fusionAll.getIncidents()).isEqualTo(3L);
        // T21: 10.40.0.20의 601 기록을 계약대로 사건 알림(스레드 답글)으로 고쳐 2건
        assertThat(fusionAll.getAlerted()).isEqualTo(2L);
        assertThat(fusionAll.getResolved()).isEqualTo(0L);
        assertThat(fusionAll.getZeekadPrecision()).isNull();
        assertThat(fusionAll.getZeekadAlertPrecision()).isNull();
        assertThat(fusionAll.getPrecisionSummaryText()).isEqualTo("판정 없음");

        // IncidentQueryService 정렬('all' 최우선) 및 IDOR 필터 확인
        DashboardUser cicUser = new DashboardUser();
        cicUser.setId(1L);
        cicUser.setUsername("cic_viewer");
        cicUser.setDisplayName("조회자");
        cicUser.setRole(UserRole.VIEWER);
        cicUser.setEnabled(true);
        DashboardUserPrincipal cicPrincipal = new DashboardUserPrincipal(
                cicUser, List.of("cic17-*"), Instant.now());
        IncidentQueryService.OperationsViewResult cicOps =
                incidentQueryService.loadOperationsView(cicPrincipal, null, "127.0.0.1");
        assertThat(cicOps.feedbackSummaries()).hasSize(4);
        assertThat(cicOps.feedbackSummaries())
                .extracting(FeedbackSummaryRecord::getCaptureId)
                .containsOnly("cic17-wed");
        assertThat(cicOps.feedbackSummaries().get(0).isAllModel()).isTrue();
        assertThat(cicOps.feedbackSummaries())
                .extracting(FeedbackSummaryRecord::getZeekadPickedBy)
                .containsExactly("all", "autoencoder", "hbos", "iforest");

        // 임시 true_positive 결론 시드로 alerted_precision 및 alerted_resolved_rate 식 검증
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        long tmpJobId = 9901L;
        String tmpCapture = "cic17-fb-calc";
        String tmpInc1 = tmpCapture + "|192.168.90.10|originator|1700009001";
        String tmpInc2 = tmpCapture + "|192.168.90.20|responder|1700009002";
        try {
            jdbc.update("""
                    INSERT INTO dashboard.raw_scoring_jobs
                    (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                    VALUES (?, ?, 'zeekad-fusion/3', 'succeeded',
                            TIMESTAMP WITH TIME ZONE '2026-11-19 03:00:00Z',
                            TIMESTAMP WITH TIME ZONE '2026-11-19 03:01:00Z', NULL, 2)
                    """, tmpJobId, tmpCapture);
            jdbc.update("""
                    INSERT INTO dashboard.raw_incident_queue
                    (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
                     event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                    VALUES
                    (?, ?, 'zeekad-fusion/3', 1, ?, '192.168.90.10', 'originator',
                     TIMESTAMP WITH TIME ZONE '2026-11-19 02:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:00:00Z',
                     'iforest', NULL, 100, NULL),
                    (?, ?, 'zeekad-fusion/3', 2, ?, '192.168.90.20', 'responder',
                     TIMESTAMP WITH TIME ZONE '2026-11-19 02:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:00:00Z',
                     'hbos', NULL, 50, NULL)
                    """, tmpJobId, tmpCapture, tmpInc1, tmpJobId, tmpCapture, tmpInc2);
            jdbc.update("""
                    INSERT INTO dashboard.raw_incident_reports
                    (job_id, incident_id, zeekad_report_kind, zeekad_report_version, zeekad_input_version,
                     zeekad_report, zeekad_verification_passed, created_at)
                    VALUES
                    (?, ?, 'llm', 'llm-report.v1', 'evidence.v1', '{"observation_summary":"s1"}' FORMAT JSON, TRUE,
                     TIMESTAMP WITH TIME ZONE '2026-11-19 03:01:30Z'),
                    (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary":"s2"}' FORMAT JSON, TRUE,
                     TIMESTAMP WITH TIME ZONE '2026-11-19 03:01:30Z')
                    """, tmpJobId, tmpInc1, tmpJobId, tmpInc2);
            jdbc.update("""
                    INSERT INTO dashboard.raw_send_decisions
                    (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at)
                    VALUES
                    (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-19 03:02:00Z'),
                    (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-19 03:02:00Z')
                    """, tmpJobId, tmpInc1, tmpJobId, tmpInc2);
            // T21: alerted는 사건 알림 Slack 기록으로 센다(발송 판단이 아니라). 두 사건 모두 사건 알림 dry-run 기록을 둔다.
            jdbc.update("""
                    INSERT INTO dashboard.raw_slack_deliveries
                    (job_id, incident_id, zeekad_message_kind, zeekad_message_version, zeekad_delivery_mode,
                     zeekad_delivery_status, slack_payload, created_at)
                    VALUES
                    (?, ?, 'incident', 'llm-report.v1', 'dry_run', 'recorded', '{"text":"a1"}' FORMAT JSON,
                     TIMESTAMP WITH TIME ZONE '2026-11-19 03:02:30Z'),
                    (?, ?, 'incident', 'template.v1', 'dry_run', 'recorded', '{"text":"a2"}' FORMAT JSON,
                     TIMESTAMP WITH TIME ZONE '2026-11-19 03:02:30Z')
                    """, tmpJobId, tmpInc1, tmpJobId, tmpInc2);
            jdbc.update("""
                    INSERT INTO dashboard.raw_incident_status
                    (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
                    VALUES
                    (?, ?, 'closed', 'true_positive', TIMESTAMP WITH TIME ZONE '2026-11-19 03:05:00Z', 'analyst1')
                    """, tmpJobId, tmpInc1);

            List<FeedbackSummaryRecord> calcRows = zeekadReadMapper.findRawFeedbackSummaries(tmpCapture)
                    .stream()
                    .map(FeedbackSummaryRecord::fromRawMap)
                    .toList();
            FeedbackSummaryRecord calcAll = calcRows.stream()
                    .filter(FeedbackSummaryRecord::isAllModel)
                    .findFirst()
                    .orElseThrow();
            assertThat(calcAll.getIncidents()).isEqualTo(2L);
            assertThat(calcAll.getAlerted()).isEqualTo(2L);
            assertThat(calcAll.getResolved()).isEqualTo(1L);
            assertThat(calcAll.getTruePositive()).isEqualTo(1L);
            assertThat(calcAll.getZeekadPrecision()).isEqualTo(1.0d);
            assertThat(calcAll.getZeekadAlertPrecision()).isEqualTo(1.0d);
            assertThat(calcAll.getZeekadAlertResolvedRate()).isEqualTo(0.5d);
            assertThat(calcAll.getPrecisionSummaryText()).isEqualTo("표본 부족 · 판정 1/2건(50.0%)");
            assertThat(calcAll.getAlertPrecisionSummaryText()).isEqualTo("표본 부족 · 경보 판정 1/2건(50.0%)");
        } finally {
            jdbc.update("DELETE FROM dashboard.raw_incident_status WHERE incident_id IN (?, ?)", tmpInc1, tmpInc2);
            jdbc.update("DELETE FROM dashboard.raw_slack_deliveries WHERE job_id = ?", tmpJobId);
            jdbc.update("DELETE FROM dashboard.raw_send_decisions WHERE job_id = ?", tmpJobId);
            jdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE job_id = ?", tmpJobId);
            jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", tmpJobId);
            jdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", tmpJobId);
        }
    }
}
