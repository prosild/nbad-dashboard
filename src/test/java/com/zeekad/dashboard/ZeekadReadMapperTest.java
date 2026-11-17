package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
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
import com.zeekad.dashboard.service.IncidentQueryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class ZeekadReadMapperTest {

    @Autowired
    private ZeekadReadMapper zeekadReadMapper;

    @Autowired
    private IncidentQueryService incidentQueryService;

    @Test
    void queriesAllTwelveContractViewsWithArrayAndJsonbTypeHandlers() {
        // v1: scoring_jobs & default latest succeeded job selection
        List<String> captures = zeekadReadMapper.findDistinctCaptureIds();
        assertThat(captures).containsExactly("cic17-wed", "syn1-tue");

        ScoringJob latestCic17 = zeekadReadMapper.findLatestSucceededJobByCaptureId("cic17-wed");
        assertThat(latestCic17).isNotNull();
        assertThat(latestCic17.getJobId()).isEqualTo(101L);
        assertThat(latestCic17.getStatus()).isEqualTo("succeeded");

        // v1: model_bundles (jsonb thresholds)
        List<ModelBundle> bundles = zeekadReadMapper.findAllModelBundles();
        assertThat(bundles).hasSize(1);
        assertThat(bundles.get(0).getThresholds().get("iforest").asDouble()).isEqualTo(0.72);
        assertThat(bundles.get(0).getThresholdEntries()).containsEntry("autoencoder", "0.85");

        // v1: incident_queue + LEFT JOIN v2 (incident_status, incident_reports, send_decisions)
        List<IncidentQueueItem> queue = zeekadReadMapper.findIncidentQueue(101L, null, null, null, null, null);
        assertThat(queue).hasSize(3);

        IncidentQueueItem rank1 = queue.get(0);
        assertThat(rank1.getQueueRank()).isEqualTo(1);
        assertThat(rank1.getZeekadAlsoFlaggedBy()).containsExactly("autoencoder", "hbos");
        assertThat(rank1.getHostName()).containsExactly("dc01.corp.local", "ad-primary");
        assertThat(rank1.getZeekadStatus()).isEqualTo("open");
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

        // v2: slack_deliveries & slack_summaries
        List<SlackDelivery> deliveries = zeekadReadMapper.findSlackDeliveries(101L, rank1.getIncidentId());
        assertThat(deliveries).hasSize(1);
        assertThat(deliveries.get(0).isDryRunOrRecorded()).isTrue();
        assertThat(deliveries.get(0).getSlackPayload().get("channel").asText()).isEqualTo("#sec-alerts");

        List<SlackSummary> summaries = zeekadReadMapper.findSlackSummaries("cic17-wed");
        assertThat(summaries).hasSize(1);
        assertThat(summaries.get(0).isDryRunOrRecorded()).isTrue();

        // v2: incident_status & incident_status_history
        String rank2Id = queue.get(1).getIncidentId();
        IncidentStatus status = zeekadReadMapper.findIncidentStatus(101L, rank2Id);
        assertThat(status).isNotNull();
        assertThat(status.getZeekadStatus()).isEqualTo("investigating");

        List<IncidentStatusHistory> history = zeekadReadMapper.findIncidentStatusHistory(101L, rank2Id);
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
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, "open", null, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1);
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, null, false, null))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(3);
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, null, null, true))
                .extracting(IncidentQueueItem::getQueueRank).containsExactly(1);
    }
}
