package com.zeekad.dashboard;

import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class FeedbackSummaryRecordTest {

    @Test
    void mapsCaseInsensitiveAndExtraColumnsSafely() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("EXTRA_NOTE", "v17-trailing");
        raw.put("CAPTURE_ID", "cic17-wed");
        raw.put("BUNDLE_ID", "zeekad-fusion/3");
        raw.put("ZEEKAD_PICKED_BY", "all");
        raw.put("INCIDENTS", 5L);
        raw.put("ALERTED", 4);
        raw.put("RESOLVED", new BigDecimal("3"));
        raw.put("TRUE_POSITIVE", 2L);
        raw.put("FALSE_POSITIVE", 1L);
        raw.put("BENIGN", 0L);
        raw.put("ZEEKAD_PRECISION", new BigDecimal("0.60"));
        raw.put("ZEEKAD_ALERT_PRECISION", 0.50d);
        raw.put("ZEEKAD_ALERT_RESOLVED_RATE", 0.50d);
        raw.put("ALERTED_RESOLVED", 2L);

        FeedbackSummaryRecord record = FeedbackSummaryRecord.fromRawMap(raw);

        assertThat(record.getCaptureId()).isEqualTo("cic17-wed");
        assertThat(record.getBundleId()).isEqualTo("zeekad-fusion/3");
        assertThat(record.isAllModel()).isTrue();
        assertThat(record.getIncidents()).isEqualTo(5L);
        assertThat(record.getAlerted()).isEqualTo(4L);
        assertThat(record.getResolved()).isEqualTo(3L);
        assertThat(record.getTruePositive()).isEqualTo(2L);
        assertThat(record.getFalsePositive()).isEqualTo(1L);
        assertThat(record.getBenign()).isEqualTo(0L);
        assertThat(record.getEffectiveAlertedResolved()).isEqualTo(2L);
        assertThat(record.getPrecisionSummaryText()).isEqualTo("정밀도 0.60, 결론 3/5 (60.0%)");
        assertThat(record.getAlertPrecisionSummaryText()).isEqualTo("정밀도 0.50, 결론 2/4 (50.0%)");
        assertThat(record.getExtraAttributes()).containsEntry("extra_note", "v17-trailing");
    }

    @Test
    void handlesOptionalAlertedResolvedAndZeroOrNullPrecisionCases() {
        // 1. alerted_resolved 없을 때 alerted * zeekad_alert_resolved_rate 계산 + alert_resolved 별칭 미사용
        Map<String, Object> computedRaw = new LinkedHashMap<>();
        computedRaw.put("capture_id", "lab-test");
        computedRaw.put("bundle_id", "zeekad-fusion/3");
        computedRaw.put("zeekad_picked_by", "iforest");
        computedRaw.put("incidents", 5L);
        computedRaw.put("alerted", 4L);
        computedRaw.put("resolved", 3L);
        computedRaw.put("zeekad_precision", 0.60d);
        computedRaw.put("zeekad_alert_precision", 0.67d);
        computedRaw.put("zeekad_alert_resolved_rate", 0.75d);
        FeedbackSummaryRecord computed = FeedbackSummaryRecord.fromRawMap(computedRaw);

        assertThat(computed.isAllModel()).isFalse();
        assertThat(computed.getAlertedResolved()).isNull();
        assertThat(computed.getEffectiveAlertedResolved()).isEqualTo(3L);
        assertThat(computed.getAlertPrecisionSummaryText()).isEqualTo("정밀도 0.67, 결론 3/4 (75.0%)");

        // 2. alert_resolved 별칭 지원 확인
        Map<String, Object> aliasRaw = new LinkedHashMap<>();
        aliasRaw.put("alerted", 4L);
        aliasRaw.put("alert_resolved", 1L);
        aliasRaw.put("zeekad_alert_precision", 1.0d);
        aliasRaw.put("zeekad_alert_resolved_rate", 0.25d);
        FeedbackSummaryRecord alias = FeedbackSummaryRecord.fromRawMap(aliasRaw);
        assertThat(alias.getEffectiveAlertedResolved()).isEqualTo(1L);
        assertThat(alias.getAlertPrecisionSummaryText()).isEqualTo("정밀도 1.00, 결론 1/4 (25.0%)");

        // 3. 결론 0건 (incidents > 0, resolved == 0, precision == null)
        Map<String, Object> noResRaw = new LinkedHashMap<>();
        noResRaw.put("incidents", 5L);
        noResRaw.put("alerted", 2L);
        noResRaw.put("resolved", 0L);
        noResRaw.put("zeekad_precision", null);
        noResRaw.put("zeekad_alert_precision", null);
        noResRaw.put("zeekad_alert_resolved_rate", 0.0d);
        FeedbackSummaryRecord noRes = FeedbackSummaryRecord.fromRawMap(noResRaw);
        assertThat(noRes.getPrecisionSummaryText()).isEqualTo("- (결론 0/5, 0.0%)");
        assertThat(noRes.getAlertPrecisionSummaryText()).isEqualTo("- (결론 0/2 (0.0%))");

        // 4. 사건 0건 / 알림 0건 / rate null
        FeedbackSummaryRecord empty = FeedbackSummaryRecord.fromRawMap(Map.of("incidents", 0L, "alerted", 0L));
        assertThat(empty.getPrecisionSummaryText()).isEqualTo("- (결론 없음)");
        assertThat(empty.getAlertPrecisionSummaryText()).isEqualTo("- (알림 없음)");

        // 5. alerted > 0 이지만 alerted_resolved 및 rate 모두 null
        FeedbackSummaryRecord unknownAlertRate = FeedbackSummaryRecord.fromRawMap(Map.of("alerted", 3L));
        assertThat(unknownAlertRate.getEffectiveAlertedResolved()).isNull();
        assertThat(unknownAlertRate.getAlertPrecisionSummaryText()).isEqualTo("- (결론 없음)");
    }
}
