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
        assertThat(record.getPrecisionSummaryText()).isEqualTo("표본 부족 · 판정 3/5건(60.0%)");
        assertThat(record.getAlertPrecisionSummaryText()).isEqualTo("표본 부족 · 경보 판정 2/4건(50.0%)");
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
        assertThat(computed.getAlertPrecisionSummaryText()).isEqualTo("표본 부족 · 경보 판정 3/4건(75.0%)");

        // 2. alert_resolved 별칭 지원 확인
        Map<String, Object> aliasRaw = new LinkedHashMap<>();
        aliasRaw.put("alerted", 4L);
        aliasRaw.put("alert_resolved", 1L);
        aliasRaw.put("zeekad_alert_precision", 1.0d);
        aliasRaw.put("zeekad_alert_resolved_rate", 0.25d);
        FeedbackSummaryRecord alias = FeedbackSummaryRecord.fromRawMap(aliasRaw);
        assertThat(alias.getEffectiveAlertedResolved()).isEqualTo(1L);
        assertThat(alias.getAlertPrecisionSummaryText()).isEqualTo("표본 부족 · 경보 판정 1/4건(25.0%)");

        // 3. 판정 0건 (incidents > 0, resolved == 0, precision == null)
        Map<String, Object> noResRaw = new LinkedHashMap<>();
        noResRaw.put("incidents", 5L);
        noResRaw.put("alerted", 2L);
        noResRaw.put("resolved", 0L);
        noResRaw.put("zeekad_precision", null);
        noResRaw.put("zeekad_alert_precision", null);
        noResRaw.put("zeekad_alert_resolved_rate", 0.0d);
        FeedbackSummaryRecord noRes = FeedbackSummaryRecord.fromRawMap(noResRaw);
        assertThat(noRes.getPrecisionSummaryText()).isEqualTo("판정 없음");
        assertThat(noRes.getAlertPrecisionSummaryText()).isEqualTo("판정 없음 · 경보 2건");

        // 4. 인시던트 0건 / 경보 0건 / rate null
        FeedbackSummaryRecord empty = FeedbackSummaryRecord.fromRawMap(Map.of("incidents", 0L, "alerted", 0L));
        assertThat(empty.getPrecisionSummaryText()).isEqualTo("판정 없음");
        assertThat(empty.getAlertPrecisionSummaryText()).isEqualTo("경보 없음");

        // 5. alerted > 0 이지만 alerted_resolved 및 rate 모두 null
        FeedbackSummaryRecord unknownAlertRate = FeedbackSummaryRecord.fromRawMap(Map.of("alerted", 3L));
        assertThat(unknownAlertRate.getEffectiveAlertedResolved()).isNull();
        assertThat(unknownAlertRate.getAlertPrecisionSummaryText()).isEqualTo("경보 3건 · 판정 수 알 수 없음");
    }

    @Test
    void usesSampleShortBelowTenResolvedAndFormatsPercentAndThousands() {
        // 판정 9건: 표본 부족(경계 아래)
        Map<String, Object> nine = new LinkedHashMap<>();
        nine.put("incidents", 1234L);
        nine.put("resolved", 9L);
        nine.put("zeekad_precision", 0.556d);
        assertThat(FeedbackSummaryRecord.fromRawMap(nine).getPrecisionSummaryText())
                .isEqualTo("표본 부족 · 판정 9/1,234건(0.7%)");

        // 판정 10건: 정탐률(경계), 천 단위 구분, 소수 첫째 자리 반올림
        Map<String, Object> ten = new LinkedHashMap<>();
        ten.put("incidents", 1234L);
        ten.put("resolved", 10L);
        ten.put("zeekad_precision", 0.6d);
        assertThat(FeedbackSummaryRecord.fromRawMap(ten).getPrecisionSummaryText())
                .isEqualTo("정탐률 60.0% · 판정 10/1,234건(0.8%)");

        // 예시 형식: 판정 18건 중 정탐 비율, 판정률
        Map<String, Object> example = new LinkedHashMap<>();
        example.put("incidents", 50L);
        example.put("resolved", 18L);
        example.put("zeekad_precision", 0.278d);
        assertThat(FeedbackSummaryRecord.fromRawMap(example).getPrecisionSummaryText())
                .isEqualTo("정탐률 27.8% · 판정 18/50건(36.0%)");

        // 반올림은 HALF_UP: 49/400 = 12.25% → 12.3%
        Map<String, Object> half = new LinkedHashMap<>();
        half.put("incidents", 400L);
        half.put("resolved", 49L);
        half.put("zeekad_precision", 0.5d);
        assertThat(FeedbackSummaryRecord.fromRawMap(half).getPrecisionSummaryText())
                .isEqualTo("정탐률 50.0% · 판정 49/400건(12.3%)");

        // 경보: 경보 판정 9건은 표본 부족, 10건은 경보 정탐률
        Map<String, Object> alertNine = new LinkedHashMap<>();
        alertNine.put("alerted", 20L);
        alertNine.put("alerted_resolved", 9L);
        alertNine.put("zeekad_alert_precision", 0.778d);
        assertThat(FeedbackSummaryRecord.fromRawMap(alertNine).getAlertPrecisionSummaryText())
                .isEqualTo("표본 부족 · 경보 판정 9/20건(45.0%)");
        Map<String, Object> alertTen = new LinkedHashMap<>();
        alertTen.put("alerted", 20L);
        alertTen.put("alerted_resolved", 10L);
        alertTen.put("zeekad_alert_precision", 0.7d);
        assertThat(FeedbackSummaryRecord.fromRawMap(alertTen).getAlertPrecisionSummaryText())
                .isEqualTo("경보 정탐률 70.0% · 경보 판정 10/20건(50.0%)");
    }
}
