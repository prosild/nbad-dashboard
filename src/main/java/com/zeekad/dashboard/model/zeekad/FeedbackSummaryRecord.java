package com.zeekad.dashboard.model.zeekad;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * dashboard.feedback_summary 뷰 DTO (migration 017, 고정 열 및 부가 열 수용).
 */
public class FeedbackSummaryRecord {

    /** 판정이 이 건수보다 적으면 비율 대신 "표본 부족"을 쓴다(docs/ui-terminology.md '운영 지표 정의'). */
    public static final long SAMPLE_MIN = 10L;
    static final String SAMPLE_SHORT_LABEL = "표본 부족";

    private String captureId;
    private String bundleId;
    private String zeekadPickedBy;
    private Long incidents;
    private Long alerted;
    private Long resolved;
    private Long truePositive;
    private Long falsePositive;
    private Long benign;
    private Double zeekadPrecision;
    private Double zeekadAlertPrecision;
    private Double zeekadAlertResolvedRate;
    private Long alertedResolved;
    private Map<String, Object> extraAttributes = Collections.emptyMap();

    public static FeedbackSummaryRecord fromRawMap(Map<String, Object> raw) {
        FeedbackSummaryRecord record = new FeedbackSummaryRecord();
        if (raw == null || raw.isEmpty()) {
            return record;
        }
        Map<String, Object> extras = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : raw.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String keyLower = entry.getKey().toLowerCase(Locale.ROOT);
            Object val = entry.getValue();
            switch (keyLower) {
                case "capture_id" -> record.setCaptureId(asString(val));
                case "bundle_id" -> record.setBundleId(asString(val));
                case "zeekad_picked_by" -> record.setZeekadPickedBy(asString(val));
                case "incidents" -> record.setIncidents(asLong(val));
                case "alerted" -> record.setAlerted(asLong(val));
                case "resolved" -> record.setResolved(asLong(val));
                case "true_positive" -> record.setTruePositive(asLong(val));
                case "false_positive" -> record.setFalsePositive(asLong(val));
                case "benign" -> record.setBenign(asLong(val));
                case "zeekad_precision" -> record.setZeekadPrecision(asDouble(val));
                case "zeekad_alert_precision" -> record.setZeekadAlertPrecision(asDouble(val));
                case "zeekad_alert_resolved_rate" -> record.setZeekadAlertResolvedRate(asDouble(val));
                case "alerted_resolved", "alert_resolved" -> record.setAlertedResolved(asLong(val));
                default -> extras.put(keyLower, val);
            }
        }
        record.setExtraAttributes(Collections.unmodifiableMap(extras));
        return record;
    }

    public boolean isAllModel() {
        return zeekadPickedBy != null && "all".equalsIgnoreCase(zeekadPickedBy.trim());
    }

    public Long getEffectiveAlertedResolved() {
        if (alertedResolved != null) {
            return alertedResolved;
        }
        if (alerted != null && alerted > 0 && zeekadAlertResolvedRate != null) {
            return Math.round(zeekadAlertResolvedRate * alerted);
        }
        if (alerted != null && alerted == 0) {
            return 0L;
        }
        return null;
    }

    /**
     * 정탐률 문장(docs/ui-terminology.md '운영 지표 정의', 프론트엔드 utils/operations.ts와 같은 형식. 두 시험이 같은 기대값 파일
     * frontend/src/test/fixtures/feedback-summary-text-cases.json을 읽는다). T67: 판정 수 ÷ 인시던트 수의 백분율은 쓰지 않는다(탐지율로 읽힌다).
     * 판정 0건이면 "분석가 판정 없음 / 모델이 올린 인시던트 n건"(인시던트도 0이면 "분석가 판정 없음"),
     * 판정 10건 미만이면 "표본 부족 · 분석가 판정 r건 / 모델이 올린 인시던트 n건", 그 밖에는 "정탐률 x% · 분석가 판정 r건 / 모델이 올린 인시던트 n건".
     * 인시던트 0건이면 " / …" 부분이 없다.
     */
    public String getPrecisionSummaryText() {
        long resolvedCount = safeLong(resolved);
        long incidentCount = safeLong(incidents);
        String tail = incidentCount > 0 ? String.format(Locale.US, " / 모델이 올린 인시던트 %,d건", incidentCount) : "";
        if (resolvedCount <= 0) {
            return "분석가 판정 없음" + tail;
        }
        String head = resolvedCount < SAMPLE_MIN ? SAMPLE_SHORT_LABEL : "정탐률 " + ratioPercent(zeekadPrecision);
        return head + String.format(Locale.US, " · 분석가 판정 %,d건", resolvedCount) + tail;
    }

    /**
     * 경보 정탐률 문장(T67: 판정 수 ÷ 경보 수의 백분율은 쓰지 않는다). 경보 0건이면 "경보 없음",
     * 경보 판정 수를 알 수 없으면 "경보 n건 · 분석가 판정 수 알 수 없음", 경보 판정 0건이면 "분석가 판정 없음 / 경보 n건",
     * 경보 판정 10건 미만이면 "표본 부족 · 분석가 판정 r건 / 경보 n건", 그 밖에는 "경보 정탐률 x% · 분석가 판정 r건 / 경보 n건".
     */
    public String getAlertPrecisionSummaryText() {
        long alertedCount = safeLong(alerted);
        if (alertedCount <= 0) {
            return "경보 없음";
        }
        Long effRes = getEffectiveAlertedResolved();
        if (effRes == null) {
            return String.format(Locale.US, "경보 %,d건 · 분석가 판정 수 알 수 없음", alertedCount);
        }
        String tail = String.format(Locale.US, " / 경보 %,d건", alertedCount);
        if (effRes <= 0) {
            return "분석가 판정 없음" + tail;
        }
        String head = effRes < SAMPLE_MIN ? SAMPLE_SHORT_LABEL : "경보 정탐률 " + ratioPercent(zeekadAlertPrecision);
        return head + String.format(Locale.US, " · 분석가 판정 %,d건", effRes) + tail;
    }

    /** 0~1 비율을 소수 첫째 자리 퍼센트로(반올림 HALF_UP). 예: 0.6 → "60.0%" */
    static String ratioPercent(Double ratio) {
        if (ratio == null || !Double.isFinite(ratio)) {
            return "-";
        }
        return BigDecimal.valueOf(ratio).multiply(BigDecimal.valueOf(100))
                .setScale(1, RoundingMode.HALF_UP)
                .toPlainString() + "%";
    }

    private static long safeLong(Long val) {
        return val != null ? val : 0L;
    }

    private static String asString(Object val) {
        return val == null ? null : val.toString();
    }

    private static Long asLong(Object val) {
        if (val == null) {
            return null;
        }
        if (val instanceof Number num) {
            return num.longValue();
        }
        String text = val.toString().trim();
        if (text.isEmpty()) {
            return null;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static Double asDouble(Object val) {
        if (val == null) {
            return null;
        }
        if (val instanceof Number num) {
            double d = num.doubleValue();
            return Double.isFinite(d) ? d : null;
        }
        String text = val.toString().trim();
        if (text.isEmpty()) {
            return null;
        }
        try {
            double d = Double.parseDouble(text);
            return Double.isFinite(d) ? d : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    public String getCaptureId() {
        return captureId;
    }

    public void setCaptureId(String captureId) {
        this.captureId = captureId;
    }

    public String getBundleId() {
        return bundleId;
    }

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    public String getZeekadPickedBy() {
        return zeekadPickedBy;
    }

    public void setZeekadPickedBy(String zeekadPickedBy) {
        this.zeekadPickedBy = zeekadPickedBy;
    }

    public Long getIncidents() {
        return incidents;
    }

    public void setIncidents(Long incidents) {
        this.incidents = incidents;
    }

    public Long getAlerted() {
        return alerted;
    }

    public void setAlerted(Long alerted) {
        this.alerted = alerted;
    }

    public Long getResolved() {
        return resolved;
    }

    public void setResolved(Long resolved) {
        this.resolved = resolved;
    }

    public Long getTruePositive() {
        return truePositive;
    }

    public void setTruePositive(Long truePositive) {
        this.truePositive = truePositive;
    }

    public Long getFalsePositive() {
        return falsePositive;
    }

    public void setFalsePositive(Long falsePositive) {
        this.falsePositive = falsePositive;
    }

    public Long getBenign() {
        return benign;
    }

    public void setBenign(Long benign) {
        this.benign = benign;
    }

    public Double getZeekadPrecision() {
        return zeekadPrecision;
    }

    public void setZeekadPrecision(Double zeekadPrecision) {
        this.zeekadPrecision = zeekadPrecision;
    }

    public Double getZeekadAlertPrecision() {
        return zeekadAlertPrecision;
    }

    public void setZeekadAlertPrecision(Double zeekadAlertPrecision) {
        this.zeekadAlertPrecision = zeekadAlertPrecision;
    }

    public Double getZeekadAlertResolvedRate() {
        return zeekadAlertResolvedRate;
    }

    public void setZeekadAlertResolvedRate(Double zeekadAlertResolvedRate) {
        this.zeekadAlertResolvedRate = zeekadAlertResolvedRate;
    }

    public Long getAlertedResolved() {
        return alertedResolved;
    }

    public void setAlertedResolved(Long alertedResolved) {
        this.alertedResolved = alertedResolved;
    }

    public Map<String, Object> getExtraAttributes() {
        return extraAttributes;
    }

    public void setExtraAttributes(Map<String, Object> extraAttributes) {
        this.extraAttributes = extraAttributes == null ? Collections.emptyMap() : extraAttributes;
    }
}
