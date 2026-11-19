package com.zeekad.dashboard.model.zeekad;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * dashboard.feedback_summary 뷰 DTO (migration 017, 고정 열 및 부가 열 수용).
 */
public class FeedbackSummaryRecord {

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

    public String getPrecisionSummaryText() {
        if (incidents == null || incidents <= 0) {
            return zeekadPrecision == null
                    ? "- (결론 없음)"
                    : String.format(Locale.US, "정밀도 %.2f", zeekadPrecision);
        }
        long resolvedCount = safeLong(resolved);
        double resolvedRatePct = (double) resolvedCount / incidents * 100.0;
        if (zeekadPrecision != null) {
            return String.format(Locale.US, "정밀도 %.2f, 결론 %d/%d (%.1f%%)",
                    zeekadPrecision, resolvedCount, incidents, resolvedRatePct);
        }
        return String.format(Locale.US, "- (결론 %d/%d, %.1f%%)",
                resolvedCount, incidents, resolvedRatePct);
    }

    public String getAlertPrecisionSummaryText() {
        if (alerted == null || alerted <= 0) {
            return "- (알림 없음)";
        }
        Long effRes = getEffectiveAlertedResolved();
        String rateSuffix = zeekadAlertResolvedRate != null
                ? String.format(Locale.US, " (%.1f%%)", zeekadAlertResolvedRate * 100.0)
                : "";
        if (effRes == null) {
            return zeekadAlertPrecision == null
                    ? "- (결론 없음)"
                    : String.format(Locale.US, "정밀도 %.2f%s", zeekadAlertPrecision, rateSuffix);
        }
        return zeekadAlertPrecision != null
                ? String.format(Locale.US, "정밀도 %.2f, 결론 %d/%d%s", zeekadAlertPrecision, effRes, alerted, rateSuffix)
                : String.format(Locale.US, "- (결론 %d/%d%s)", effRes, alerted, rateSuffix);
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
