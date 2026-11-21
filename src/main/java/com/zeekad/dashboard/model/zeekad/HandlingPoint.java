package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * 처리 시간 지표·담당 현황(T25) 투영: 인시던트마다 시각만. 차이·기간 거르기·백분위는 Java에서 한다.
 * ackAt = 이력에서 to_status = investigating인 첫 changed_at, statusUpdatedAt은 종결이면 종결 시각이다.
 */
public class HandlingPoint {
    private String incidentId;
    private String captureId;
    private OffsetDateTime eventStart;
    private OffsetDateTime detectedAt;
    /** open · investigating · closed · 그 밖(소문자) */
    private String statusNorm;
    private String priority;
    private OffsetDateTime ackAt;
    private OffsetDateTime statusUpdatedAt;
    private String zeekadResolution;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public OffsetDateTime getEventStart() { return eventStart; }
    public void setEventStart(OffsetDateTime eventStart) { this.eventStart = eventStart; }
    public OffsetDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(OffsetDateTime detectedAt) { this.detectedAt = detectedAt; }
    public String getStatusNorm() { return statusNorm; }
    public void setStatusNorm(String statusNorm) { this.statusNorm = statusNorm; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public OffsetDateTime getAckAt() { return ackAt; }
    public void setAckAt(OffsetDateTime ackAt) { this.ackAt = ackAt; }
    public OffsetDateTime getStatusUpdatedAt() { return statusUpdatedAt; }
    public void setStatusUpdatedAt(OffsetDateTime statusUpdatedAt) { this.statusUpdatedAt = statusUpdatedAt; }
    public String getZeekadResolution() { return zeekadResolution; }
    public void setZeekadResolution(String zeekadResolution) { this.zeekadResolution = zeekadResolution; }
}
