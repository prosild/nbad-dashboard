package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * 인시던트 번호(T27, 대시보드 DB incident_refs). 한 번 매기면 바뀌지 않는다.
 * zeekad 쪽 후보(번호 매기기 전)를 담을 때는 incidentNo가 null이다.
 */
public class IncidentRef {

    private Long incidentNo;
    private String incidentId;
    private String captureId;
    private OffsetDateTime detectedAt;
    private OffsetDateTime createdAt;

    public IncidentRef() {
    }

    public IncidentRef(String incidentId, String captureId, OffsetDateTime detectedAt) {
        this.incidentId = incidentId;
        this.captureId = captureId;
        this.detectedAt = detectedAt;
    }

    public Long getIncidentNo() { return incidentNo; }
    public void setIncidentNo(Long incidentNo) { this.incidentNo = incidentNo; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public OffsetDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(OffsetDateTime detectedAt) { this.detectedAt = detectedAt; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }
}
