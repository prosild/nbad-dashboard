package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * dashboard.incident_status_history 뷰 DTO.
 */
public class IncidentStatusHistory {

    private Long jobId;
    private String incidentId;
    private String fromStatus;
    private String toStatus;
    private String zeekadResolution;
    private String actor;
    private String reason;
    private OffsetDateTime changedAt;

    public Long getJobId() {
        return jobId;
    }

    public void setJobId(Long jobId) {
        this.jobId = jobId;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
    }

    public String getFromStatus() {
        return fromStatus;
    }

    public void setFromStatus(String fromStatus) {
        this.fromStatus = fromStatus;
    }

    public String getToStatus() {
        return toStatus;
    }

    public void setToStatus(String toStatus) {
        this.toStatus = toStatus;
    }

    public String getZeekadResolution() {
        return zeekadResolution;
    }

    public void setZeekadResolution(String zeekadResolution) {
        this.zeekadResolution = zeekadResolution;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public OffsetDateTime getChangedAt() {
        return changedAt;
    }

    public void setChangedAt(OffsetDateTime changedAt) {
        this.changedAt = changedAt;
    }
}
