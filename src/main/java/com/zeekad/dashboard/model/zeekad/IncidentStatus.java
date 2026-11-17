package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * dashboard.incident_status 뷰 DTO.
 */
public class IncidentStatus {

    private Long jobId;
    private String incidentId;
    private String zeekadStatus;
    private String zeekadResolution;
    private OffsetDateTime updatedAt;
    private String updatedBy;

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

    public String getZeekadStatus() {
        return zeekadStatus;
    }

    public void setZeekadStatus(String zeekadStatus) {
        this.zeekadStatus = zeekadStatus;
    }

    public String getZeekadResolution() {
        return zeekadResolution;
    }

    public void setZeekadResolution(String zeekadResolution) {
        this.zeekadResolution = zeekadResolution;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(OffsetDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }
}
