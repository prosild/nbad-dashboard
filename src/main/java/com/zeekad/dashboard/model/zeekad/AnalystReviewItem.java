package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * dashboard.analyst_review_queue (scoring_jobs 조인 포함) 뷰 DTO.
 */
public class AnalystReviewItem {

    private Long jobId;
    private String captureId;
    private String incidentId;
    private Integer queueRank;
    private String hostIp;
    private String zeekadRole;
    private String zeekadReviewReason;
    private OffsetDateTime requestedAt;
    private String zeekadReviewAction;
    private String analyst;
    private OffsetDateTime decidedAt;

    public Long getJobId() {
        return jobId;
    }

    public void setJobId(Long jobId) {
        this.jobId = jobId;
    }

    public String getCaptureId() {
        return captureId;
    }

    public void setCaptureId(String captureId) {
        this.captureId = captureId;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
    }

    public Integer getQueueRank() {
        return queueRank;
    }

    public void setQueueRank(Integer queueRank) {
        this.queueRank = queueRank;
    }

    public String getHostIp() {
        return hostIp;
    }

    public void setHostIp(String hostIp) {
        this.hostIp = hostIp;
    }

    public String getZeekadRole() {
        return zeekadRole;
    }

    public void setZeekadRole(String zeekadRole) {
        this.zeekadRole = zeekadRole;
    }

    public String getZeekadReviewReason() {
        return zeekadReviewReason;
    }

    public void setZeekadReviewReason(String zeekadReviewReason) {
        this.zeekadReviewReason = zeekadReviewReason;
    }

    public OffsetDateTime getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(OffsetDateTime requestedAt) {
        this.requestedAt = requestedAt;
    }

    public String getZeekadReviewAction() {
        return zeekadReviewAction;
    }

    public void setZeekadReviewAction(String zeekadReviewAction) {
        this.zeekadReviewAction = zeekadReviewAction;
    }

    public String getAnalyst() {
        return analyst;
    }

    public void setAnalyst(String analyst) {
        this.analyst = analyst;
    }

    public OffsetDateTime getDecidedAt() {
        return decidedAt;
    }

    public void setDecidedAt(OffsetDateTime decidedAt) {
        this.decidedAt = decidedAt;
    }

    public boolean isPending() {
        return zeekadReviewAction == null || zeekadReviewAction.isBlank();
    }
}
