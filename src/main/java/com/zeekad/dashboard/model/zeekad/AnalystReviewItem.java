package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * dashboard.analyst_review_queue (scoring_jobs 조인 포함) 뷰 DTO.
 */
public class AnalystReviewItem {

    private Long jobId;
    private Long reviewJobId;
    private String captureId;
    private String incidentId;
    private Integer queueRank;
    private String hostIp;
    private String zeekadRole;
    private String zeekadReviewReason;
    private OffsetDateTime requestedAt;
    private String zeekadReviewAction;
    private String analyst;
    private String analystDisplay;
    private OffsetDateTime decidedAt;
    private OffsetDateTime zeekadReviewResumedAt;
    private Boolean zeekadReviewResumeFailed;
    /** T27 인시던트 번호(대시보드 DB, 매기지 못했으면 null) */
    private Long incidentNo;

    public Long getIncidentNo() {
        return incidentNo;
    }

    public void setIncidentNo(Long incidentNo) {
        this.incidentNo = incidentNo;
    }

    public Long getJobId() {
        return jobId;
    }

    public void setJobId(Long jobId) {
        this.jobId = jobId;
    }

    public Long getReviewJobId() {
        return reviewJobId;
    }

    public void setReviewJobId(Long reviewJobId) {
        this.reviewJobId = reviewJobId;
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

    public String getAnalystDisplay() {
        return analystDisplay;
    }

    public void setAnalystDisplay(String analystDisplay) {
        this.analystDisplay = analystDisplay;
    }

    public OffsetDateTime getDecidedAt() {
        return decidedAt;
    }

    public void setDecidedAt(OffsetDateTime decidedAt) {
        this.decidedAt = decidedAt;
    }

    public OffsetDateTime getZeekadReviewResumedAt() {
        return zeekadReviewResumedAt;
    }

    public void setZeekadReviewResumedAt(OffsetDateTime zeekadReviewResumedAt) {
        this.zeekadReviewResumedAt = zeekadReviewResumedAt;
    }

    public Boolean getZeekadReviewResumeFailed() {
        return zeekadReviewResumeFailed;
    }

    public void setZeekadReviewResumeFailed(Boolean zeekadReviewResumeFailed) {
        this.zeekadReviewResumeFailed = zeekadReviewResumeFailed;
    }

    public boolean isPending() {
        return zeekadReviewAction == null || zeekadReviewAction.isBlank();
    }

    public boolean isResumeFailed() {
        return Boolean.TRUE.equals(zeekadReviewResumeFailed);
    }

    public String getResumeStatusLabel() {
        if (isPending()) {
            return "에스컬레이션 대기";
        }
        if (Boolean.TRUE.equals(zeekadReviewResumeFailed)) {
            return "반영 실패(관리자 확인 필요)";
        }
        if (zeekadReviewResumedAt != null) {
            return "반영됨";
        }
        return "반영 중";
    }
}
