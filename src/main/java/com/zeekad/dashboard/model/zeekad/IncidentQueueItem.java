package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;

/**
 * dashboard.incident_queue 및 조인 상태/보고서/전송판단 조회 DTO.
 */
public class IncidentQueueItem {

    private Long jobId;
    private String captureId;
    private String bundleId;
    private Integer queueRank;
    private String incidentId;
    private String hostIp;
    private String zeekadRole;
    private OffsetDateTime eventStart;
    private OffsetDateTime eventEnd;
    private String zeekadPickedBy;
    private List<String> zeekadAlsoFlaggedBy = Collections.emptyList();
    private Long connectionCount;
    private List<String> hostName = Collections.emptyList();

    private String zeekadStatus;
    private String zeekadResolution;
    private OffsetDateTime statusUpdatedAt;
    private Long zeekadReportJobId;
    private boolean hasReport;
    private String zeekadReportKind;
    private Boolean zeekadVerificationPassed;
    private boolean zeekadWouldSend;
    private String zeekadReviewAction;
    private boolean zeekadReviewPending;
    /**
     * 경보 발송(T21): 사건 알림 Slack 기록이 있는 인시던트. incident_id 기준, 상태 후속 알림(status:*)은 뺀다.
     * dashboard.feedback_summary의 alerted와 같은 식이다(dry-run 기록·발송 실패 기록도 센다).
     */
    private boolean alerted;

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

    public String getBundleId() {
        return bundleId;
    }

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    public Integer getQueueRank() {
        return queueRank;
    }

    public void setQueueRank(Integer queueRank) {
        this.queueRank = queueRank;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
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

    public OffsetDateTime getEventStart() {
        return eventStart;
    }

    public void setEventStart(OffsetDateTime eventStart) {
        this.eventStart = eventStart;
    }

    public OffsetDateTime getEventEnd() {
        return eventEnd;
    }

    public void setEventEnd(OffsetDateTime eventEnd) {
        this.eventEnd = eventEnd;
    }

    public String getZeekadPickedBy() {
        return zeekadPickedBy;
    }

    public void setZeekadPickedBy(String zeekadPickedBy) {
        this.zeekadPickedBy = zeekadPickedBy;
    }

    public List<String> getZeekadAlsoFlaggedBy() {
        return zeekadAlsoFlaggedBy;
    }

    public void setZeekadAlsoFlaggedBy(List<String> zeekadAlsoFlaggedBy) {
        this.zeekadAlsoFlaggedBy = zeekadAlsoFlaggedBy == null ? Collections.emptyList() : zeekadAlsoFlaggedBy;
    }

    public Long getConnectionCount() {
        return connectionCount;
    }

    public void setConnectionCount(Long connectionCount) {
        this.connectionCount = connectionCount;
    }

    public List<String> getHostName() {
        return hostName;
    }

    public void setHostName(List<String> hostName) {
        this.hostName = hostName == null ? Collections.emptyList() : hostName;
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

    public OffsetDateTime getStatusUpdatedAt() {
        return statusUpdatedAt;
    }

    public void setStatusUpdatedAt(OffsetDateTime statusUpdatedAt) {
        this.statusUpdatedAt = statusUpdatedAt;
    }

    public Long getZeekadReportJobId() {
        return zeekadReportJobId;
    }

    public void setZeekadReportJobId(Long zeekadReportJobId) {
        this.zeekadReportJobId = zeekadReportJobId;
    }

    public boolean isHasReport() {
        return hasReport;
    }

    public void setHasReport(boolean hasReport) {
        this.hasReport = hasReport;
    }

    public String getZeekadReportKind() {
        return zeekadReportKind;
    }

    public void setZeekadReportKind(String zeekadReportKind) {
        this.zeekadReportKind = zeekadReportKind;
    }

    public Boolean getZeekadVerificationPassed() {
        return zeekadVerificationPassed;
    }

    public void setZeekadVerificationPassed(Boolean zeekadVerificationPassed) {
        this.zeekadVerificationPassed = zeekadVerificationPassed;
    }

    public boolean isZeekadWouldSend() {
        return zeekadWouldSend;
    }

    public void setZeekadWouldSend(boolean zeekadWouldSend) {
        this.zeekadWouldSend = zeekadWouldSend;
    }

    public String getZeekadReviewAction() {
        return zeekadReviewAction;
    }

    public void setZeekadReviewAction(String zeekadReviewAction) {
        this.zeekadReviewAction = zeekadReviewAction;
    }

    public boolean isZeekadReviewPending() {
        return zeekadReviewPending;
    }

    public void setZeekadReviewPending(boolean zeekadReviewPending) {
        this.zeekadReviewPending = zeekadReviewPending;
    }

    public boolean isAlerted() {
        return alerted;
    }

    public void setAlerted(boolean alerted) {
        this.alerted = alerted;
    }

    public boolean isMultiModelFlagged() {
        return zeekadAlsoFlaggedBy != null && !zeekadAlsoFlaggedBy.isEmpty();
    }
}
