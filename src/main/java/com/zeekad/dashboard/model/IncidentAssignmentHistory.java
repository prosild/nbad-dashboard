package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * 담당 변경 이력 한 행(T25, 추가만). fromUsername·toUsername은 users를 붙여 읽은 값이다(미배정이면 null).
 */
public class IncidentAssignmentHistory {

    private Long id;
    private String incidentId;
    private String captureId;
    private Long jobId;
    private Long fromUserId;
    private Long toUserId;
    private String fromUsername;
    private String toUsername;
    private String actorUsername;
    /** manual · auto_on_start */
    private String reason;
    private OffsetDateTime changedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public Long getJobId() { return jobId; }
    public void setJobId(Long jobId) { this.jobId = jobId; }
    public Long getFromUserId() { return fromUserId; }
    public void setFromUserId(Long fromUserId) { this.fromUserId = fromUserId; }
    public Long getToUserId() { return toUserId; }
    public void setToUserId(Long toUserId) { this.toUserId = toUserId; }
    public String getFromUsername() { return fromUsername; }
    public void setFromUsername(String fromUsername) { this.fromUsername = fromUsername; }
    public String getToUsername() { return toUsername; }
    public void setToUsername(String toUsername) { this.toUsername = toUsername; }
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public OffsetDateTime getChangedAt() { return changedAt; }
    public void setChangedAt(OffsetDateTime changedAt) { this.changedAt = changedAt; }
}
