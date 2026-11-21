package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * 인시던트 담당 현재 값(T25, 대시보드 DB incident_assignments). assignee*는 users를 붙여 읽은 값이다(해제면 null).
 */
public class IncidentAssignment {

    private String incidentId;
    private String captureId;
    private Long assigneeUserId;
    private OffsetDateTime assignedAt;
    private String assignedBy;
    private int version;
    private String assigneeUsername;
    private String assigneeDisplayName;
    private Boolean assigneeEnabled;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public Long getAssigneeUserId() { return assigneeUserId; }
    public void setAssigneeUserId(Long assigneeUserId) { this.assigneeUserId = assigneeUserId; }
    public OffsetDateTime getAssignedAt() { return assignedAt; }
    public void setAssignedAt(OffsetDateTime assignedAt) { this.assignedAt = assignedAt; }
    public String getAssignedBy() { return assignedBy; }
    public void setAssignedBy(String assignedBy) { this.assignedBy = assignedBy; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
    public String getAssigneeUsername() { return assigneeUsername; }
    public void setAssigneeUsername(String assigneeUsername) { this.assigneeUsername = assigneeUsername; }
    public String getAssigneeDisplayName() { return assigneeDisplayName; }
    public void setAssigneeDisplayName(String assigneeDisplayName) { this.assigneeDisplayName = assigneeDisplayName; }
    public Boolean getAssigneeEnabled() { return assigneeEnabled; }
    public void setAssigneeEnabled(Boolean assigneeEnabled) { this.assigneeEnabled = assigneeEnabled; }
}
