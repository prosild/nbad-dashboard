package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * 불변 감사 로그 엔티티.
 */
public class AuditLog {

    private Long id;
    private OffsetDateTime occurredAt;
    private String actorUsername;
    private String actorRole;
    private String actionType;
    private String targetCaptureId;
    private Long targetJobId;
    private String targetIncidentId;
    private String detailJson;
    private String clientIp;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public OffsetDateTime getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(OffsetDateTime occurredAt) {
        this.occurredAt = occurredAt;
    }

    public String getActorUsername() {
        return actorUsername;
    }

    public void setActorUsername(String actorUsername) {
        this.actorUsername = actorUsername;
    }

    public String getActorRole() {
        return actorRole;
    }

    public void setActorRole(String actorRole) {
        this.actorRole = actorRole;
    }

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    public String getTargetCaptureId() {
        return targetCaptureId;
    }

    public void setTargetCaptureId(String targetCaptureId) {
        this.targetCaptureId = targetCaptureId;
    }

    public Long getTargetJobId() {
        return targetJobId;
    }

    public void setTargetJobId(Long targetJobId) {
        this.targetJobId = targetJobId;
    }

    public String getTargetIncidentId() {
        return targetIncidentId;
    }

    public void setTargetIncidentId(String targetIncidentId) {
        this.targetIncidentId = targetIncidentId;
    }

    public String getDetailJson() {
        return detailJson;
    }

    public void setDetailJson(String detailJson) {
        this.detailJson = detailJson;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }
}
