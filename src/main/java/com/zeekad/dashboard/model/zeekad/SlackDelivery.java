package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

/**
 * dashboard.slack_deliveries 뷰 DTO.
 */
public class SlackDelivery {

    private Long jobId;
    private String incidentId;
    private String zeekadMessageKind;
    private String zeekadMessageVersion;
    private String zeekadDeliveryMode;
    private String zeekadDeliveryStatus;
    private JsonNode slackPayload;
    private String slackTs;
    private OffsetDateTime deliveredAt;
    private String error;
    private OffsetDateTime createdAt;

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

    public String getZeekadMessageKind() {
        return zeekadMessageKind;
    }

    public void setZeekadMessageKind(String zeekadMessageKind) {
        this.zeekadMessageKind = zeekadMessageKind;
    }

    public String getZeekadMessageVersion() {
        return zeekadMessageVersion;
    }

    public void setZeekadMessageVersion(String zeekadMessageVersion) {
        this.zeekadMessageVersion = zeekadMessageVersion;
    }

    public String getZeekadDeliveryMode() {
        return zeekadDeliveryMode;
    }

    public void setZeekadDeliveryMode(String zeekadDeliveryMode) {
        this.zeekadDeliveryMode = zeekadDeliveryMode;
    }

    public String getZeekadDeliveryStatus() {
        return zeekadDeliveryStatus;
    }

    public void setZeekadDeliveryStatus(String zeekadDeliveryStatus) {
        this.zeekadDeliveryStatus = zeekadDeliveryStatus;
    }

    public JsonNode getSlackPayload() {
        return slackPayload;
    }

    public void setSlackPayload(JsonNode slackPayload) {
        this.slackPayload = slackPayload;
    }

    public String getSlackTs() {
        return slackTs;
    }

    public void setSlackTs(String slackTs) {
        this.slackTs = slackTs;
    }

    public OffsetDateTime getDeliveredAt() {
        return deliveredAt;
    }

    public void setDeliveredAt(OffsetDateTime deliveredAt) {
        this.deliveredAt = deliveredAt;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isDryRunOrRecorded() {
        return "dry_run".equalsIgnoreCase(zeekadDeliveryMode)
                || "recorded".equalsIgnoreCase(zeekadDeliveryStatus);
    }
}
