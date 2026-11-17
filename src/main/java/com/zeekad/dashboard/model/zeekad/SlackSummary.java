package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

/**
 * dashboard.slack_summaries 뷰 DTO.
 */
public class SlackSummary {

    private Long jobId;
    private String captureId;
    private String zeekadMessageVersion;
    private String zeekadDeliveryMode;
    private String zeekadDeliveryStatus;
    private JsonNode slackPayload;
    private String slackTs;
    private OffsetDateTime deliveredAt;
    private OffsetDateTime createdAt;

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

    public String getPayloadTextPreview() {
        if (slackPayload == null) {
            return "";
        }
        if (slackPayload.hasNonNull("text")) {
            return slackPayload.get("text").asText();
        }
        return slackPayload.toString();
    }

    public String getPayloadChannel() {
        if (slackPayload != null && slackPayload.hasNonNull("channel")) {
            return slackPayload.get("channel").asText();
        }
        return "-";
    }
}
