package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

/**
 * dashboard.send_decisions 뷰 DTO.
 */
public class SendDecision {

    private Long jobId;
    private String incidentId;
    private Boolean zeekadWouldSend;
    private String zeekadDecidedBy;
    private String policyId;
    private String policyChoice;
    private Boolean policyMandatory;
    private JsonNode policyReasons;
    private String llmChoice;
    private String decisionModel;
    private String decisionModelChoice;
    private Double decisionModelConfidence;
    private JsonNode decisionModelProbabilities;
    private String decisionModelError;
    private String zeekadSourceRun;
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

    public Boolean getZeekadWouldSend() {
        return zeekadWouldSend;
    }

    public void setZeekadWouldSend(Boolean zeekadWouldSend) {
        this.zeekadWouldSend = zeekadWouldSend;
    }

    public String getZeekadDecidedBy() {
        return zeekadDecidedBy;
    }

    public void setZeekadDecidedBy(String zeekadDecidedBy) {
        this.zeekadDecidedBy = zeekadDecidedBy;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getPolicyChoice() {
        return policyChoice;
    }

    public void setPolicyChoice(String policyChoice) {
        this.policyChoice = policyChoice;
    }

    public Boolean getPolicyMandatory() {
        return policyMandatory;
    }

    public void setPolicyMandatory(Boolean policyMandatory) {
        this.policyMandatory = policyMandatory;
    }

    public JsonNode getPolicyReasons() {
        return policyReasons;
    }

    public void setPolicyReasons(JsonNode policyReasons) {
        this.policyReasons = policyReasons;
    }

    public String getLlmChoice() {
        return llmChoice;
    }

    public void setLlmChoice(String llmChoice) {
        this.llmChoice = llmChoice;
    }

    public String getDecisionModel() {
        return decisionModel;
    }

    public void setDecisionModel(String decisionModel) {
        this.decisionModel = decisionModel;
    }

    public String getDecisionModelChoice() {
        return decisionModelChoice;
    }

    public void setDecisionModelChoice(String decisionModelChoice) {
        this.decisionModelChoice = decisionModelChoice;
    }

    public Double getDecisionModelConfidence() {
        return decisionModelConfidence;
    }

    public void setDecisionModelConfidence(Double decisionModelConfidence) {
        this.decisionModelConfidence = decisionModelConfidence;
    }

    public JsonNode getDecisionModelProbabilities() {
        return decisionModelProbabilities;
    }

    public void setDecisionModelProbabilities(JsonNode decisionModelProbabilities) {
        this.decisionModelProbabilities = decisionModelProbabilities;
    }

    public String getDecisionModelError() {
        return decisionModelError;
    }

    public void setDecisionModelError(String decisionModelError) {
        this.decisionModelError = decisionModelError;
    }

    public String getZeekadSourceRun() {
        return zeekadSourceRun;
    }

    public void setZeekadSourceRun(String zeekadSourceRun) {
        this.zeekadSourceRun = zeekadSourceRun;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
