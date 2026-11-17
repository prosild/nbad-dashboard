package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

/**
 * dashboard.incident_reports 뷰 DTO.
 */
public class IncidentReport {

    private Long jobId;
    private String incidentId;
    private String zeekadReportKind;
    private String zeekadReportVersion;
    private String zeekadInputVersion;
    private JsonNode zeekadReport;
    private Boolean zeekadVerificationPassed;
    private String zeekadVerificationReason;
    private JsonNode zeekadVerificationProblems;
    private String llmModelRequested;
    private String llmModelVersion;
    private Double llmSeconds;
    private Integer llmInputTokens;
    private Integer llmOutputTokens;
    private Integer llmThinkingTokens;
    private String llmError;
    private JsonNode zeekadAttackCandidates;
    private String zeekadSourceRun;
    private OffsetDateTime createdAt;
    private JsonNode zeekadFacts;
    private JsonNode zeekadPseudonyms;

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

    public String getZeekadReportKind() {
        return zeekadReportKind;
    }

    public void setZeekadReportKind(String zeekadReportKind) {
        this.zeekadReportKind = zeekadReportKind;
    }

    public String getZeekadReportVersion() {
        return zeekadReportVersion;
    }

    public void setZeekadReportVersion(String zeekadReportVersion) {
        this.zeekadReportVersion = zeekadReportVersion;
    }

    public String getZeekadInputVersion() {
        return zeekadInputVersion;
    }

    public void setZeekadInputVersion(String zeekadInputVersion) {
        this.zeekadInputVersion = zeekadInputVersion;
    }

    public JsonNode getZeekadReport() {
        return zeekadReport;
    }

    public void setZeekadReport(JsonNode zeekadReport) {
        this.zeekadReport = zeekadReport;
    }

    public Boolean getZeekadVerificationPassed() {
        return zeekadVerificationPassed;
    }

    public void setZeekadVerificationPassed(Boolean zeekadVerificationPassed) {
        this.zeekadVerificationPassed = zeekadVerificationPassed;
    }

    public String getZeekadVerificationReason() {
        return zeekadVerificationReason;
    }

    public void setZeekadVerificationReason(String zeekadVerificationReason) {
        this.zeekadVerificationReason = zeekadVerificationReason;
    }

    public JsonNode getZeekadVerificationProblems() {
        return zeekadVerificationProblems;
    }

    public void setZeekadVerificationProblems(JsonNode zeekadVerificationProblems) {
        this.zeekadVerificationProblems = zeekadVerificationProblems;
    }

    public String getLlmModelRequested() {
        return llmModelRequested;
    }

    public void setLlmModelRequested(String llmModelRequested) {
        this.llmModelRequested = llmModelRequested;
    }

    public String getLlmModelVersion() {
        return llmModelVersion;
    }

    public void setLlmModelVersion(String llmModelVersion) {
        this.llmModelVersion = llmModelVersion;
    }

    public Double getLlmSeconds() {
        return llmSeconds;
    }

    public void setLlmSeconds(Double llmSeconds) {
        this.llmSeconds = llmSeconds;
    }

    public Integer getLlmInputTokens() {
        return llmInputTokens;
    }

    public void setLlmInputTokens(Integer llmInputTokens) {
        this.llmInputTokens = llmInputTokens;
    }

    public Integer getLlmOutputTokens() {
        return llmOutputTokens;
    }

    public void setLlmOutputTokens(Integer llmOutputTokens) {
        this.llmOutputTokens = llmOutputTokens;
    }

    public Integer getLlmThinkingTokens() {
        return llmThinkingTokens;
    }

    public void setLlmThinkingTokens(Integer llmThinkingTokens) {
        this.llmThinkingTokens = llmThinkingTokens;
    }

    public String getLlmError() {
        return llmError;
    }

    public void setLlmError(String llmError) {
        this.llmError = llmError;
    }

    public JsonNode getZeekadAttackCandidates() {
        return zeekadAttackCandidates;
    }

    public void setZeekadAttackCandidates(JsonNode zeekadAttackCandidates) {
        this.zeekadAttackCandidates = zeekadAttackCandidates;
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

    public JsonNode getZeekadFacts() {
        return zeekadFacts;
    }

    public void setZeekadFacts(JsonNode zeekadFacts) {
        this.zeekadFacts = zeekadFacts;
    }

    public JsonNode getZeekadPseudonyms() {
        return zeekadPseudonyms;
    }

    public void setZeekadPseudonyms(JsonNode zeekadPseudonyms) {
        this.zeekadPseudonyms = zeekadPseudonyms;
    }
}
