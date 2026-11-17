package com.zeekad.dashboard.client;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * FastAPI GET /api/v1/jobs/{job_id}/incidents/{rank} 응답 DTO.
 */
public class EvidenceApiResponse {

    private boolean available;
    private String statusMessage;
    private Long jobId;
    private Integer rank;
    private Map<String, Object> incident = Collections.emptyMap();
    private List<Map<String, Object>> modelScores = Collections.emptyList();
    private List<Map<String, Object>> assetNames = Collections.emptyList();
    private EvidenceData evidence = EvidenceData.unavailable();
    private Map<String, Object> rawPayload = Collections.emptyMap();

    public static EvidenceApiResponse unavailable() {
        EvidenceApiResponse resp = new EvidenceApiResponse();
        resp.setAvailable(false);
        resp.setStatusMessage(EvidenceData.FALLBACK_MESSAGE);
        resp.setEvidence(EvidenceData.unavailable());
        return resp;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public Long getJobId() {
        return jobId;
    }

    public void setJobId(Long jobId) {
        this.jobId = jobId;
    }

    public Integer getRank() {
        return rank;
    }

    public void setRank(Integer rank) {
        this.rank = rank;
    }

    public Map<String, Object> getIncident() {
        return incident;
    }

    public void setIncident(Map<String, Object> incident) {
        this.incident = incident == null ? Collections.emptyMap() : incident;
    }

    public List<Map<String, Object>> getModelScores() {
        return modelScores;
    }

    public void setModelScores(List<Map<String, Object>> modelScores) {
        this.modelScores = modelScores == null ? Collections.emptyList() : modelScores;
    }

    public List<Map<String, Object>> getAssetNames() {
        return assetNames;
    }

    public void setAssetNames(List<Map<String, Object>> assetNames) {
        this.assetNames = assetNames == null ? Collections.emptyList() : assetNames;
    }

    public EvidenceData getEvidence() {
        return evidence;
    }

    public void setEvidence(EvidenceData evidence) {
        this.evidence = evidence == null ? EvidenceData.unavailable() : evidence;
    }

    public Map<String, Object> getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(Map<String, Object> rawPayload) {
        this.rawPayload = rawPayload == null ? Collections.emptyMap() : rawPayload;
    }
}
