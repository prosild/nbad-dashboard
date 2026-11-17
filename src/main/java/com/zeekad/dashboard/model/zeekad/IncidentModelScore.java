package com.zeekad.dashboard.model.zeekad;

/**
 * dashboard.incident_model_scores 뷰 DTO.
 */
public class IncidentModelScore {

    private Long jobId;
    private String incidentId;
    private String zeekadModel;
    private Double maxScore;
    private Integer candidateWindows;
    private Integer windows;

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

    public String getZeekadModel() {
        return zeekadModel;
    }

    public void setZeekadModel(String zeekadModel) {
        this.zeekadModel = zeekadModel;
    }

    public Double getMaxScore() {
        return maxScore;
    }

    public void setMaxScore(Double maxScore) {
        this.maxScore = maxScore;
    }

    public Integer getCandidateWindows() {
        return candidateWindows;
    }

    public void setCandidateWindows(Integer candidateWindows) {
        this.candidateWindows = candidateWindows;
    }

    public Integer getWindows() {
        return windows;
    }

    public void setWindows(Integer windows) {
        this.windows = windows;
    }

    public String getWindowRatioLabel() {
        int cand = candidateWindows != null ? candidateWindows : 0;
        int total = windows != null ? windows : 0;
        return cand + " / " + total;
    }
}
