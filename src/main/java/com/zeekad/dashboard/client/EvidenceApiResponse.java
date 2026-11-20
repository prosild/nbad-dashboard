package com.zeekad.dashboard.client;

/**
 * FastAPI GET /api/v1/jobs/{job_id}/incidents/{rank} 응답 DTO.
 * 사건·모델 점수·관측 이름은 DB 뷰에서 가져오므로 이 응답에서는 evidence만 읽는다.
 */
public class EvidenceApiResponse {

    private boolean available;
    private String statusMessage;
    private Long jobId;
    private Integer rank;
    private EvidenceData evidence = EvidenceData.unavailable();

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

    public EvidenceData getEvidence() {
        return evidence;
    }

    public void setEvidence(EvidenceData evidence) {
        this.evidence = evidence == null ? EvidenceData.unavailable() : evidence;
    }
}
