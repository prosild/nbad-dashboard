package com.zeekad.dashboard.model.zeekad;

/** 인시던트가 든 작업·순위(T27 번호 API 위치) */
public class IncidentLocation {

    private Long jobId;
    private Integer queueRank;

    public Long getJobId() { return jobId; }
    public void setJobId(Long jobId) { this.jobId = jobId; }
    public Integer getQueueRank() { return queueRank; }
    public void setQueueRank(Integer queueRank) { this.queueRank = queueRank; }
}
