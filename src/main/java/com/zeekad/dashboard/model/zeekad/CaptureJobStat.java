package com.zeekad.dashboard.model.zeekad;

/**
 * 캡처별 작업 통계(T24): 가장 최근의 끝난 작업(succeeded·failed 중 job_id 최대), 최근 성공 작업, 기간 안 실패 작업 수.
 */
public class CaptureJobStat {
    private String captureId;
    private Long latestEndedJobId;
    private Long latestSucceededJobId;
    private Long failedInPeriod;

    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public Long getLatestEndedJobId() { return latestEndedJobId; }
    public void setLatestEndedJobId(Long latestEndedJobId) { this.latestEndedJobId = latestEndedJobId; }
    public Long getLatestSucceededJobId() { return latestSucceededJobId; }
    public void setLatestSucceededJobId(Long latestSucceededJobId) { this.latestSucceededJobId = latestSucceededJobId; }
    public long getFailedInPeriod() { return failedInPeriod == null ? 0 : failedInPeriod; }
    public void setFailedInPeriod(Long failedInPeriod) { this.failedInPeriod = failedInPeriod; }
}
