package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * 캡처별 최신 성공 작업 ID와 그 작업의 최대 event_end(T23 수집원 목록·진행 중 계산용).
 */
public class CaptureQueueStat {
    private String captureId;
    private Long latestJobId;
    private OffsetDateTime maxEventEnd;

    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public Long getLatestJobId() { return latestJobId; }
    public void setLatestJobId(Long latestJobId) { this.latestJobId = latestJobId; }
    public OffsetDateTime getMaxEventEnd() { return maxEventEnd; }
    public void setMaxEventEnd(OffsetDateTime maxEventEnd) { this.maxEventEnd = maxEventEnd; }
}
