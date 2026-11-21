package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * T29 통합 큐를 기간 조건 없이 한 번 훑어 나눈 수. 다른 조건(띠 축 포함)은 모두 적용한 집합이다.
 * inPeriod = 기간 (after, until] 안, totalAll = 기간 전체, latestInPeriod = 기간 안 최대 탐지 시각,
 * newestBeforePeriod = 기간 시작(after) 이하 최대 탐지 시각.
 */
public class UnifiedQueuePeriodSplit {
    private long inPeriod;
    private long totalAll;
    private OffsetDateTime latestInPeriod;
    private OffsetDateTime newestBeforePeriod;

    public long getInPeriod() { return inPeriod; }
    public void setInPeriod(Long inPeriod) { this.inPeriod = inPeriod == null ? 0 : inPeriod; }
    public long getTotalAll() { return totalAll; }
    public void setTotalAll(Long totalAll) { this.totalAll = totalAll == null ? 0 : totalAll; }
    public OffsetDateTime getLatestInPeriod() { return latestInPeriod; }
    public void setLatestInPeriod(OffsetDateTime latestInPeriod) { this.latestInPeriod = latestInPeriod; }
    public OffsetDateTime getNewestBeforePeriod() { return newestBeforePeriod; }
    public void setNewestBeforePeriod(OffsetDateTime newestBeforePeriod) { this.newestBeforePeriod = newestBeforePeriod; }
}
