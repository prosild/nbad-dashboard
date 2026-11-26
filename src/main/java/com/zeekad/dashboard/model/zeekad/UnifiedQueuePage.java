package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * T51 목록 한 문장(findUnifiedQueuePage)의 결과: 집계 하나 + 그 쪽의 큐 행들(목록 정렬 순서, 쪽이 비면 빈 목록).
 * total·latestDetectedAt = 일반 조건 ∧ 기간 ∧ 띠 축, totalAll·newestBeforePeriod = 일반 조건 ∧ 띠 축(기간 제외),
 * sum* = 일반 조건 ∧ 기간(띠 축 제외, 요약). pageNo는 pageCount 안으로 누른 쪽 번호다.
 * 행은 목록 문장(findUnifiedQueue)과 같은 UnifiedQueueRecord다(응답에 실리는 객체의 형이 바뀌면 직렬화 결과가 달라진다).
 */
public class UnifiedQueuePage {

    private long total;
    private long totalAll;
    private OffsetDateTime latestDetectedAt;
    private OffsetDateTime newestBeforePeriod;
    private long pageCount = 1;
    private long pageNo = 1;
    private long sumTotal;
    private long sumHigh;
    private long sumMedium;
    private long sumLow;
    private long sumReviewPending;
    private long sumAlerted;
    private long sumStatusOpen;
    private long sumStatusInvestigating;
    private long sumStatusClosed;
    private long sumStatusOther;
    private long sumOverdue;
    private List<UnifiedQueueRecord> rows = new ArrayList<>();

    public long getTotal() { return total; }
    public void setTotal(Long v) { this.total = v == null ? 0 : v; }
    public long getTotalAll() { return totalAll; }
    public void setTotalAll(Long v) { this.totalAll = v == null ? 0 : v; }
    public OffsetDateTime getLatestDetectedAt() { return latestDetectedAt; }
    public void setLatestDetectedAt(OffsetDateTime v) { this.latestDetectedAt = v; }
    public OffsetDateTime getNewestBeforePeriod() { return newestBeforePeriod; }
    public void setNewestBeforePeriod(OffsetDateTime v) { this.newestBeforePeriod = v; }
    public long getPageCount() { return pageCount; }
    public void setPageCount(Long v) { this.pageCount = v == null ? 1 : v; }
    public long getPageNo() { return pageNo; }
    public void setPageNo(Long v) { this.pageNo = v == null ? 1 : v; }
    public long getSumTotal() { return sumTotal; }
    public void setSumTotal(Long v) { this.sumTotal = v == null ? 0 : v; }
    public long getSumHigh() { return sumHigh; }
    public void setSumHigh(Long v) { this.sumHigh = v == null ? 0 : v; }
    public long getSumMedium() { return sumMedium; }
    public void setSumMedium(Long v) { this.sumMedium = v == null ? 0 : v; }
    public long getSumLow() { return sumLow; }
    public void setSumLow(Long v) { this.sumLow = v == null ? 0 : v; }
    public long getSumReviewPending() { return sumReviewPending; }
    public void setSumReviewPending(Long v) { this.sumReviewPending = v == null ? 0 : v; }
    public long getSumAlerted() { return sumAlerted; }
    public void setSumAlerted(Long v) { this.sumAlerted = v == null ? 0 : v; }
    public long getSumStatusOpen() { return sumStatusOpen; }
    public void setSumStatusOpen(Long v) { this.sumStatusOpen = v == null ? 0 : v; }
    public long getSumStatusInvestigating() { return sumStatusInvestigating; }
    public void setSumStatusInvestigating(Long v) { this.sumStatusInvestigating = v == null ? 0 : v; }
    public long getSumStatusClosed() { return sumStatusClosed; }
    public void setSumStatusClosed(Long v) { this.sumStatusClosed = v == null ? 0 : v; }
    public long getSumStatusOther() { return sumStatusOther; }
    public void setSumStatusOther(Long v) { this.sumStatusOther = v == null ? 0 : v; }
    public long getSumOverdue() { return sumOverdue; }
    public void setSumOverdue(Long v) { this.sumOverdue = v == null ? 0 : v; }
    public List<UnifiedQueueRecord> getRows() { return rows; }
    public void setRows(List<UnifiedQueueRecord> rows) { this.rows = rows == null ? new ArrayList<>() : rows; }
}
