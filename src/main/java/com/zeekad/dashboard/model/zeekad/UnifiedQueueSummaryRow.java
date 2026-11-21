package com.zeekad.dashboard.model.zeekad;

/**
 * 통합 큐 요약 집계(T23). 띠 축(우선순위·에스컬레이션 대기·경보 발송)을 뺀 거르기를 적용한 집합에서 센다.
 */
public class UnifiedQueueSummaryRow {
    private long total;
    private long high;
    private long medium;
    private long low;
    private long reviewPending;
    private long alerted;
    private long statusOpen;
    private long statusInvestigating;
    private long statusClosed;
    private long statusOther;

    public long getTotal() { return total; }
    public void setTotal(Long total) { this.total = total == null ? 0 : total; }
    public long getHigh() { return high; }
    public void setHigh(Long high) { this.high = high == null ? 0 : high; }
    public long getMedium() { return medium; }
    public void setMedium(Long medium) { this.medium = medium == null ? 0 : medium; }
    public long getLow() { return low; }
    public void setLow(Long low) { this.low = low == null ? 0 : low; }
    public long getReviewPending() { return reviewPending; }
    public void setReviewPending(Long reviewPending) { this.reviewPending = reviewPending == null ? 0 : reviewPending; }
    public long getAlerted() { return alerted; }
    public void setAlerted(Long alerted) { this.alerted = alerted == null ? 0 : alerted; }
    public long getStatusOpen() { return statusOpen; }
    public void setStatusOpen(Long v) { this.statusOpen = v == null ? 0 : v; }
    public long getStatusInvestigating() { return statusInvestigating; }
    public void setStatusInvestigating(Long v) { this.statusInvestigating = v == null ? 0 : v; }
    public long getStatusClosed() { return statusClosed; }
    public void setStatusClosed(Long v) { this.statusClosed = v == null ? 0 : v; }
    public long getStatusOther() { return statusOther; }
    public void setStatusOther(Long v) { this.statusOther = v == null ? 0 : v; }
}
