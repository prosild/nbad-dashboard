package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 통합 인시던트 큐(T23) 조회 조건. MyBatis에는 #{}로만 바인딩하고, 정렬 키·방향은 매퍼의 &lt;choose&gt; 허용 목록으로 고른다.
 * captureIds는 서버가 계산한 허용 캡처(∩ 수집원 ∩ 고른 캡처)이며 비어 있으면 매퍼를 부르지 않는다.
 */
public class UnifiedQueueCriteria {

    private List<String> captureIds = List.of();
    /** 한 인시던트만(상세 메타데이터·neighbors current용). null이면 조건 없음 */
    private String incidentId;
    /** 기간 시작(불포함). null이면 시각 하한 없음 */
    private OffsetDateTime detectedAfter;
    /** 기간 끝(포함). null이면 상한 없음 */
    private OffsetDateTime detectedUntil;
    private String pickedBy;
    private String role;
    private String status;
    private Boolean hasReport;
    private Boolean wouldSend;
    /** 띠 축 거르기(우선순위·에스컬레이션 대기·경보 발송). summary 집계 때는 적용하지 않는다. */
    private String priority;
    private boolean reviewPending;
    private boolean alerted;
    private boolean applyStripFilters = true;
    private String sortKey = "priority";
    private boolean sortAsc = true;
    private Integer limit;
    private Integer offset;

    public UnifiedQueueCriteria copy() {
        UnifiedQueueCriteria c = new UnifiedQueueCriteria();
        c.captureIds = captureIds;
        c.incidentId = incidentId;
        c.detectedAfter = detectedAfter;
        c.detectedUntil = detectedUntil;
        c.pickedBy = pickedBy;
        c.role = role;
        c.status = status;
        c.hasReport = hasReport;
        c.wouldSend = wouldSend;
        c.priority = priority;
        c.reviewPending = reviewPending;
        c.alerted = alerted;
        c.applyStripFilters = applyStripFilters;
        c.sortKey = sortKey;
        c.sortAsc = sortAsc;
        c.limit = limit;
        c.offset = offset;
        return c;
    }

    public List<String> getCaptureIds() { return captureIds; }
    public void setCaptureIds(List<String> captureIds) { this.captureIds = captureIds; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public OffsetDateTime getDetectedAfter() { return detectedAfter; }
    public void setDetectedAfter(OffsetDateTime detectedAfter) { this.detectedAfter = detectedAfter; }
    public OffsetDateTime getDetectedUntil() { return detectedUntil; }
    public void setDetectedUntil(OffsetDateTime detectedUntil) { this.detectedUntil = detectedUntil; }
    public String getPickedBy() { return pickedBy; }
    public void setPickedBy(String pickedBy) { this.pickedBy = pickedBy; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Boolean getHasReport() { return hasReport; }
    public void setHasReport(Boolean hasReport) { this.hasReport = hasReport; }
    public Boolean getWouldSend() { return wouldSend; }
    public void setWouldSend(Boolean wouldSend) { this.wouldSend = wouldSend; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public boolean isReviewPending() { return reviewPending; }
    public void setReviewPending(boolean reviewPending) { this.reviewPending = reviewPending; }
    public boolean isAlerted() { return alerted; }
    public void setAlerted(boolean alerted) { this.alerted = alerted; }
    public boolean isApplyStripFilters() { return applyStripFilters; }
    public void setApplyStripFilters(boolean applyStripFilters) { this.applyStripFilters = applyStripFilters; }
    public String getSortKey() { return sortKey; }
    public void setSortKey(String sortKey) { this.sortKey = sortKey; }
    public boolean isSortAsc() { return sortAsc; }
    public void setSortAsc(boolean sortAsc) { this.sortAsc = sortAsc; }
    public Integer getLimit() { return limit; }
    public void setLimit(Integer limit) { this.limit = limit; }
    public Integer getOffset() { return offset; }
    public void setOffset(Integer offset) { this.offset = offset; }
}
