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
    /** T25 착수 지연 띠 축 */
    private boolean overdue;
    private boolean applyStripFilters = true;
    /** T25 담당 조건: me(목록 안) · none(목록 밖) · null. 목록은 담당자가 있는 incident_id(배열 바인드 하나) */
    private String assigneeMode;
    private String[] assigneeIncidentIds;
    /** T40 알림 묶음 조건: 머리 ∪ 답글 incident_id(배열 바인드 하나). null이면 조건 없음. 비는 경우는 없다(머리가 늘 든다) */
    private String[] threadIncidentIds;
    /** T45 호스트 조건: 고른 host_ip 원문(배열 바인드 하나). null이면 조건 없음. 빈 배열로는 부르지 않는다(서비스가 0건으로 끝낸다) */
    private String[] hostIps;
    /** T45 ATT&amp;CK 조건: 리포트 후보가 맞는 incident_id(배열 바인드 하나). null이면 조건 없음. 빈 배열로는 부르지 않는다 */
    private String[] attackIncidentIds;
    /** T25 착수 지연 식: 실습망 캡처(captureIds 안)와 우선순위별 경계(기준 시각 − 목표). 하나라도 없으면 지연 0 */
    private List<String> liveCaptureIds = List.of();
    private OffsetDateTime ackHighBefore;
    private OffsetDateTime ackMediumBefore;
    private OffsetDateTime ackLowBefore;
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
        c.overdue = overdue;
        c.applyStripFilters = applyStripFilters;
        c.assigneeMode = assigneeMode;
        c.assigneeIncidentIds = assigneeIncidentIds;
        c.threadIncidentIds = threadIncidentIds;
        c.hostIps = hostIps;
        c.attackIncidentIds = attackIncidentIds;
        c.liveCaptureIds = liveCaptureIds;
        c.ackHighBefore = ackHighBefore;
        c.ackMediumBefore = ackMediumBefore;
        c.ackLowBefore = ackLowBefore;
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
    public boolean isOverdue() { return overdue; }
    public void setOverdue(boolean overdue) { this.overdue = overdue; }
    public String getAssigneeMode() { return assigneeMode; }
    public void setAssigneeMode(String assigneeMode) { this.assigneeMode = assigneeMode; }
    public String[] getAssigneeIncidentIds() { return assigneeIncidentIds; }
    public void setAssigneeIncidentIds(String[] assigneeIncidentIds) { this.assigneeIncidentIds = assigneeIncidentIds; }
    public String[] getThreadIncidentIds() { return threadIncidentIds; }
    public void setThreadIncidentIds(String[] threadIncidentIds) { this.threadIncidentIds = threadIncidentIds; }
    public String[] getHostIps() { return hostIps; }
    public void setHostIps(String[] hostIps) { this.hostIps = hostIps; }
    public String[] getAttackIncidentIds() { return attackIncidentIds; }
    public void setAttackIncidentIds(String[] attackIncidentIds) { this.attackIncidentIds = attackIncidentIds; }
    public boolean isHasAssigneeIds() { return assigneeIncidentIds != null && assigneeIncidentIds.length > 0; }
    public List<String> getLiveCaptureIds() { return liveCaptureIds; }
    public void setLiveCaptureIds(List<String> liveCaptureIds) { this.liveCaptureIds = liveCaptureIds; }
    public OffsetDateTime getAckHighBefore() { return ackHighBefore; }
    public void setAckHighBefore(OffsetDateTime v) { this.ackHighBefore = v; }
    public OffsetDateTime getAckMediumBefore() { return ackMediumBefore; }
    public void setAckMediumBefore(OffsetDateTime v) { this.ackMediumBefore = v; }
    public OffsetDateTime getAckLowBefore() { return ackLowBefore; }
    public void setAckLowBefore(OffsetDateTime v) { this.ackLowBefore = v; }
    /** 착수 지연 식을 쓸 수 있는지(실습망 캡처와 경계가 모두 있음) */
    public boolean isAckReady() {
        return liveCaptureIds != null && !liveCaptureIds.isEmpty()
                && ackHighBefore != null && ackMediumBefore != null && ackLowBefore != null;
    }
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
