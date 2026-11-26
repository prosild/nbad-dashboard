package com.zeekad.dashboard.dto;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;

import java.time.OffsetDateTime;

/**
 * 통합 인시던트 큐(T23) 응답 한 행. 큐 행 필드(역할 마스킹을 거친 IncidentQueueItem)를 그대로 펼치고
 * 서버가 계산한 detectedAt·sourceType·priority·ongoing과 T25 assignee·ackDueAt·ackOverdue, T45 threadHeadNo·threadMemberCount를 더한다. 캡처 표시 이름은 넣지 않는다(화면 사전 labels.ts 한 곳).
 * T52: assetCritical(중요 자산 여부)·priorityBase(기본 규칙 값)는 두 역할 모두에게, criticalAssetName은 분석가·관리자에게만 준다
 * (조회자는 늘 null. 이름은 주소를 가린 뜻을 무너뜨린다). 자산의 설명은 싣지 않는다.
 */
public class UnifiedQueueRow {

    private final IncidentQueueItem item;
    private final OffsetDateTime detectedAt;
    private final String sourceType;
    private final String priority;
    private final boolean ongoing;
    private final AssignmentDtos.Assignee assignee;
    private final OffsetDateTime ackDueAt;
    private final boolean ackOverdue;
    private final Long incidentNo;
    private final Long threadHeadNo;
    private final Long threadMemberCount;
    private final boolean assetCritical;
    private final String priorityBase;
    private final String criticalAssetName;

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue) {
        this(item, detectedAt, sourceType, priority, ongoing, assignee, ackDueAt, ackOverdue, null);
    }

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue, Long incidentNo) {
        this(item, detectedAt, sourceType, priority, ongoing, assignee, ackDueAt, ackOverdue, incidentNo, null, null);
    }

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue, Long incidentNo,
                           Long threadHeadNo, Long threadMemberCount) {
        // T52 앞 호출 호환: 중요 자산 없음(기본 값 = 우선순위)
        this(item, detectedAt, sourceType, priority, ongoing, assignee, ackDueAt, ackOverdue, incidentNo,
                threadHeadNo, threadMemberCount, false, priority, null);
    }

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue, Long incidentNo,
                           Long threadHeadNo, Long threadMemberCount,
                           boolean assetCritical, String priorityBase, String criticalAssetName) {
        this.assetCritical = assetCritical;
        this.priorityBase = priorityBase;
        this.criticalAssetName = criticalAssetName;
        this.item = item;
        this.detectedAt = detectedAt;
        this.sourceType = sourceType;
        this.priority = priority;
        this.ongoing = ongoing;
        this.assignee = assignee;
        this.ackDueAt = ackDueAt;
        this.ackOverdue = ackOverdue;
        this.incidentNo = incidentNo;
        this.threadHeadNo = threadHeadNo;
        this.threadMemberCount = threadMemberCount;
    }

    /** T52 이 행의 호스트가 중요 자산인지 */
    public boolean isAssetCritical() {
        return assetCritical;
    }

    /** T52 중요 자산을 보기 전의 기본 우선순위(종결이면 null). priority와 다르면 한 단계 올린 것이다 */
    public String getPriorityBase() {
        return priorityBase;
    }

    /** T52 중요 자산 이름(분석가·관리자만. 조회자와 중요 자산이 아닌 행은 null) */
    public String getCriticalAssetName() {
        return criticalAssetName;
    }

    /** T45 알림 묶음 표지: 가장 큰 묶음의 최초 알림 인시던트 번호(구성원 2건 이상인 보이는 묶음이 없으면 null) */
    public Long getThreadHeadNo() {
        return threadHeadNo;
    }

    /** T45 그 묶음의 구성원 수(허용 캡처 전체의 최신 큐 기준. 상세 Slack 탭 memberCount·큐 thread 조건 total과 같다) */
    public Long getThreadMemberCount() {
        return threadMemberCount;
    }

    /** T27 인시던트 번호(매기지 못했으면 null) */
    public Long getIncidentNo() {
        return incidentNo;
    }

    /** T25 담당자(없으면 null) */
    public AssignmentDtos.Assignee getAssignee() {
        return assignee;
    }

    /** T25 착수 목표 시각(실습망·신규·우선순위 있음이 아니면 null) */
    public OffsetDateTime getAckDueAt() {
        return ackDueAt;
    }

    public boolean isAckOverdue() {
        return ackOverdue;
    }

    @JsonUnwrapped
    public IncidentQueueItem getItem() {
        return item;
    }

    public OffsetDateTime getDetectedAt() {
        return detectedAt;
    }

    public String getSourceType() {
        return sourceType;
    }

    public String getPriority() {
        return priority;
    }

    public boolean isOngoing() {
        return ongoing;
    }
}
