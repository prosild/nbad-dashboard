package com.zeekad.dashboard.dto;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;

import java.time.OffsetDateTime;

/**
 * 통합 인시던트 큐(T23) 응답 한 행. 큐 행 필드(역할 마스킹을 거친 IncidentQueueItem)를 그대로 펼치고
 * 서버가 계산한 detectedAt·sourceType·priority·ongoing과 T25 assignee·ackDueAt·ackOverdue를 더한다. 캡처 표시 이름은 넣지 않는다(화면 사전 labels.ts 한 곳).
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

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue) {
        this(item, detectedAt, sourceType, priority, ongoing, assignee, ackDueAt, ackOverdue, null);
    }

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing,
                           AssignmentDtos.Assignee assignee, OffsetDateTime ackDueAt, boolean ackOverdue, Long incidentNo) {
        this.item = item;
        this.detectedAt = detectedAt;
        this.sourceType = sourceType;
        this.priority = priority;
        this.ongoing = ongoing;
        this.assignee = assignee;
        this.ackDueAt = ackDueAt;
        this.ackOverdue = ackOverdue;
        this.incidentNo = incidentNo;
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
