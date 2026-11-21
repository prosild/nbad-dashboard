package com.zeekad.dashboard.dto;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;

import java.time.OffsetDateTime;

/**
 * 통합 인시던트 큐(T23) 응답 한 행. 큐 행 필드(역할 마스킹을 거친 IncidentQueueItem)를 그대로 펼치고
 * 서버가 계산한 detectedAt·sourceType·priority·ongoing을 더한다. 캡처 표시 이름은 넣지 않는다(화면 사전 labels.ts 한 곳).
 */
public class UnifiedQueueRow {

    private final IncidentQueueItem item;
    private final OffsetDateTime detectedAt;
    private final String sourceType;
    private final String priority;
    private final boolean ongoing;

    public UnifiedQueueRow(IncidentQueueItem item, OffsetDateTime detectedAt, String sourceType, String priority, boolean ongoing) {
        this.item = item;
        this.detectedAt = detectedAt;
        this.sourceType = sourceType;
        this.priority = priority;
        this.ongoing = ongoing;
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
