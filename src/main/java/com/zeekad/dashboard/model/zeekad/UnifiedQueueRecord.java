package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * 통합 인시던트 큐(T23) 한 행: 최신 작업 큐 행(latest_incident_queue) + 서버가 계산한 탐지 시각·우선순위.
 * 탐지 시각 = 그 incident_id가 처음 나온 성공 작업(finished_at 있음)의 완료 시각 최소값.
 */
public class UnifiedQueueRecord extends IncidentQueueItem {

    private OffsetDateTime detectedAt;
    /** high | medium | low, 종결이면 null */
    private String priority;

    public OffsetDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(OffsetDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public String getPriority() {
        return priority;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }
}
