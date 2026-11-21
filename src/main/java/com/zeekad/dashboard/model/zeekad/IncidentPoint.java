package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * 현황판(T24) 가벼운 투영: 통합 큐와 같은 조건의 행마다 캡처·탐지 시각·우선순위·경보 발송만.
 * 탐지 추이 구간·수집원별 수를 Java로 센다(큐 summary와 같은 집합).
 */
public class IncidentPoint {
    private String captureId;
    private OffsetDateTime detectedAt;
    /** high·medium·low, 종결이면 null */
    private String priority;
    private boolean alerted;

    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public OffsetDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(OffsetDateTime detectedAt) { this.detectedAt = detectedAt; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public boolean isAlerted() { return alerted; }
    public void setAlerted(boolean alerted) { this.alerted = alerted; }
}
