package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/** T29 캡처별 최신 큐 인시던트의 가장 늦은 탐지 시각(통합 큐 탐지 시각과 같은 정의) */
public class CaptureLastDetected {
    private String captureId;
    private OffsetDateTime lastDetectedAt;

    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public OffsetDateTime getLastDetectedAt() { return lastDetectedAt; }
    public void setLastDetectedAt(OffsetDateTime lastDetectedAt) { this.lastDetectedAt = lastDetectedAt; }
}
