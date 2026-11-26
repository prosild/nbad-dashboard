package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.time.OffsetDateTime;

/**
 * 통합 인시던트 큐(T23) 한 행: 최신 작업 큐 행(latest_incident_queue) + 서버가 계산한 탐지 시각·우선순위.
 * 탐지 시각 = 그 incident_id가 처음 나온 성공 작업(finished_at 있음)의 완료 시각 최소값.
 * T52: priorityBase(기본 규칙 값)와 assetCritical(중요 자산 여부)도 SQL에서 읽는다. 응답에는 UnifiedQueueRow의 필드로 나가므로
 * 이 객체를 펼친 분석가 응답에 같은 키가 두 번 나오지 않게 여기서는 직렬화하지 않는다.
 * 서버가 붙이는 값(중요 자산 이름)은 이 객체에 두지 않는다(옛 문장과 새 문장의 결과를 속성 전부로 견주는 T51 대조가 깨진다).
 */
public class UnifiedQueueRecord extends IncidentQueueItem {

    private OffsetDateTime detectedAt;
    /** high | medium | low, 종결이면 null(중요 자산이면 기본 값에서 한 단계 올린 값) */
    private String priority;
    /** T52 기본 규칙의 우선순위(중요 자산을 보기 전). 종결이면 null */
    private String priorityBase;
    /** T52 이 행의 호스트가 중요 자산인지(host_ip가 NULL이면 false) */
    private boolean assetCritical;

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

    @JsonIgnore
    public String getPriorityBase() {
        return priorityBase;
    }

    public void setPriorityBase(String priorityBase) {
        this.priorityBase = priorityBase;
    }

    @JsonIgnore
    public boolean isAssetCritical() {
        return assetCritical;
    }

    public void setAssetCritical(boolean assetCritical) {
        this.assetCritical = assetCritical;
    }
}
