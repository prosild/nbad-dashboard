package com.zeekad.dashboard.model.zeekad;

import java.time.OffsetDateTime;

/**
 * 현황판(T24) 가벼운 투영: 통합 큐와 같은 조건의 행마다 캡처·탐지 시각·우선순위·경보 발송만.
 * 탐지 추이 구간·수집원별 수를 Java로 센다(큐 summary와 같은 집합).
 * T45b: 같은 행을 한 번 더 읽지 않게 인시던트 ID·호스트·통신 방향을 같이 읽는다(ATT&amp;CK 분포·위험 호스트·알림 묶음).
 * 이 값들은 응답에 그대로 넣지 않는다(호스트는 역할에 따라 가린 뒤 묶는다).
 */
public class IncidentPoint {
    private String captureId;
    private OffsetDateTime detectedAt;
    /** high·medium·low, 종결이면 null */
    private String priority;
    private boolean alerted;
    private String incidentId;
    /** host_ip 원문 */
    private String hostIp;
    /** zeekad_role 원문 */
    private String zeekadRole;

    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public OffsetDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(OffsetDateTime detectedAt) { this.detectedAt = detectedAt; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public boolean isAlerted() { return alerted; }
    public void setAlerted(boolean alerted) { this.alerted = alerted; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getHostIp() { return hostIp; }
    public void setHostIp(String hostIp) { this.hostIp = hostIp; }
    public String getZeekadRole() { return zeekadRole; }
    public void setZeekadRole(String zeekadRole) { this.zeekadRole = zeekadRole; }
}
