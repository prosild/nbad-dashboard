package com.zeekad.dashboard.model.zeekad;

/** T45b 현황판 주요 알림 묶음: 머리 인시던트의 최신 큐 행에서 호스트·탐지 모델만(허용 캡처 전체 범위) */
public class ThreadHeadRow {
    private String incidentId;
    private String captureId;
    /** host_ip 원문 */
    private String hostIp;
    private String zeekadPickedBy;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public String getHostIp() { return hostIp; }
    public void setHostIp(String hostIp) { this.hostIp = hostIp; }
    public String getZeekadPickedBy() { return zeekadPickedBy; }
    public void setZeekadPickedBy(String zeekadPickedBy) { this.zeekadPickedBy = zeekadPickedBy; }
}
