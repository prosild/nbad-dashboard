package com.zeekad.dashboard.model.zeekad;

/** T45 큐 묶음 표지: Slack 기록 한 행의 인시던트와 스레드 부모(없으면 null) */
public class SlackThreadLink {
    private String incidentId;
    private String threadParent;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getThreadParent() { return threadParent; }
    public void setThreadParent(String threadParent) { this.threadParent = threadParent; }
}
