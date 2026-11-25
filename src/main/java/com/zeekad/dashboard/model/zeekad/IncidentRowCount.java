package com.zeekad.dashboard.model.zeekad;

/** T45 큐 묶음 표지: incident_id별 최신 큐 행 수(허용 캡처 안) */
public class IncidentRowCount {
    private String incidentId;
    private long rowCount;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public long getRowCount() { return rowCount; }
    public void setRowCount(long rowCount) { this.rowCount = rowCount; }
}
