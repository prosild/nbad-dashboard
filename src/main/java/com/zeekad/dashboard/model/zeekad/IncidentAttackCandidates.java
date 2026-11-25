package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

/** T45 큐 attack 조건: 최신 큐 행이 가리키는 리포트의 ATT&amp;CK 후보(JSON 그대로, Java에서 읽는다) */
public class IncidentAttackCandidates {
    private String incidentId;
    private JsonNode candidates;

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public JsonNode getCandidates() { return candidates; }
    public void setCandidates(JsonNode candidates) { this.candidates = candidates; }
}
