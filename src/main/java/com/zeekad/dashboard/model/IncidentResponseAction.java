package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * 대응 조치 기록 한 행(T56, 추가만). 분석가가 인시던트에 어떤 조치를 했다고 적은 것이다(콘솔이 조치를 실행하지 않는다).
 */
public class IncidentResponseAction {

    private Long id;
    private String incidentId;
    private String captureId;
    private Long jobId;
    /** block_ip · isolate_host · lock_account · handover · monitor · none · other */
    private String actionType;
    private String note;
    private String actorUsername;
    /** 조치한 시각이 아니라 기록한 시각 */
    private OffsetDateTime recordedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String captureId) { this.captureId = captureId; }
    public Long getJobId() { return jobId; }
    public void setJobId(Long jobId) { this.jobId = jobId; }
    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }
    public OffsetDateTime getRecordedAt() { return recordedAt; }
    public void setRecordedAt(OffsetDateTime recordedAt) { this.recordedAt = recordedAt; }
}
