package com.zeekad.dashboard.client;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FastAPI evidence.v1 근거 요약 DTO.
 */
public class EvidenceData {

    public static final String FALLBACK_MESSAGE = "근거 API 연결 불가(DB 뷰 정보만 표시)";

    private boolean available;
    private String statusMessage;
    private Long connectionCount;
    private Long origBytes;
    private Long respBytes;
    private Map<String, Object> transportCounts = Collections.emptyMap();
    private Map<String, Object> connStateCounts = Collections.emptyMap();
    private List<Map<String, Object>> topPeers = Collections.emptyList();
    private List<Map<String, Object>> topPorts = Collections.emptyList();
    private Map<String, Object> protocolCounts = Collections.emptyMap();
    private List<Map<String, Object>> representativeConnections = Collections.emptyList();
    private List<String> limitations = Collections.emptyList();
    private Map<String, Object> rawEvidence = Collections.emptyMap();

    public static EvidenceData unavailable() {
        return unavailable(FALLBACK_MESSAGE);
    }

    public static EvidenceData unavailable(String message) {
        EvidenceData data = new EvidenceData();
        data.setAvailable(false);
        data.setStatusMessage(message == null || message.isBlank() ? FALLBACK_MESSAGE : message);
        return data;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public Long getConnectionCount() {
        return connectionCount;
    }

    public void setConnectionCount(Long connectionCount) {
        this.connectionCount = connectionCount;
    }

    public Long getOrigBytes() {
        return origBytes;
    }

    public void setOrigBytes(Long origBytes) {
        this.origBytes = origBytes;
    }

    public Long getRespBytes() {
        return respBytes;
    }

    public void setRespBytes(Long respBytes) {
        this.respBytes = respBytes;
    }

    public Map<String, Object> getTransportCounts() {
        return transportCounts;
    }

    public void setTransportCounts(Map<String, Object> transportCounts) {
        this.transportCounts = transportCounts == null ? Collections.emptyMap() : transportCounts;
    }

    public Map<String, Object> getConnStateCounts() {
        return connStateCounts;
    }

    public void setConnStateCounts(Map<String, Object> connStateCounts) {
        this.connStateCounts = connStateCounts == null ? Collections.emptyMap() : connStateCounts;
    }

    public List<Map<String, Object>> getTopPeers() {
        return topPeers;
    }

    public void setTopPeers(List<Map<String, Object>> topPeers) {
        this.topPeers = topPeers == null ? Collections.emptyList() : topPeers;
    }

    public List<Map<String, Object>> getTopPorts() {
        return topPorts;
    }

    public void setTopPorts(List<Map<String, Object>> topPorts) {
        this.topPorts = topPorts == null ? Collections.emptyList() : topPorts;
    }

    public Map<String, Object> getProtocolCounts() {
        return protocolCounts;
    }

    public void setProtocolCounts(Map<String, Object> protocolCounts) {
        this.protocolCounts = protocolCounts == null ? Collections.emptyMap() : protocolCounts;
    }

    public List<Map<String, Object>> getRepresentativeConnections() {
        return representativeConnections;
    }

    public void setRepresentativeConnections(List<Map<String, Object>> representativeConnections) {
        this.representativeConnections = representativeConnections == null
                ? Collections.emptyList() : representativeConnections;
    }

    public List<String> getLimitations() {
        return limitations;
    }

    public void setLimitations(List<String> limitations) {
        this.limitations = limitations == null ? Collections.emptyList() : limitations;
    }

    public Map<String, Object> getRawEvidence() {
        return rawEvidence;
    }

    public void setRawEvidence(Map<String, Object> rawEvidence) {
        this.rawEvidence = rawEvidence == null ? Collections.emptyMap() : rawEvidence;
    }

    public EvidenceData copyWithMaskedNetworkFields(List<Map<String, Object>> maskedPeers,
                                                    List<Map<String, Object>> maskedConnections,
                                                    Map<String, Object> maskedRaw) {
        EvidenceData copy = new EvidenceData();
        copy.setAvailable(this.available);
        copy.setStatusMessage(this.statusMessage);
        copy.setConnectionCount(this.connectionCount);
        copy.setOrigBytes(this.origBytes);
        copy.setRespBytes(this.respBytes);
        copy.setTransportCounts(new LinkedHashMap<>(this.transportCounts));
        copy.setConnStateCounts(new LinkedHashMap<>(this.connStateCounts));
        copy.setTopPeers(maskedPeers);
        copy.setTopPorts(this.topPorts);
        copy.setProtocolCounts(new LinkedHashMap<>(this.protocolCounts));
        copy.setRepresentativeConnections(maskedConnections);
        copy.setLimitations(this.limitations);
        copy.setRawEvidence(maskedRaw);
        return copy;
    }
}
