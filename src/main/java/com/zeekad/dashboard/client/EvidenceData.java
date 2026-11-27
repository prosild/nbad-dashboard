package com.zeekad.dashboard.client;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * FastAPI evidence.v1 증적 요약 DTO(zeek_AD zeek_ad/evidence.py summarize_incident 스키마).
 * 숫자 필드는 키가 없거나 null이면 null로 두고 0으로 바꾸지 않는다.
 */
public class EvidenceData {

    public static final String FALLBACK_MESSAGE = "상세 증거를 불러오지 못했습니다. 기본 정보만 표시합니다.";
    public static final String NO_EVIDENCE_MESSAGE = "이 인시던트에는 증거 요약이 없습니다. 증거 조회는 정상입니다.";

    private boolean available;
    private String statusMessage;
    private Long connectionCount;
    /** network.bytes.sent: 자산(사건 대상 호스트) 기준 송신 IP 바이트 */
    private Long bytesSent;
    /** network.bytes.received: 자산 기준 수신 IP 바이트 */
    private Long bytesReceived;
    private Long payloadBytesInflated;
    private Map<String, Object> transportCounts = Collections.emptyMap();
    private Map<String, Object> serviceProtocolCounts = Collections.emptyMap();
    private Map<String, Object> connStateCounts = Collections.emptyMap();
    private List<Map<String, Object>> topPeers = Collections.emptyList();
    private Long uniquePeers;
    private List<Map<String, Object>> topPorts = Collections.emptyList();
    private Long uniquePorts;
    private Map<String, Object> protocolLogs = Collections.emptyMap();
    private List<Map<String, Object>> representativeConnections = Collections.emptyList();
    private List<String> limits = Collections.emptyList();
    private Map<String, Object> additionalFields = Collections.emptyMap();

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

    public Long getBytesSent() {
        return bytesSent;
    }

    public void setBytesSent(Long bytesSent) {
        this.bytesSent = bytesSent;
    }

    public Long getBytesReceived() {
        return bytesReceived;
    }

    public void setBytesReceived(Long bytesReceived) {
        this.bytesReceived = bytesReceived;
    }

    public Long getPayloadBytesInflated() {
        return payloadBytesInflated;
    }

    public void setPayloadBytesInflated(Long payloadBytesInflated) {
        this.payloadBytesInflated = payloadBytesInflated;
    }

    public Map<String, Object> getTransportCounts() {
        return transportCounts;
    }

    public void setTransportCounts(Map<String, Object> transportCounts) {
        this.transportCounts = transportCounts == null ? Collections.emptyMap() : transportCounts;
    }

    public Map<String, Object> getServiceProtocolCounts() {
        return serviceProtocolCounts;
    }

    public void setServiceProtocolCounts(Map<String, Object> serviceProtocolCounts) {
        this.serviceProtocolCounts = serviceProtocolCounts == null ? Collections.emptyMap() : serviceProtocolCounts;
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

    public Long getUniquePeers() {
        return uniquePeers;
    }

    public void setUniquePeers(Long uniquePeers) {
        this.uniquePeers = uniquePeers;
    }

    public List<Map<String, Object>> getTopPorts() {
        return topPorts;
    }

    public void setTopPorts(List<Map<String, Object>> topPorts) {
        this.topPorts = topPorts == null ? Collections.emptyList() : topPorts;
    }

    public Long getUniquePorts() {
        return uniquePorts;
    }

    public void setUniquePorts(Long uniquePorts) {
        this.uniquePorts = uniquePorts;
    }

    /** protocol_logs: 프로토콜 이름 → 하위 수치 객체(값은 숫자 또는 배열). 키가 없던 프로토콜은 담지 않는다. */
    public Map<String, Object> getProtocolLogs() {
        return protocolLogs;
    }

    public void setProtocolLogs(Map<String, Object> protocolLogs) {
        this.protocolLogs = protocolLogs == null ? Collections.emptyMap() : protocolLogs;
    }

    public List<Map<String, Object>> getRepresentativeConnections() {
        return representativeConnections;
    }

    public void setRepresentativeConnections(List<Map<String, Object>> representativeConnections) {
        this.representativeConnections = representativeConnections == null
                ? Collections.emptyList() : representativeConnections;
    }

    public List<String> getLimits() {
        return limits;
    }

    public void setLimits(List<String> limits) {
        this.limits = limits == null ? Collections.emptyList() : limits;
    }

    /** 정형 필드로 옮기지 않은 evidence 최상위 키(version·host·event·zeekad_role 등). */
    public Map<String, Object> getAdditionalFields() {
        return additionalFields;
    }

    public void setAdditionalFields(Map<String, Object> additionalFields) {
        this.additionalFields = additionalFields == null ? Collections.emptyMap() : additionalFields;
    }

    /** 모든 필드를 옮긴 얕은 사본. 마스킹은 호출자가 사본의 해당 필드를 바꿔 끼운다. */
    public EvidenceData copy() {
        EvidenceData copy = new EvidenceData();
        copy.setAvailable(this.available);
        copy.setStatusMessage(this.statusMessage);
        copy.setConnectionCount(this.connectionCount);
        copy.setBytesSent(this.bytesSent);
        copy.setBytesReceived(this.bytesReceived);
        copy.setPayloadBytesInflated(this.payloadBytesInflated);
        copy.setTransportCounts(this.transportCounts);
        copy.setServiceProtocolCounts(this.serviceProtocolCounts);
        copy.setConnStateCounts(this.connStateCounts);
        copy.setTopPeers(this.topPeers);
        copy.setUniquePeers(this.uniquePeers);
        copy.setTopPorts(this.topPorts);
        copy.setUniquePorts(this.uniquePorts);
        copy.setProtocolLogs(this.protocolLogs);
        copy.setRepresentativeConnections(this.representativeConnections);
        copy.setLimits(this.limits);
        copy.setAdditionalFields(this.additionalFields);
        return copy;
    }
}
