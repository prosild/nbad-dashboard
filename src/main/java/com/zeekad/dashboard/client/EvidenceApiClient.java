package com.zeekad.dashboard.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * zeek_AD 근거 조회 FastAPI(evidence.v1) 클라이언트.
 * 연결 실패·타임아웃·4xx/5xx 시 예외를 전파하지 않고 안전한 폴백 객체를 반환한다.
 */
@Component
public class EvidenceApiClient {

    private static final Logger log = LoggerFactory.getLogger(EvidenceApiClient.class);

    /** evidence.v1 최상위 키 중 정형 필드로 옮기는 키. */
    public static final Set<String> STRUCTURED_EVIDENCE_KEYS = Set.of(
            "connection_count", "network", "zeek_conn_state", "peers", "destination_ports",
            "protocol_logs", "representative_connections", "limits"
    );
    /** 정형 필드로 옮기지 않고 additionalFields로 남기는 키(version, 그리고 DB 뷰 값과 중복되는 host·event·zeekad_role). */
    public static final Set<String> ADDITIONAL_EVIDENCE_KEYS = Set.of(
            "version", "host", "event", "zeekad_role"
    );
    private static final int MAX_REPRESENTATIVE_CONNECTIONS = 10;

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<Map<String, Object>>> LIST_OF_MAPS_TYPE = new TypeReference<>() {};

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    public EvidenceApiClient(@Qualifier("evidenceRestClient") RestClient restClient,
                             ObjectMapper objectMapper) {
        this.restClient = restClient;
        this.objectMapper = objectMapper;
    }

    public List<Map<String, Object>> fetchJobs() {
        try {
            String body = restClient.get()
                    .uri("/api/v1/jobs")
                    .retrieve()
                    .body(String.class);
            if (body == null || body.isBlank()) {
                return Collections.emptyList();
            }
            JsonNode root = objectMapper.readTree(body);
            if (root.isArray()) {
                return toListOfMaps(root);
            }
            if (root.has("jobs") && root.get("jobs").isArray()) {
                return toListOfMaps(root.get("jobs"));
            }
            return Collections.emptyList();
        } catch (RestClientException | java.io.IOException e) {
            log.warn("근거 API /api/v1/jobs 호출 실패(폴백 반환): {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    public List<Map<String, Object>> fetchCaptureQueue(String captureId, int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 100));
        try {
            String body = restClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/v1/captures/{captureId}/queue")
                            .queryParam("limit", safeLimit)
                            .build(captureId))
                    .retrieve()
                    .body(String.class);
            if (body == null || body.isBlank()) {
                return Collections.emptyList();
            }
            JsonNode root = objectMapper.readTree(body);
            if (root.isArray()) {
                return toListOfMaps(root);
            }
            if (root.has("items") && root.get("items").isArray()) {
                return toListOfMaps(root.get("items"));
            }
            if (root.has("queue") && root.get("queue").isArray()) {
                return toListOfMaps(root.get("queue"));
            }
            return Collections.emptyList();
        } catch (RestClientException | java.io.IOException e) {
            log.warn("근거 API /api/v1/captures/{}/queue 호출 실패(폴백 반환): {}", captureId, e.getMessage());
            return Collections.emptyList();
        }
    }

    public EvidenceApiResponse fetchIncidentEvidence(long jobId, int rank) {
        try {
            String body = restClient.get()
                    .uri("/api/v1/jobs/{jobId}/incidents/{rank}", jobId, rank)
                    .retrieve()
                    .body(String.class);
            if (body == null || body.isBlank()) {
                return EvidenceApiResponse.unavailable();
            }
            JsonNode root = objectMapper.readTree(body);
            if (root == null || !root.isObject()) {
                return EvidenceApiResponse.unavailable();
            }
            return parseIncidentResponse(root, jobId, rank);
        } catch (RestClientException | java.io.IOException e) {
            log.warn("근거 API /api/v1/jobs/{}/incidents/{} 호출 실패(폴백 반환): {}", jobId, rank, e.getMessage());
            return EvidenceApiResponse.unavailable();
        }
    }

    private EvidenceApiResponse parseIncidentResponse(JsonNode root, long jobId, int rank) {
        EvidenceApiResponse response = new EvidenceApiResponse();
        response.setAvailable(true);
        response.setStatusMessage("정상");
        response.setJobId(jobId);
        response.setRank(rank);

        // 근거 행이 없으면 API가 "evidence": null을 준다. 응답 최상위(detection·관측 이름 등)로 대체하지 않는다.
        JsonNode evidenceNode = root.get("evidence");
        if (evidenceNode == null || !evidenceNode.isObject()) {
            response.setEvidence(EvidenceData.unavailable(EvidenceData.NO_EVIDENCE_MESSAGE));
            return response;
        }
        response.setEvidence(parseEvidenceNode(evidenceNode));
        return response;
    }

    private EvidenceData parseEvidenceNode(JsonNode node) {
        EvidenceData data = new EvidenceData();
        data.setAvailable(true);
        data.setStatusMessage("정상");

        data.setConnectionCount(extractLong(node.get("connection_count")));

        JsonNode network = objectOrNull(node.get("network"));
        if (network != null) {
            JsonNode bytes = objectOrNull(network.get("bytes"));
            if (bytes != null) {
                data.setBytesSent(extractLong(bytes.get("sent")));
                data.setBytesReceived(extractLong(bytes.get("received")));
            }
            data.setTransportCounts(extractMap(network.get("transport")));
            data.setServiceProtocolCounts(extractMap(network.get("protocol")));
            data.setPayloadBytesInflated(extractLong(network.get("zeekad_payload_bytes_inflated")));
        }

        data.setConnStateCounts(extractMap(node.get("zeek_conn_state")));

        JsonNode peers = objectOrNull(node.get("peers"));
        if (peers != null) {
            data.setTopPeers(extractListOfMaps(peers.get("top")));
            data.setUniquePeers(extractLong(peers.get("unique")));
        }
        JsonNode ports = objectOrNull(node.get("destination_ports"));
        if (ports != null) {
            data.setTopPorts(extractListOfMaps(ports.get("top")));
            data.setUniquePorts(extractLong(ports.get("unique")));
        }

        data.setProtocolLogs(extractMap(node.get("protocol_logs")));

        List<Map<String, Object>> reps = extractListOfMaps(node.get("representative_connections"));
        if (reps.size() > MAX_REPRESENTATIVE_CONNECTIONS) {
            reps = reps.subList(0, MAX_REPRESENTATIVE_CONNECTIONS);
        }
        data.setRepresentativeConnections(reps);
        data.setLimits(extractStringList(node.get("limits")));

        Map<String, Object> additional = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            if (!STRUCTURED_EVIDENCE_KEYS.contains(entry.getKey())) {
                additional.put(entry.getKey(), objectMapper.convertValue(entry.getValue(), Object.class));
            }
        }
        data.setAdditionalFields(Collections.unmodifiableMap(additional));
        return data;
    }

    private JsonNode objectOrNull(JsonNode node) {
        return node != null && node.isObject() ? node : null;
    }

    private Long extractLong(JsonNode target) {
        if (target == null || target.isNull()) {
            return null;
        }
        if (target.isNumber()) {
            return target.asLong();
        }
        if (target.isTextual()) {
            try {
                return Long.parseLong(target.asText().trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Map<String, Object> extractMap(JsonNode target) {
        if (target != null && target.isObject()) {
            return toMap(target);
        }
        return Collections.emptyMap();
    }

    private List<Map<String, Object>> extractListOfMaps(JsonNode target) {
        if (target != null && target.isArray()) {
            return toListOfMaps(target);
        }
        return Collections.emptyList();
    }

    private List<String> extractStringList(JsonNode target) {
        if (target == null || target.isNull()) {
            return Collections.emptyList();
        }
        if (target.isArray()) {
            List<String> list = new ArrayList<>();
            for (JsonNode item : target) {
                if (item != null && !item.isNull()) {
                    list.add(item.asText());
                }
            }
            return Collections.unmodifiableList(list);
        }
        if (target.isTextual()) {
            String text = target.asText().trim();
            return text.isEmpty() ? Collections.emptyList() : List.of(text);
        }
        return Collections.emptyList();
    }

    private Map<String, Object> toMap(JsonNode node) {
        return Collections.unmodifiableMap(objectMapper.convertValue(node, MAP_TYPE));
    }

    private List<Map<String, Object>> toListOfMaps(JsonNode arrayNode) {
        List<Map<String, Object>> converted = objectMapper.convertValue(arrayNode, LIST_OF_MAPS_TYPE);
        return converted == null ? Collections.emptyList() : Collections.unmodifiableList(converted);
    }
}
