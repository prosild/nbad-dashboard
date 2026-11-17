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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * zeek_AD 근거 조회 FastAPI(evidence.v1) 클라이언트.
 * 연결 실패·타임아웃·4xx/5xx 시 예외를 전파하지 않고 안전한 폴백 객체를 반환한다.
 */
@Component
public class EvidenceApiClient {

    private static final Logger log = LoggerFactory.getLogger(EvidenceApiClient.class);

    private static final List<String> PROTOCOL_LOG_KEYS = List.of(
            "dns", "http", "tls", "ssh", "ftp", "smb", "kerberos", "dce_rpc", "ntlm"
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
        response.setRawPayload(toMap(root));

        if (root.has("incident") && root.get("incident").isObject()) {
            response.setIncident(toMap(root.get("incident")));
        }
        if (root.has("model_scores") && root.get("model_scores").isArray()) {
            response.setModelScores(toListOfMaps(root.get("model_scores")));
        }
        if (root.has("asset_names") && root.get("asset_names").isArray()) {
            response.setAssetNames(toListOfMaps(root.get("asset_names")));
        }

        JsonNode evidenceNode = root.has("evidence") && root.get("evidence").isObject()
                ? root.get("evidence")
                : root;
        response.setEvidence(parseEvidenceNode(evidenceNode));
        return response;
    }

    private EvidenceData parseEvidenceNode(JsonNode node) {
        if (node == null || !node.isObject()) {
            return EvidenceData.unavailable();
        }
        EvidenceData data = new EvidenceData();
        data.setAvailable(true);
        data.setStatusMessage("정상");
        data.setRawEvidence(toMap(node));

        data.setConnectionCount(extractLong(node, "connection_count", "connections"));
        data.setOrigBytes(extractLong(node, "orig_bytes", "bytes_sent"));
        data.setRespBytes(extractLong(node, "resp_bytes", "bytes_received"));

        data.setTransportCounts(extractMap(node, "transport_counts", "protocols"));
        data.setConnStateCounts(extractMap(node, "conn_state_counts", "conn_states"));

        data.setTopPeers(extractTopList(node, "peers", "top_peers"));
        data.setTopPorts(extractTopList(node, "ports", "top_ports"));
        data.setProtocolCounts(extractProtocolCounts(node));

        List<Map<String, Object>> reps = extractListOfMaps(node, "representative_connections");
        if (reps.size() > MAX_REPRESENTATIVE_CONNECTIONS) {
            reps = reps.subList(0, MAX_REPRESENTATIVE_CONNECTIONS);
        }
        data.setRepresentativeConnections(reps);
        data.setLimitations(extractStringList(node, "limitations"));
        return data;
    }

    private Long extractLong(JsonNode node, String primaryKey, String fallbackKey) {
        JsonNode target = node.hasNonNull(primaryKey) ? node.get(primaryKey) : node.get(fallbackKey);
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

    private Map<String, Object> extractMap(JsonNode node, String primaryKey, String fallbackKey) {
        JsonNode target = node.has(primaryKey) && node.get(primaryKey).isObject()
                ? node.get(primaryKey)
                : node.get(fallbackKey);
        if (target != null && target.isObject()) {
            return toMap(target);
        }
        return Collections.emptyMap();
    }

    private List<Map<String, Object>> extractTopList(JsonNode node, String nestedParentKey, String directListKey) {
        if (node.has(nestedParentKey) && node.get(nestedParentKey).isObject()) {
            JsonNode top = node.get(nestedParentKey).get("top");
            if (top != null && top.isArray()) {
                return toListOfMaps(top);
            }
        }
        if (node.has(directListKey) && node.get(directListKey).isArray()) {
            return toListOfMaps(node.get(directListKey));
        }
        return Collections.emptyList();
    }

    private Map<String, Object> extractProtocolCounts(JsonNode node) {
        Map<String, Object> counts = new LinkedHashMap<>();
        JsonNode source = node.has("protocol_counts") && node.get("protocol_counts").isObject()
                ? node.get("protocol_counts")
                : node;
        for (String key : PROTOCOL_LOG_KEYS) {
            if (source.has(key) && !source.get(key).isNull()) {
                counts.put(key, objectMapper.convertValue(source.get(key), Object.class));
            } else if (node.has(key) && !node.get(key).isNull()) {
                counts.put(key, objectMapper.convertValue(node.get(key), Object.class));
            }
        }
        return Collections.unmodifiableMap(counts);
    }

    private List<Map<String, Object>> extractListOfMaps(JsonNode node, String key) {
        if (node.has(key) && node.get(key).isArray()) {
            return toListOfMaps(node.get(key));
        }
        return Collections.emptyList();
    }

    private List<String> extractStringList(JsonNode node, String key) {
        if (!node.has(key) || node.get(key).isNull()) {
            return Collections.emptyList();
        }
        JsonNode target = node.get(key);
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
