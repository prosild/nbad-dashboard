package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentModelScore;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.SlackDelivery;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 역할별 개인정보·IPv4·가명표 마스킹 서비스.
 * VIEWER에게만 마스킹을 적용하고, ANALYST·ADMIN에게는 원문을 반환한다.
 */
@Service
public class MaskingService {

    // Java의 \b는 한글 등 유니코드 문자도 단어 문자로 취급하므로 ASCII 영숫자/밑줄/점 경계를 사용한다.
    private static final Pattern IPV4_PATTERN =
            Pattern.compile("(?<![A-Za-z0-9_.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![A-Za-z0-9_.])");

    private final ObjectMapper objectMapper;

    public MaskingService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean shouldMask(UserRole role) {
        return role == null || role == UserRole.VIEWER;
    }

    public String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return ip;
        }
        return maskIpsInText(ip);
    }

    public String maskIpsInText(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        Matcher matcher = IPV4_PATTERN.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            if (isValidOctet(matcher.group(1))
                    && isValidOctet(matcher.group(2))
                    && isValidOctet(matcher.group(3))
                    && isValidOctet(matcher.group(4))) {
                String replacement = matcher.group(1) + "." + matcher.group(2) + ".*.*";
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            } else {
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matcher.group(0)));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private boolean isValidOctet(String group) {
        try {
            int val = Integer.parseInt(group);
            return val >= 0 && val <= 255;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public String maskUsername(String username) {
        if (username == null || username.isEmpty()) {
            return username;
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty()) {
            return username;
        }
        if (trimmed.length() <= 1) {
            return "***";
        }
        return trimmed.charAt(0) + "***";
    }

    public JsonNode maskPseudonyms(JsonNode pseudonyms, UserRole role) {
        if (pseudonyms == null || !shouldMask(role)) {
            return pseudonyms;
        }
        return maskJsonIps(pseudonyms);
    }

    public JsonNode maskSlackPayload(JsonNode slackPayload, UserRole role) {
        if (slackPayload == null || !shouldMask(role)) {
            return slackPayload;
        }
        return maskJsonIps(slackPayload);
    }

    public JsonNode maskJsonIps(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isTextual()) {
            return TextNode.valueOf(maskIpsInText(node.asText()));
        }
        if (node.isObject()) {
            ObjectNode copy = objectMapper.createObjectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                copy.set(entry.getKey(), maskJsonIps(entry.getValue()));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = objectMapper.createArrayNode();
            for (JsonNode child : node) {
                copy.add(maskJsonIps(child));
            }
            return copy;
        }
        return node.deepCopy();
    }

    public IncidentQueueItem maskIncidentQueueItem(IncidentQueueItem item, UserRole role) {
        if (item == null || !shouldMask(role)) {
            return item;
        }
        IncidentQueueItem copy = new IncidentQueueItem();
        copy.setJobId(item.getJobId());
        copy.setCaptureId(item.getCaptureId());
        copy.setBundleId(item.getBundleId());
        copy.setQueueRank(item.getQueueRank());
        copy.setIncidentId(maskIpsInText(item.getIncidentId()));
        copy.setHostIp(maskIp(item.getHostIp()));
        copy.setZeekadRole(item.getZeekadRole());
        copy.setEventStart(item.getEventStart());
        copy.setEventEnd(item.getEventEnd());
        copy.setZeekadPickedBy(item.getZeekadPickedBy());
        copy.setZeekadAlsoFlaggedBy(item.getZeekadAlsoFlaggedBy());
        copy.setConnectionCount(item.getConnectionCount());
        copy.setHostName(maskStringListIps(item.getHostName()));
        copy.setZeekadStatus(item.getZeekadStatus());
        copy.setZeekadResolution(item.getZeekadResolution());
        copy.setStatusUpdatedAt(item.getStatusUpdatedAt());
        copy.setZeekadReportJobId(item.getZeekadReportJobId());
        copy.setHasReport(item.isHasReport());
        copy.setZeekadReportKind(item.getZeekadReportKind());
        copy.setZeekadVerificationPassed(item.getZeekadVerificationPassed());
        copy.setZeekadWouldSend(item.isZeekadWouldSend());
        copy.setZeekadReviewAction(item.getZeekadReviewAction());
        copy.setZeekadReviewPending(item.isZeekadReviewPending());
        return copy;
    }

    public IncidentModelScore maskIncidentModelScore(IncidentModelScore score, UserRole role) {
        if (score == null || !shouldMask(role)) {
            return score;
        }
        IncidentModelScore copy = new IncidentModelScore();
        copy.setJobId(score.getJobId());
        copy.setIncidentId(maskIpsInText(score.getIncidentId()));
        copy.setZeekadModel(score.getZeekadModel());
        copy.setMaxScore(score.getMaxScore());
        copy.setCandidateWindows(score.getCandidateWindows());
        copy.setWindows(score.getWindows());
        return copy;
    }

    public AssetNameRecord maskAssetNameRecord(AssetNameRecord asset, UserRole role) {
        if (asset == null || !shouldMask(role)) {
            return asset;
        }
        AssetNameRecord copy = new AssetNameRecord();
        copy.setCaptureId(asset.getCaptureId());
        copy.setHostIp(maskIp(asset.getHostIp()));
        copy.setKerberosUser(maskUsername(asset.getKerberosUser()));
        copy.setNtlmUser(maskUsername(asset.getNtlmUser()));
        copy.setExtraAttributes(maskMapValues(asset.getExtraAttributes()));
        return copy;
    }

    public AnalystReviewItem maskAnalystReviewItem(AnalystReviewItem item, UserRole role) {
        if (item == null || !shouldMask(role)) {
            return item;
        }
        AnalystReviewItem copy = new AnalystReviewItem();
        copy.setJobId(item.getJobId());
        copy.setReviewJobId(item.getReviewJobId());
        copy.setCaptureId(item.getCaptureId());
        copy.setIncidentId(maskIpsInText(item.getIncidentId()));
        copy.setQueueRank(item.getQueueRank());
        copy.setHostIp(maskIp(item.getHostIp()));
        copy.setZeekadRole(item.getZeekadRole());
        copy.setZeekadReviewReason(maskIpsInText(item.getZeekadReviewReason()));
        copy.setRequestedAt(item.getRequestedAt());
        copy.setZeekadReviewAction(item.getZeekadReviewAction());
        copy.setAnalyst(item.getAnalyst());
        copy.setAnalystDisplay(item.getAnalystDisplay());
        copy.setDecidedAt(item.getDecidedAt());
        copy.setZeekadReviewResumedAt(item.getZeekadReviewResumedAt());
        copy.setZeekadReviewResumeFailed(item.getZeekadReviewResumeFailed());
        return copy;
    }

    public SlackSummary maskSlackSummary(SlackSummary summary, UserRole role) {
        if (summary == null || !shouldMask(role)) {
            return summary;
        }
        SlackSummary copy = new SlackSummary();
        copy.setJobId(summary.getJobId());
        copy.setCaptureId(summary.getCaptureId());
        copy.setZeekadMessageVersion(summary.getZeekadMessageVersion());
        copy.setZeekadDeliveryMode(summary.getZeekadDeliveryMode());
        copy.setZeekadDeliveryStatus(summary.getZeekadDeliveryStatus());
        copy.setSlackPayload(maskSlackPayload(summary.getSlackPayload(), role));
        copy.setSlackTs(summary.getSlackTs());
        copy.setDeliveredAt(summary.getDeliveredAt());
        copy.setCreatedAt(summary.getCreatedAt());
        return copy;
    }

    public SlackDelivery maskSlackDelivery(SlackDelivery delivery, UserRole role) {
        if (delivery == null || !shouldMask(role)) {
            return delivery;
        }
        SlackDelivery copy = new SlackDelivery();
        copy.setJobId(delivery.getJobId());
        copy.setIncidentId(maskIpsInText(delivery.getIncidentId()));
        copy.setZeekadMessageKind(delivery.getZeekadMessageKind());
        copy.setZeekadMessageVersion(delivery.getZeekadMessageVersion());
        copy.setZeekadDeliveryMode(delivery.getZeekadDeliveryMode());
        copy.setZeekadDeliveryStatus(delivery.getZeekadDeliveryStatus());
        copy.setSlackPayload(maskSlackPayload(delivery.getSlackPayload(), role));
        copy.setSlackTs(delivery.getSlackTs());
        copy.setDeliveredAt(delivery.getDeliveredAt());
        copy.setError(maskIpsInText(delivery.getError()));
        copy.setCreatedAt(delivery.getCreatedAt());
        copy.setZeekadThreadParent(maskIpsInText(delivery.getZeekadThreadParent()));
        copy.setZeekadReplyBroadcast(delivery.getZeekadReplyBroadcast());
        return copy;
    }

    public EvidenceData maskEvidence(EvidenceData evidence, UserRole role) {
        if (evidence == null || !shouldMask(role)) {
            return evidence;
        }
        EvidenceData masked = evidence.copy();
        masked.setTopPeers(maskListOfMaps(evidence.getTopPeers()));
        masked.setRepresentativeConnections(maskListOfMaps(evidence.getRepresentativeConnections()));
        masked.setProtocolLogs(maskMapValues(evidence.getProtocolLogs()));
        masked.setAdditionalFields(maskMapValues(evidence.getAdditionalFields()));
        masked.setLimits(maskStringListIps(evidence.getLimits()));
        return masked;
    }

    private List<String> maskStringListIps(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> masked = new ArrayList<>(values.size());
        for (String v : values) {
            masked.add(maskIpsInText(v));
        }
        return Collections.unmodifiableList(masked);
    }

    private List<Map<String, Object>> maskListOfMaps(List<Map<String, Object>> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        List<Map<String, Object>> masked = new ArrayList<>(list.size());
        for (Map<String, Object> row : list) {
            masked.add(maskMapValues(row));
        }
        return Collections.unmodifiableList(masked);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> maskMapValues(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> masked = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            masked.put(entry.getKey(), maskObjectValue(entry.getValue()));
        }
        return Collections.unmodifiableMap(masked);
    }

    @SuppressWarnings("unchecked")
    private Object maskObjectValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String str) {
            return maskIpsInText(str);
        }
        if (value instanceof Map<?, ?> nestedMap) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : nestedMap.entrySet()) {
                if (e.getKey() != null) {
                    copy.put(e.getKey().toString(), maskObjectValue(e.getValue()));
                }
            }
            return Collections.unmodifiableMap(copy);
        }
        if (value instanceof List<?> nestedList) {
            List<Object> copy = new ArrayList<>(nestedList.size());
            for (Object elem : nestedList) {
                copy.add(maskObjectValue(elem));
            }
            return Collections.unmodifiableList(copy);
        }
        return value;
    }
}
