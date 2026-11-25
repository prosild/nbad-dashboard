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
import com.zeekad.dashboard.model.zeekad.ScoringJob;
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

    // 경계는 숫자로만 본다(T37): 앞에 숫자나 "숫자."가 붙거나 뒤에 숫자나 ".숫자"가 이어지면 더 긴 숫자열이라 IP로 보지 않는다.
    // 영문자·밑줄·점·한글에 붙은 IP(name_10.0.0.1, peer.10.0.0.1, 10.0.0.1에서, 문장 끝 10.0.0.1.)도 가린다.
    // T37 전에는 앞뒤가 ASCII 영숫자·밑줄·점이면 가리지 않아 위 꼴(한글 뒤 제외)이 조회자에게 원문으로 나갔다.
    private static final Pattern IPV4_PATTERN =
            Pattern.compile("(?<!\\d)(?<!\\d\\.)(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?!\\d)(?!\\.\\d)");

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

    /**
     * T37: 글 잎과 객체 키 모두의 IPv4를 가린다(maskJsonIps는 키를 그대로 두므로 따로 둔다).
     * 가린 뒤 같은 객체 안에서 키가 겹치면 값을 잃지 않도록 전체를 null로 돌려준다(호출자는 구조 값을 싣지 않는다).
     */
    public JsonNode maskJsonIpsIncludingKeys(JsonNode node) {
        if (node == null) {
            return null;
        }
        try {
            return maskJsonIpsIncludingKeysOrThrow(node);
        } catch (MaskedKeyCollisionException e) {
            return null;
        }
    }

    private JsonNode maskJsonIpsIncludingKeysOrThrow(JsonNode node) {
        if (node.isTextual()) {
            return TextNode.valueOf(maskIpsInText(node.asText()));
        }
        if (node.isObject()) {
            ObjectNode copy = objectMapper.createObjectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String maskedKey = maskIpsInText(entry.getKey());
                if (copy.has(maskedKey)) {
                    throw new MaskedKeyCollisionException();
                }
                copy.set(maskedKey, maskJsonIpsIncludingKeysOrThrow(entry.getValue()));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = objectMapper.createArrayNode();
            for (JsonNode child : node) {
                copy.add(maskJsonIpsIncludingKeysOrThrow(child));
            }
            return copy;
        }
        return node.deepCopy();
    }

    private static final class MaskedKeyCollisionException extends RuntimeException {
        MaskedKeyCollisionException() {
            super(null, null, false, false);
        }
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
        copy.setAlerted(item.isAlerted());
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
        copy.setExtraAttributes(maskAssetExtraAttributes(asset.getExtraAttributes()));
        return copy;
    }

    /** dashboard.asset_names의 관측 계정 이름 열(T46). 상세 증적 탭 '관측 계정'과 /hosts가 이 값을 먼저 보인다. */
    public static final String ASSET_ACCOUNT_NAME_KEY = "zeekad_name";

    /**
     * 자산 이름 부가 열(T46): 키가 zeekad_name(대소문자 무시)이면 계정 이름으로 가리고, 나머지 키는 지금처럼 IPv4만 가린다.
     * 호스트 이름(host_name)은 여기서 다루지 않는다(큐 행의 값이고 IPv4만 가린다).
     */
    private Map<String, Object> maskAssetExtraAttributes(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> masked = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            boolean account = entry.getKey() != null && ASSET_ACCOUNT_NAME_KEY.equalsIgnoreCase(entry.getKey());
            masked.put(entry.getKey(), account ? maskAccountValue(entry.getValue()) : maskObjectValue(entry.getValue()));
        }
        return Collections.unmodifiableMap(masked);
    }

    /**
     * 계정 이름 값: 문자열이면 그 글에, 리스트면 원소마다 maskIpsInText 다음 maskUsername을 적용한다.
     * 문자열이 아닌 값(리스트 원소 포함)은 글로 바꿔 같은 규칙으로 가린다(이 키만은 모르는 타입을 그대로 내보내지 않는다). null은 null이다.
     */
    private Object maskAccountValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            for (Object elem : list) {
                copy.add(elem == null ? null : maskAccountText(String.valueOf(elem)));
            }
            return Collections.unmodifiableList(copy);
        }
        return maskAccountText(String.valueOf(value));
    }

    private String maskAccountText(String text) {
        return maskUsername(maskIpsInText(text));
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
        copy.setIncidentNo(item.getIncidentNo());
        return copy;
    }

    /**
     * 탐지 작업(T24): VIEWER면 오류 글 안의 IPv4를 가린다. 나머지 값은 그대로다.
     * 현황판 overview와 /api/operations(jobs[].error, latestJobs) 두 곳에 같이 쓴다.
     */
    public ScoringJob maskScoringJob(ScoringJob job, UserRole role) {
        if (job == null || !shouldMask(role)) {
            return job;
        }
        ScoringJob copy = new ScoringJob();
        copy.setJobId(job.getJobId());
        copy.setCaptureId(job.getCaptureId());
        copy.setBundleId(job.getBundleId());
        copy.setStatus(job.getStatus());
        copy.setStartedAt(job.getStartedAt());
        copy.setFinishedAt(job.getFinishedAt());
        copy.setError(maskIpsInText(job.getError()));
        copy.setIncidentCount(job.getIncidentCount());
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
        masked.setAdditionalFields(maskAdditionalFields(evidence.getAdditionalFields()));
        masked.setLimits(maskStringListIps(evidence.getLimits()));
        return masked;
    }

    /** VIEWER 증적 추가 필드 host에서 남기는 하위 키(T21). 나머지 하위 키(host.name 등)는 서버에서 뺀다. */
    static final String EVIDENCE_HOST_KEY = "host";
    static final String EVIDENCE_HOST_ALLOWED_SUBKEY = "ip";

    /**
     * 추가 필드를 마스킹한다. host는 허용 목록으로 거른다(T21):
     * 객체면 하위 키 ip만 마스킹해 남기고, 문자열이면 IPv4를 가리고, 그 밖의 형태(배열·숫자·null 등)는 뺀다.
     */
    private Map<String, Object> maskAdditionalFields(Map<String, Object> fields) {
        if (fields == null || fields.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> masked = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            if (EVIDENCE_HOST_KEY.equals(entry.getKey())) {
                Object host = entry.getValue();
                if (host instanceof Map<?, ?> hostMap) {
                    Map<String, Object> allowed = new LinkedHashMap<>();
                    if (hostMap.containsKey(EVIDENCE_HOST_ALLOWED_SUBKEY)) {
                        allowed.put(EVIDENCE_HOST_ALLOWED_SUBKEY,
                                maskObjectValue(hostMap.get(EVIDENCE_HOST_ALLOWED_SUBKEY)));
                    }
                    masked.put(EVIDENCE_HOST_KEY, Collections.unmodifiableMap(allowed));
                } else if (host instanceof String str) {
                    masked.put(EVIDENCE_HOST_KEY, maskIpsInText(str));
                }
                continue;
            }
            masked.put(entry.getKey(), maskObjectValue(entry.getValue()));
        }
        return Collections.unmodifiableMap(masked);
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
