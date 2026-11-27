package com.zeekad.dashboard.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.zeekad.dashboard.client.EvidenceApiClient;
import com.zeekad.dashboard.client.EvidenceApiResponse;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.IncidentRef;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentModelScore;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.IncidentReport;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.model.zeekad.IncidentStatusHistory;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SendDecision;
import com.zeekad.dashboard.model.zeekad.SlackDelivery;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 사건 상세 화면(/incidents/{jobId}/rank/{queueRank}) 데이터 조합, 가명 치환, 마스킹, 감사 로그 기록 서비스.
 */
@Service
public class IncidentDetailService {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IncidentDetailService.class);

    private static final List<String> PROTOCOL_LOG_KEYS = List.of(
            "dns", "http", "tls", "ssh", "ftp", "smb", "kerberos", "dce_rpc", "ntlm"
    );

    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final IncidentQueryService incidentQueryService;
    private final EvidenceApiClient evidenceApiClient;
    private final MaskingService maskingService;
    private final PseudonymAnnotator pseudonymAnnotator;
    private final ObjectMapper objectMapper;
    private final IncidentRefService incidentRefService;
    private final SlackThreadService slackThreadService;

    /** 페이로드 맨 위의 스레드 부모 키(T39 new-shapes.md) */
    private static final String PAYLOAD_THREAD_PARENT = "zeekad_thread_parent";

    public IncidentDetailService(ZeekadReadMapper zeekadReadMapper,
                                 CaptureAccessService captureAccessService,
                                 IncidentQueryService incidentQueryService,
                                 EvidenceApiClient evidenceApiClient,
                                 MaskingService maskingService,
                                 PseudonymAnnotator pseudonymAnnotator,
                                 ObjectMapper objectMapper,
                                 IncidentRefService incidentRefService,
                                 SlackThreadService slackThreadService) {
        this.incidentRefService = incidentRefService;
        this.slackThreadService = slackThreadService;
        this.zeekadReadMapper = zeekadReadMapper;
        this.captureAccessService = captureAccessService;
        this.incidentQueryService = incidentQueryService;
        this.evidenceApiClient = evidenceApiClient;
        this.maskingService = maskingService;
        this.pseudonymAnnotator = pseudonymAnnotator;
        this.objectMapper = objectMapper;
    }

    public IncidentDetailView loadDetail(DashboardUserPrincipal principal,
                                         Long jobId,
                                         Integer queueRank,
                                         String clientIp) {
        IncidentQueueItem rawIncident = captureAccessService.requireIncidentAccessByRank(
                principal, jobId, queueRank, clientIp);
        UserRole role = principal != null ? principal.getRole() : UserRole.VIEWER;

        captureAccessService.recordUnmaskedViewIfPrivileged(
                principal, rawIncident.getCaptureId(), jobId, rawIncident.getIncidentId(), clientIp);

        // T63(설계자 결정): 작업 오류 글은 현황판·운영 현황처럼 조회자에게 가린다(전에는 상세만 원문이었다)
        ScoringJob job = maskingService.maskScoringJob(zeekadReadMapper.findScoringJobById(jobId), role);
        List<IncidentModelScore> modelScores = zeekadReadMapper.findModelScores(jobId, rawIncident.getIncidentId())
                .stream()
                .map(score -> maskingService.maskIncidentModelScore(score, role))
                .toList();
        List<AssetNameRecord> assetNames = incidentQueryService.findAssetNames(
                rawIncident.getCaptureId(), rawIncident.getHostIp(), role);

        IncidentQueueItem displayIncident = maskingService.maskIncidentQueueItem(rawIncident, role);

        EvidenceApiResponse apiResponse = evidenceApiClient.fetchIncidentEvidence(jobId, queueRank);
        IncidentDetailView.EvidenceView evidenceView = buildEvidenceViewOrFallback(apiResponse, role, jobId, queueRank);

        Map<String, String> userDisplayMap = incidentQueryService.loadUserDisplayMap();

        Long reportJobId = rawIncident.getZeekadReportJobId();
        IncidentDetailView.ReportView reportView;
        IncidentDetailView.SendDecisionView decisionView;
        IncidentDetailView.AnalystReviewView analystReviewView;
        if (reportJobId != null) {
            IncidentReport rawReport = zeekadReadMapper.findIncidentReport(
                    reportJobId, rawIncident.getIncidentId());
            reportView = buildReportView(rawReport, role);

            SendDecision rawDecision = zeekadReadMapper.findSendDecision(
                    reportJobId, rawIncident.getIncidentId());
            decisionView = buildSendDecisionView(rawDecision, role);

            AnalystReviewItem rawReview = zeekadReadMapper.findAnalystReviewByJobAndIncident(
                    reportJobId, rawIncident.getIncidentId());
            analystReviewView = buildAnalystReviewView(rawReview, role, userDisplayMap);
        } else {
            reportView = IncidentDetailView.ReportView.absent();
            decisionView = IncidentDetailView.SendDecisionView.absent();
            analystReviewView = IncidentDetailView.AnalystReviewView.absent();
        }

        List<SlackDelivery> rawDeliveries = zeekadReadMapper.findSlackDeliveries(rawIncident.getIncidentId());
        SlackThreads slackThreads = buildSlackThreads(rawDeliveries, rawIncident.getIncidentId(), principal, role);
        List<IncidentDetailView.SlackDeliveryView> deliveryViews = slackThreads.deliveries();
        List<IncidentDetailView.SlackThreadGroup> threadGroups = slackThreads.groups();

        IncidentStatus status = zeekadReadMapper.findIncidentStatus(rawIncident.getIncidentId());
        String currentStatus = resolveStatus(status, rawIncident);
        String currentResolution = status != null ? status.getZeekadResolution() : rawIncident.getZeekadResolution();

        List<IncidentStatusHistory> rawHistory = zeekadReadMapper.findIncidentStatusHistory(
                rawIncident.getIncidentId());
        String updatedByDisplay = status != null
                ? incidentQueryService.formatActorDisplay(status.getUpdatedBy(), userDisplayMap)
                : null;
        List<IncidentDetailView.StatusHistoryItem> historyItems = rawHistory.stream()
                .map(h -> new IncidentDetailView.StatusHistoryItem(
                        h.getJobId(),
                        h.getFromStatus(),
                        h.getToStatus(),
                        h.getZeekadResolution(),
                        incidentQueryService.formatActorDisplay(h.getActor(), userDisplayMap),
                        maskingService.shouldMask(role) ? maskingService.maskViewerText(h.getReason(), true) : h.getReason(),
                        h.getChangedAt()
                ))
                .toList();

        boolean canTransition = role == UserRole.ANALYST || role == UserRole.ADMIN;
        String nextAllowedStatus = resolveNextAllowedStatus(currentStatus);

        return new IncidentDetailView(
                displayIncident,
                job,
                modelScores,
                assetNames,
                evidenceView,
                reportView,
                decisionView,
                deliveryViews,
                threadGroups,
                analystReviewView,
                currentStatus,
                currentResolution,
                status != null ? status.getUpdatedAt() : rawIncident.getStatusUpdatedAt(),
                updatedByDisplay,
                historyItems,
                canTransition,
                nextAllowedStatus
        );
    }

    /**
     * 근거 API는 바깥 시스템이다(T42). 클라이언트가 정상으로 돌려준 값을 조립(마스킹·형변환)하다 예외가 나도
     * 상세 전체를 500으로 만들지 않고 증적만 "불러오지 못함"으로 둔다. 조립하던 값은 일부라도 싣지 않는다
     * (마스킹이 끝나지 않은 값이 조회자에게 나가지 않게). 로그는 경로·예외 종류만 적는다.
     */
    private IncidentDetailView.EvidenceView buildEvidenceViewOrFallback(EvidenceApiResponse apiResponse, UserRole role,
                                                                        long jobId, int queueRank) {
        try {
            return buildEvidenceView(apiResponse, role);
        } catch (RuntimeException e) {
            log.warn("근거 API /api/v1/jobs/{}/incidents/{} 증거 조립 실패(폴백 반환): {}",
                    jobId, queueRank, e.getClass().getName());
            return IncidentDetailView.EvidenceView.unavailable(EvidenceData.FALLBACK_MESSAGE);
        }
    }

    private IncidentDetailView.EvidenceView buildEvidenceView(EvidenceApiResponse apiResponse, UserRole role) {
        if (apiResponse == null || !apiResponse.isAvailable()) {
            return IncidentDetailView.EvidenceView.unavailable(EvidenceData.FALLBACK_MESSAGE);
        }
        EvidenceData raw = apiResponse.getEvidence();
        if (raw == null || !raw.isAvailable()) {
            // API는 응답했지만 이 사건의 근거 행이 없는 경우 등: 클라이언트가 정한 상태 문구를 그대로 쓴다.
            String message = raw != null ? raw.getStatusMessage() : null;
            return IncidentDetailView.EvidenceView.unavailable(
                    message == null || message.isBlank() ? EvidenceData.FALLBACK_MESSAGE : message);
        }

        EvidenceData data = maskingService.maskEvidence(raw, role);
        Map<String, Object> logs = data.getProtocolLogs();
        List<IncidentDetailView.ProtocolLogEntry> protocols = new ArrayList<>();
        for (String key : PROTOCOL_LOG_KEYS) {
            protocols.add(new IncidentDetailView.ProtocolLogEntry(key, toMetrics(logs.get(key))));
        }
        for (Map.Entry<String, Object> entry : logs.entrySet()) {
            if (!PROTOCOL_LOG_KEYS.contains(entry.getKey())) {
                protocols.add(new IncidentDetailView.ProtocolLogEntry(entry.getKey(), toMetrics(entry.getValue())));
            }
        }

        return new IncidentDetailView.EvidenceView(
                true,
                data.getStatusMessage(),
                data.getConnectionCount(),
                data.getBytesSent(),
                data.getBytesReceived(),
                data.getPayloadBytesInflated(),
                data.getTransportCounts(),
                data.getServiceProtocolCounts(),
                data.getConnStateCounts(),
                data.getTopPeers(),
                data.getUniquePeers(),
                data.getTopPorts(),
                data.getUniquePorts(),
                Collections.unmodifiableList(protocols),
                data.getRepresentativeConnections(),
                data.getLimits(),
                data.getAdditionalFields()
        );
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toMetrics(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        // 키가 없거나 객체가 아니면 null(값 없음). 0으로 바꾸지 않는다.
        return null;
    }

    private IncidentDetailView.ReportView buildReportView(IncidentReport report, UserRole role) {
        if (report == null) {
            return IncidentDetailView.ReportView.absent();
        }
        boolean mask = maskingService.shouldMask(role);
        Map<String, String> pseudonyms = pseudonymAnnotator.buildEffectivePseudonymMap(
                report.getZeekadPseudonyms(), role);
        ParsedFacts parsedFacts = parseFacts(report.getZeekadFacts(), mask);
        Map<String, IncidentDetailView.FactItem> factIndex = parsedFacts.index();

        JsonNode body = report.getZeekadReport();
        String observationSummary = null;
        List<IncidentDetailView.ClaimItem> claims = List.of();
        List<IncidentDetailView.ExplanationItem> explanations = List.of();
        IncidentDetailView.SendRecommendationItem sendRecommendation = null;
        List<String> limitations = List.of();
        List<String> followUp = List.of();

        if (body != null && body.isObject()) {
            observationSummary = annotateText(textOrNull(body.get("observation_summary")), pseudonyms, role);
            claims = parseClaims(body.get("claims"), pseudonyms, factIndex, mask, role);
            explanations = parseExplanations(body.get("possible_explanations"), pseudonyms, factIndex, mask, role);
            sendRecommendation = parseSendRecommendation(
                    body.get("send_recommendation"), pseudonyms, factIndex, mask, role);
            limitations = annotateTextList(extractTextArray(body.get("limitations")), pseudonyms, role);
            followUp = annotateTextList(extractTextArray(body.get("follow_up")), pseudonyms, role);
        }

        List<String> verificationProblems = extractTextArray(report.getZeekadVerificationProblems());
        if (mask) {
            verificationProblems = verificationProblems.stream()
                    .map(p -> maskingService.maskViewerText(p, true))
                    .toList();
        }
        List<JsonNode> verificationProblemItems =
                buildVerificationProblemItems(report.getZeekadVerificationProblems(), mask);

        String verificationReason = mask
                ? maskingService.maskViewerText(report.getZeekadVerificationReason(), true)
                : report.getZeekadVerificationReason();
        String llmError = mask
                ? maskingService.maskViewerText(report.getLlmError(), true)
                : report.getLlmError();

        List<IncidentDetailView.AttackCandidateItem> attackCandidates =
                parseAttackCandidates(report.getZeekadAttackCandidates(), mask);

        return new IncidentDetailView.ReportView(
                true,
                report.getZeekadReportKind(),
                report.getZeekadReportVersion(),
                report.getZeekadInputVersion(),
                report.getLlmModelRequested(),
                report.getLlmModelVersion(),
                report.getLlmSeconds(),
                report.getLlmInputTokens(),
                report.getLlmOutputTokens(),
                report.getLlmThinkingTokens(),
                llmError,
                report.getZeekadVerificationPassed(),
                verificationReason,
                verificationProblems,
                report.getCreatedAt(),
                report.getZeekadSourceRun(),
                pseudonyms,
                observationSummary,
                claims,
                explanations,
                sendRecommendation,
                limitations,
                followUp,
                attackCandidates,
                parsedFacts.all(),
                verificationProblemItems
        );
    }

    /** T37: parseFacts 결과. index는 인용 해석용(같은 id면 뒤의 것), all은 원래 순서 전체 목록. */
    private record ParsedFacts(Map<String, IncidentDetailView.FactItem> index,
                               List<IncidentDetailView.FactItem> all) {
    }

    private ParsedFacts parseFacts(JsonNode factsNode, boolean mask) {
        if (factsNode == null || !factsNode.isArray()) {
            return new ParsedFacts(Collections.emptyMap(), List.of());
        }
        Map<String, IncidentDetailView.FactItem> index = new LinkedHashMap<>();
        List<IncidentDetailView.FactItem> all = new ArrayList<>();
        for (JsonNode node : factsNode) {
            if (node == null || !node.isObject()) {
                continue;
            }
            String id = textOrNull(node.get("id"));
            if (id == null) {
                continue;
            }
            String name = textOrNull(node.get("name"));
            String rawVal = nodeValueToString(node.get("value"));
            String value = mask ? maskingService.maskViewerText(rawVal, true) : rawVal;
            String safeName = name != null ? (mask ? maskingService.maskViewerText(name, false) : name) : "-";
            String safeId = mask ? maskingService.maskIpsInText(id) : id;
            IncidentDetailView.FactItem item = new IncidentDetailView.FactItem(
                    safeId, safeName, value != null ? value : "-", structuredValue(node.get("value"), mask));
            // 인용 해석은 원래 id로 찾는다(같은 id면 뒤의 것). 전체 목록에는 원래 순서로 모두 넣는다.
            index.put(id, item);
            all.add(item);
        }
        return new ParsedFacts(Collections.unmodifiableMap(index), Collections.unmodifiableList(all));
    }

    /** T37: 사실 값의 구조 값. 조회자는 글 잎과 객체 키의 IPv4를 가리고, 가린 키가 겹치면 null(글 값만 남김). */
    private JsonNode structuredValue(JsonNode valueNode, boolean mask) {
        if (valueNode == null || valueNode.isMissingNode()) {
            return null;
        }
        return mask ? maskingService.maskJsonIpsIncludingKeys(valueNode) : valueNode.deepCopy();
    }

    /**
     * T37: 검증 문제 구조 목록. 항목 고르기는 extractTextArray와 같다(null·빈 글 제외).
     * 객체 항목은 구조 그대로(조회자는 키·글 잎 IPv4 가림, 가린 키가 겹치면 가린 글), 그 밖은 글로 넘긴다.
     */
    private List<JsonNode> buildVerificationProblemItems(JsonNode problemsNode, boolean mask) {
        if (problemsNode == null || problemsNode.isNull()) {
            return List.of();
        }
        List<JsonNode> source = new ArrayList<>();
        if (problemsNode.isArray()) {
            problemsNode.forEach(source::add);
        } else {
            source.add(problemsNode);
        }
        List<JsonNode> items = new ArrayList<>();
        for (JsonNode child : source) {
            String text = nodeValueToString(child);
            if (text == null || text.isBlank()) {
                continue;
            }
            String safeText = mask ? maskingService.maskViewerText(text, true) : text;
            if (child.isObject()) {
                JsonNode structured = mask ? maskingService.maskJsonIpsIncludingKeys(child) : child.deepCopy();
                items.add(structured != null ? structured : TextNode.valueOf(safeText));
            } else {
                items.add(TextNode.valueOf(safeText));
            }
        }
        return Collections.unmodifiableList(items);
    }

    private List<IncidentDetailView.ClaimItem> parseClaims(JsonNode claimsNode,
                                                           Map<String, String> pseudonyms,
                                                           Map<String, IncidentDetailView.FactItem> factIndex,
                                                           boolean mask,
                                                           UserRole role) {
        if (claimsNode == null || !claimsNode.isArray()) {
            return List.of();
        }
        List<IncidentDetailView.ClaimItem> items = new ArrayList<>();
        for (JsonNode node : claimsNode) {
            if (node == null || node.isNull()) {
                continue;
            }
            if (node.isTextual()) {
                items.add(new IncidentDetailView.ClaimItem(
                        annotateText(node.asText(), pseudonyms, role), List.of()));
                continue;
            }
            if (node.isObject()) {
                String claimText = annotateText(textOrNull(node.get("claim")), pseudonyms, role);
                if (claimText != null) {
                    List<IncidentDetailView.FactItem> facts = resolveFacts(node.get("fact_ids"), factIndex, mask);
                    items.add(new IncidentDetailView.ClaimItem(claimText, facts));
                }
            }
        }
        return Collections.unmodifiableList(items);
    }

    private List<IncidentDetailView.ExplanationItem> parseExplanations(JsonNode expNode,
                                                                       Map<String, String> pseudonyms,
                                                                       Map<String, IncidentDetailView.FactItem> factIndex,
                                                                       boolean mask,
                                                                       UserRole role) {
        if (expNode == null || !expNode.isArray()) {
            return List.of();
        }
        List<IncidentDetailView.ExplanationItem> items = new ArrayList<>();
        for (JsonNode node : expNode) {
            if (node == null || node.isNull()) {
                continue;
            }
            if (node.isTextual()) {
                items.add(new IncidentDetailView.ExplanationItem(
                        annotateText(node.asText(), pseudonyms, role), List.of(), List.of()));
                continue;
            }
            if (node.isObject()) {
                String text = annotateText(textOrNull(node.get("explanation")), pseudonyms, role);
                if (text != null) {
                    List<IncidentDetailView.FactItem> facts = resolveFacts(node.get("fact_ids"), factIndex, mask);
                    List<String> attackIds = extractTextArray(node.get("attack_ids"));
                    items.add(new IncidentDetailView.ExplanationItem(text, facts, attackIds));
                }
            }
        }
        return Collections.unmodifiableList(items);
    }

    private IncidentDetailView.SendRecommendationItem parseSendRecommendation(
            JsonNode recNode,
            Map<String, String> pseudonyms,
            Map<String, IncidentDetailView.FactItem> factIndex,
            boolean mask,
            UserRole role) {
        if (recNode == null || !recNode.isObject() || recNode.isEmpty()) {
            return null;
        }
        String choice = textOrNull(recNode.get("choice"));
        String reason = annotateText(textOrNull(recNode.get("reason")), pseudonyms, role);
        List<IncidentDetailView.FactItem> facts = resolveFacts(recNode.get("fact_ids"), factIndex, mask);
        if (choice == null && reason == null && facts.isEmpty()) {
            return null;
        }
        return new IncidentDetailView.SendRecommendationItem(choice, reason, facts);
    }

    /**
     * ATT&amp;CK 후보. attackId는 식별자라 그대로 두고, 이름·전술은 T63(설계자 결정)부터 조회자에게 현황판 위협 패널
     * (DashboardThreatService)과 같은 가림(maskViewerText)을 적용한다(전에는 상세만 원문이었다).
     */
    private List<IncidentDetailView.AttackCandidateItem> parseAttackCandidates(JsonNode candidatesNode, boolean mask) {
        if (candidatesNode == null || !candidatesNode.isArray()) {
            return List.of();
        }
        List<IncidentDetailView.AttackCandidateItem> items = new ArrayList<>();
        for (JsonNode node : candidatesNode) {
            if (node == null || !node.isObject()) {
                continue;
            }
            String attackId = textOrNull(node.get("attack_id"));
            String name = textOrNull(node.get("name"));
            List<String> tactics = extractTextArray(node.get("tactics"));
            if (mask) {
                name = name == null ? null : maskingService.maskViewerText(name, false);
                tactics = tactics.stream().map(t -> maskingService.maskViewerText(t, false)).toList();
            }
            if (attackId != null || name != null) {
                items.add(new IncidentDetailView.AttackCandidateItem(
                        attackId != null ? attackId : "-",
                        name != null ? name : "-",
                        tactics
                ));
            }
        }
        return Collections.unmodifiableList(items);
    }

    private List<IncidentDetailView.FactItem> resolveFacts(JsonNode factIdsNode,
                                                            Map<String, IncidentDetailView.FactItem> factIndex,
                                                            boolean mask) {
        List<String> ids = extractTextArray(factIdsNode);
        if (ids.isEmpty()) {
            return List.of();
        }
        List<IncidentDetailView.FactItem> resolved = new ArrayList<>(ids.size());
        for (String id : ids) {
            IncidentDetailView.FactItem found = factIndex.get(id);
            if (found != null) {
                resolved.add(found);
            } else {
                String safeId = mask ? maskingService.maskIpsInText(id) : id;
                resolved.add(new IncidentDetailView.FactItem(safeId, "근거 정보 없음", "-", null));
            }
        }
        return Collections.unmodifiableList(resolved);
    }

    private IncidentDetailView.SendDecisionView buildSendDecisionView(SendDecision decision, UserRole role) {
        if (decision == null) {
            return IncidentDetailView.SendDecisionView.absent();
        }
        boolean mask = maskingService.shouldMask(role);
        List<String> reasons = extractTextArray(decision.getPolicyReasons());
        if (mask) {
            reasons = reasons.stream().map(r -> maskingService.maskViewerText(r, true)).toList();
        }

        Map<String, Double> probs = new LinkedHashMap<>();
        if (decision.getDecisionModelProbabilities() != null && decision.getDecisionModelProbabilities().isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = decision.getDecisionModelProbabilities().fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (entry.getKey() != null && entry.getValue() != null && entry.getValue().isNumber()) {
                    probs.put(entry.getKey(), entry.getValue().asDouble());
                }
            }
        }

        Set<String> distinctChoices = new LinkedHashSet<>();
        addNormalizedChoice(distinctChoices, decision.getPolicyChoice());
        addNormalizedChoice(distinctChoices, decision.getLlmChoice());
        addNormalizedChoice(distinctChoices, decision.getDecisionModelChoice());
        boolean opinionMismatch = distinctChoices.size() > 1;

        String modelError = mask
                ? maskingService.maskViewerText(decision.getDecisionModelError(), true)
                : decision.getDecisionModelError();

        return new IncidentDetailView.SendDecisionView(
                true,
                decision.getZeekadWouldSend(),
                decision.getZeekadDecidedBy(),
                decision.getPolicyId(),
                decision.getPolicyChoice(),
                decision.getPolicyMandatory(),
                reasons,
                decision.getLlmChoice(),
                decision.getDecisionModel(),
                decision.getDecisionModelChoice(),
                decision.getDecisionModelConfidence(),
                Collections.unmodifiableMap(probs),
                modelError,
                opinionMismatch
        );
    }

    private IncidentDetailView.AnalystReviewView buildAnalystReviewView(AnalystReviewItem review,
                                                                        UserRole role,
                                                                        Map<String, String> userDisplayMap) {
        if (review == null) {
            return IncidentDetailView.AnalystReviewView.absent();
        }
        AnalystReviewItem masked = maskingService.maskAnalystReviewItem(review, role);
        String analystDisplay = masked.getAnalyst() != null && !masked.getAnalyst().isBlank()
                ? incidentQueryService.formatActorDisplay(masked.getAnalyst(), userDisplayMap)
                : null;
        boolean pending = masked.isPending();
        boolean canDecide = pending && (role == UserRole.ANALYST || role == UserRole.ADMIN);
        Long reviewJobId = masked.getReviewJobId() != null ? masked.getReviewJobId() : masked.getJobId();
        return new IncidentDetailView.AnalystReviewView(
                true,
                reviewJobId,
                masked.getZeekadReviewReason(),
                masked.getRequestedAt(),
                masked.getZeekadReviewAction(),
                analystDisplay,
                masked.getDecidedAt(),
                masked.getZeekadReviewResumedAt(),
                masked.isResumeFailed(),
                pending,
                masked.getResumeStatusLabel(),
                canDecide
        );
    }

    /** 상세 Slack 탭의 행 목록(원래 순서)과 묶음 목록(처음 나온 순서) */
    private record SlackThreads(List<IncidentDetailView.SlackDeliveryView> deliveries,
                                List<IncidentDetailView.SlackThreadGroup> groups) {
    }

    /**
     * T40: 묶음은 원문 열쇠(부모가 있으면 부모 incident_id, 없으면 자기 incident_id)로 나누고 보이는 값만 가린다.
     * 머리를 볼 수 있다 = 머리가 자기 자신이거나, 머리의 incident_refs 행(읽기만)이 있고 그 캡처가 허용 캡처 안이다.
     * 볼 수 있는 묶음에만 머리 번호와 구성원 수(허용 캡처 안 최신 큐)를 낸다. 볼 수 없는 묶음은 threadKey·threadParent와
     * 페이로드 맨 위 zeekad_thread_parent를 응답 안 순서 표지(restricted-N)로 바꿔 머리의 식별자를 내보내지 않는다.
     */
    private SlackThreads buildSlackThreads(List<SlackDelivery> deliveries,
                                           String rawSelfId,
                                           DashboardUserPrincipal principal,
                                           UserRole role) {
        if (deliveries == null || deliveries.isEmpty()) {
            return new SlackThreads(List.of(), List.of());
        }
        boolean mask = maskingService.shouldMask(role);
        Map<String, List<Integer>> indexesByKey = new LinkedHashMap<>();
        String[] rawParents = new String[deliveries.size()];
        for (int i = 0; i < deliveries.size(); i++) {
            SlackDelivery d = deliveries.get(i);
            String rawParent = (d.getZeekadThreadParent() != null && !d.getZeekadThreadParent().isBlank())
                    ? d.getZeekadThreadParent().trim()
                    : null;
            rawParents[i] = rawParent;
            String ownId = d.getIncidentId() != null ? d.getIncidentId() : rawSelfId;
            String rawKey = rawParent != null ? rawParent : ownId;
            indexesByKey.computeIfAbsent(rawKey != null ? rawKey : "", k -> new ArrayList<>()).add(i);
        }

        // 행 읽기 → 캡처 확인 → 그 뒤에만 번호를 낸다(번호 동기화·쓰기 없음)
        Map<String, IncidentRef> refs = incidentRefService.readRefsOnly(indexesByKey.keySet());
        List<String> allowed = captureAccessService.listAllowedCaptures(principal);

        IncidentDetailView.SlackDeliveryView[] views = new IncidentDetailView.SlackDeliveryView[deliveries.size()];
        List<IncidentDetailView.SlackThreadGroup> groups = new ArrayList<>(indexesByKey.size());
        int restrictedSeq = 0;
        for (Map.Entry<String, List<Integer>> entry : indexesByKey.entrySet()) {
            String rawKey = entry.getKey();
            boolean self = rawKey.equals(rawSelfId);
            IncidentRef ref = refs.get(rawKey);
            boolean visible = self
                    || (ref != null && ref.getCaptureId() != null && allowed.contains(ref.getCaptureId()));
            Long headNo = visible && ref != null ? ref.getIncidentNo() : null;
            long memberCount = visible
                    ? slackThreadService.countVisibleMembers(allowed, slackThreadService.memberIds(rawKey))
                    : 0L;
            String restricted = null;
            if (!visible) {
                restrictedSeq++;
                restricted = "restricted-" + restrictedSeq;
            }
            String displayKey = visible ? (mask ? maskingService.maskIpsInText(rawKey) : rawKey) : restricted;

            List<IncidentDetailView.SlackDeliveryView> groupViews = new ArrayList<>(entry.getValue().size());
            for (int i : entry.getValue()) {
                views[i] = toSlackDeliveryView(deliveries.get(i), rawParents[i], displayKey, restricted, role);
                groupViews.add(views[i]);
            }
            groups.add(new IncidentDetailView.SlackThreadGroup(
                    displayKey, Collections.unmodifiableList(groupViews), self, headNo, memberCount));
        }
        return new SlackThreads(List.of(views), Collections.unmodifiableList(groups));
    }

    private IncidentDetailView.SlackDeliveryView toSlackDeliveryView(SlackDelivery d,
                                                                     String rawThreadParent,
                                                                     String displayThreadKey,
                                                                     String restricted,
                                                                     UserRole role) {
        String threadRoleLabel;
        if (rawThreadParent == null) {
            threadRoleLabel = "최초 알림";
        } else if (rawThreadParent.equals(d.getIncidentId())) {
            threadRoleLabel = "후속 알림";
        } else {
            threadRoleLabel = "다른 인시던트의 후속 알림";
        }
        SlackDelivery masked = maskingService.maskSlackDelivery(d, role);
        String displayThreadParent;
        if (rawThreadParent == null) {
            displayThreadParent = null;
        } else if (restricted != null) {
            displayThreadParent = restricted;
        } else {
            displayThreadParent = (masked.getZeekadThreadParent() != null && !masked.getZeekadThreadParent().isBlank())
                    ? masked.getZeekadThreadParent()
                    : null;
        }
        JsonNode payload = masked.getSlackPayload();
        if (restricted != null && payload instanceof ObjectNode obj && obj.has(PAYLOAD_THREAD_PARENT)) {
            ObjectNode copy = obj.deepCopy();
            copy.put(PAYLOAD_THREAD_PARENT, restricted);
            payload = copy;
        }
        return new IncidentDetailView.SlackDeliveryView(
                masked.getJobId(),
                masked.getZeekadMessageKind(),
                masked.getZeekadMessageVersion(),
                masked.getZeekadDeliveryMode(),
                masked.getZeekadDeliveryStatus(),
                masked.isDryRunOrRecorded(),
                masked.getSlackTs(),
                masked.getDeliveredAt(),
                masked.getError(),
                masked.getCreatedAt(),
                prettyJson(payload),
                displayThreadParent,
                displayThreadKey,
                threadRoleLabel,
                masked.isReplyBroadcast()
        );
    }

    private String resolveStatus(IncidentStatus status, IncidentQueueItem queueItem) {
        if (status != null && status.getZeekadStatus() != null && !status.getZeekadStatus().isBlank()) {
            return status.getZeekadStatus().trim().toLowerCase(Locale.ROOT);
        }
        if (queueItem != null && queueItem.getZeekadStatus() != null && !queueItem.getZeekadStatus().isBlank()) {
            return queueItem.getZeekadStatus().trim().toLowerCase(Locale.ROOT);
        }
        return "open";
    }

    private String resolveNextAllowedStatus(String currentStatus) {
        if ("open".equals(currentStatus)) {
            return "investigating";
        }
        if ("investigating".equals(currentStatus)) {
            return "closed";
        }
        return null;
    }

    private String annotateText(String text, Map<String, String> pseudonyms, UserRole role) {
        if (text == null) {
            return null;
        }
        return pseudonymAnnotator.annotate(text, pseudonyms, role);
    }

    private List<String> annotateTextList(List<String> list, Map<String, String> pseudonyms, UserRole role) {
        if (list == null || list.isEmpty()) {
            return List.of();
        }
        return list.stream()
                .map(item -> annotateText(item, pseudonyms, role))
                .toList();
    }

    private List<String> extractTextArray(JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isArray()) {
            List<String> list = new ArrayList<>();
            for (JsonNode child : node) {
                String text = nodeValueToString(child);
                if (text != null && !text.isBlank()) {
                    list.add(text);
                }
            }
            return Collections.unmodifiableList(list);
        }
        String single = nodeValueToString(node);
        return (single == null || single.isBlank()) ? List.of() : List.of(single);
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        String val = node.isTextual() ? node.asText() : node.toString();
        return val.isBlank() ? null : val;
    }

    private String nodeValueToString(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            return node.asText();
        }
        return node.toString();
    }

    private void addNormalizedChoice(Set<String> choices, String choice) {
        if (choice != null && !choice.isBlank()) {
            choices.add(choice.trim().toLowerCase(Locale.ROOT));
        }
    }

    private String prettyJson(JsonNode node) {
        if (node == null || node.isNull()) {
            return "{}";
        }
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(node);
        } catch (JsonProcessingException e) {
            return node.toString();
        }
    }
}
