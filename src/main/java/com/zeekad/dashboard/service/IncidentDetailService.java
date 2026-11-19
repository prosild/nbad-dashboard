package com.zeekad.dashboard.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceApiClient;
import com.zeekad.dashboard.client.EvidenceApiResponse;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
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

    private static final List<String> PROTOCOL_LOG_KEYS = List.of(
            "dns", "http", "tls", "ssh", "ftp", "smb", "kerberos", "dce_rpc", "ntlm"
    );

    private static final Set<String> STANDARD_EVIDENCE_KEYS = Set.of(
            "connection_count", "connections",
            "orig_bytes", "bytes_sent",
            "resp_bytes", "bytes_received",
            "transport_counts", "protocols",
            "conn_state_counts", "conn_states",
            "peers", "top_peers",
            "ports", "top_ports",
            "protocol_counts",
            "dns", "http", "tls", "ssh", "ftp", "smb", "kerberos", "dce_rpc", "ntlm",
            "representative_connections",
            "limitations"
    );

    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final IncidentQueryService incidentQueryService;
    private final EvidenceApiClient evidenceApiClient;
    private final MaskingService maskingService;
    private final PseudonymAnnotator pseudonymAnnotator;
    private final ObjectMapper objectMapper;

    public IncidentDetailService(ZeekadReadMapper zeekadReadMapper,
                                 CaptureAccessService captureAccessService,
                                 IncidentQueryService incidentQueryService,
                                 EvidenceApiClient evidenceApiClient,
                                 MaskingService maskingService,
                                 PseudonymAnnotator pseudonymAnnotator,
                                 ObjectMapper objectMapper) {
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

        ScoringJob job = zeekadReadMapper.findScoringJobById(jobId);
        List<IncidentModelScore> modelScores = zeekadReadMapper.findModelScores(jobId, rawIncident.getIncidentId());
        List<AssetNameRecord> assetNames = incidentQueryService.findAssetNames(
                rawIncident.getCaptureId(), rawIncident.getHostIp(), role);

        IncidentQueueItem displayIncident = maskingService.maskIncidentQueueItem(rawIncident, role);

        EvidenceApiResponse apiResponse = evidenceApiClient.fetchIncidentEvidence(jobId, queueRank);
        IncidentDetailView.EvidenceView evidenceView = buildEvidenceView(apiResponse, role);

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
        List<IncidentDetailView.SlackDeliveryView> deliveryViews = buildSlackDeliveryViews(rawDeliveries, role);
        List<IncidentDetailView.SlackThreadGroup> threadGroups = groupSlackDeliveries(deliveryViews);

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
                        maskingService.shouldMask(role) ? maskingService.maskIpsInText(h.getReason()) : h.getReason(),
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

    private IncidentDetailView.EvidenceView buildEvidenceView(EvidenceApiResponse apiResponse, UserRole role) {
        if (apiResponse == null || !apiResponse.isAvailable() || apiResponse.getEvidence() == null
                || !apiResponse.getEvidence().isAvailable()) {
            return new IncidentDetailView.EvidenceView(
                    false,
                    EvidenceData.FALLBACK_MESSAGE,
                    null, null, null,
                    Map.of(), Map.of(), List.of(), List.of(), List.of(), List.of(), List.of(), Map.of()
            );
        }

        EvidenceData data = maskingService.maskEvidence(apiResponse.getEvidence(), role);
        List<IncidentDetailView.ProtocolCountEntry> protocols = new ArrayList<>(PROTOCOL_LOG_KEYS.size());
        Map<String, Object> rawProtoCounts = data.getProtocolCounts();
        for (String key : PROTOCOL_LOG_KEYS) {
            Object val = rawProtoCounts != null && rawProtoCounts.containsKey(key) ? rawProtoCounts.get(key) : 0;
            protocols.add(new IncidentDetailView.ProtocolCountEntry(key, val));
        }

        Map<String, Object> additional = new LinkedHashMap<>();
        if (data.getRawEvidence() != null) {
            for (Map.Entry<String, Object> entry : data.getRawEvidence().entrySet()) {
                if (entry.getKey() != null && !STANDARD_EVIDENCE_KEYS.contains(entry.getKey())) {
                    additional.put(entry.getKey(), entry.getValue());
                }
            }
        }

        return new IncidentDetailView.EvidenceView(
                true,
                data.getStatusMessage(),
                data.getConnectionCount(),
                data.getOrigBytes(),
                data.getRespBytes(),
                data.getTransportCounts(),
                data.getConnStateCounts(),
                data.getTopPeers(),
                data.getTopPorts(),
                Collections.unmodifiableList(protocols),
                data.getRepresentativeConnections(),
                data.getLimitations(),
                Collections.unmodifiableMap(additional)
        );
    }

    private IncidentDetailView.ReportView buildReportView(IncidentReport report, UserRole role) {
        if (report == null) {
            return IncidentDetailView.ReportView.absent();
        }
        boolean mask = maskingService.shouldMask(role);
        Map<String, String> pseudonyms = pseudonymAnnotator.buildEffectivePseudonymMap(
                report.getZeekadPseudonyms(), role);
        Map<String, IncidentDetailView.FactItem> factIndex = parseFacts(report.getZeekadFacts(), mask);

        JsonNode body = report.getZeekadReport();
        String observationSummary = null;
        List<IncidentDetailView.ClaimItem> claims = List.of();
        List<IncidentDetailView.ExplanationItem> explanations = List.of();
        IncidentDetailView.SendRecommendationItem sendRecommendation = null;
        List<String> limitations = List.of();
        List<String> followUp = List.of();

        if (body != null && body.isObject()) {
            observationSummary = annotateText(textOrNull(body.get("observation_summary")), pseudonyms, role);
            claims = parseClaims(body.get("claims"), pseudonyms, factIndex, role);
            explanations = parseExplanations(body.get("possible_explanations"), pseudonyms, factIndex, role);
            sendRecommendation = parseSendRecommendation(body.get("send_recommendation"), pseudonyms, factIndex, role);
            limitations = annotateTextList(extractTextArray(body.get("limitations")), pseudonyms, role);
            followUp = annotateTextList(extractTextArray(body.get("follow_up")), pseudonyms, role);
        }

        List<String> verificationProblems = extractTextArray(report.getZeekadVerificationProblems());
        if (mask) {
            verificationProblems = verificationProblems.stream()
                    .map(maskingService::maskIpsInText)
                    .toList();
        }

        String verificationReason = mask
                ? maskingService.maskIpsInText(report.getZeekadVerificationReason())
                : report.getZeekadVerificationReason();
        String llmError = mask
                ? maskingService.maskIpsInText(report.getLlmError())
                : report.getLlmError();

        List<IncidentDetailView.AttackCandidateItem> attackCandidates =
                parseAttackCandidates(report.getZeekadAttackCandidates());

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
                attackCandidates
        );
    }

    private Map<String, IncidentDetailView.FactItem> parseFacts(JsonNode factsNode, boolean mask) {
        if (factsNode == null || !factsNode.isArray()) {
            return Collections.emptyMap();
        }
        Map<String, IncidentDetailView.FactItem> index = new LinkedHashMap<>();
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
            String value = mask ? maskingService.maskIpsInText(rawVal) : rawVal;
            String safeName = name != null ? (mask ? maskingService.maskIpsInText(name) : name) : "-";
            index.put(id, new IncidentDetailView.FactItem(id, safeName, value != null ? value : "-"));
        }
        return Collections.unmodifiableMap(index);
    }

    private List<IncidentDetailView.ClaimItem> parseClaims(JsonNode claimsNode,
                                                           Map<String, String> pseudonyms,
                                                           Map<String, IncidentDetailView.FactItem> factIndex,
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
                    List<IncidentDetailView.FactItem> facts = resolveFacts(node.get("fact_ids"), factIndex);
                    items.add(new IncidentDetailView.ClaimItem(claimText, facts));
                }
            }
        }
        return Collections.unmodifiableList(items);
    }

    private List<IncidentDetailView.ExplanationItem> parseExplanations(JsonNode expNode,
                                                                       Map<String, String> pseudonyms,
                                                                       Map<String, IncidentDetailView.FactItem> factIndex,
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
                    List<IncidentDetailView.FactItem> facts = resolveFacts(node.get("fact_ids"), factIndex);
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
            UserRole role) {
        if (recNode == null || !recNode.isObject() || recNode.isEmpty()) {
            return null;
        }
        String choice = textOrNull(recNode.get("choice"));
        String reason = annotateText(textOrNull(recNode.get("reason")), pseudonyms, role);
        List<IncidentDetailView.FactItem> facts = resolveFacts(recNode.get("fact_ids"), factIndex);
        if (choice == null && reason == null && facts.isEmpty()) {
            return null;
        }
        return new IncidentDetailView.SendRecommendationItem(choice, reason, facts);
    }

    private List<IncidentDetailView.AttackCandidateItem> parseAttackCandidates(JsonNode candidatesNode) {
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
                                                            Map<String, IncidentDetailView.FactItem> factIndex) {
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
                resolved.add(new IncidentDetailView.FactItem(id, "근거 정보 없음", "-"));
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
            reasons = reasons.stream().map(maskingService::maskIpsInText).toList();
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
                ? maskingService.maskIpsInText(decision.getDecisionModelError())
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

    private List<IncidentDetailView.SlackDeliveryView> buildSlackDeliveryViews(List<SlackDelivery> deliveries,
                                                                               UserRole role) {
        if (deliveries == null || deliveries.isEmpty()) {
            return List.of();
        }
        boolean mask = maskingService.shouldMask(role);
        List<IncidentDetailView.SlackDeliveryView> views = new ArrayList<>(deliveries.size());
        for (SlackDelivery d : deliveries) {
            String rawThreadParent = (d.getZeekadThreadParent() != null && !d.getZeekadThreadParent().isBlank())
                    ? d.getZeekadThreadParent().trim()
                    : null;
            String rawIncidentId = d.getIncidentId();
            String threadRoleLabel;
            if (rawThreadParent == null) {
                threadRoleLabel = "머리 알림";
            } else if (rawThreadParent.equals(rawIncidentId)) {
                threadRoleLabel = "머리 사건 후속 답글";
            } else {
                threadRoleLabel = "스레드 답글";
            }
            String rawThreadKey = rawThreadParent != null ? rawThreadParent : rawIncidentId;
            String displayThreadKey = mask ? maskingService.maskIpsInText(rawThreadKey) : rawThreadKey;

            SlackDelivery masked = maskingService.maskSlackDelivery(d, role);
            String displayThreadParent = (masked.getZeekadThreadParent() != null && !masked.getZeekadThreadParent().isBlank())
                    ? masked.getZeekadThreadParent()
                    : null;
            views.add(new IncidentDetailView.SlackDeliveryView(
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
                    prettyJson(masked.getSlackPayload()),
                    displayThreadParent,
                    displayThreadKey,
                    threadRoleLabel,
                    masked.isReplyBroadcast()
            ));
        }
        return Collections.unmodifiableList(views);
    }

    private List<IncidentDetailView.SlackThreadGroup> groupSlackDeliveries(
            List<IncidentDetailView.SlackDeliveryView> deliveries) {
        if (deliveries == null || deliveries.isEmpty()) {
            return List.of();
        }
        Map<String, List<IncidentDetailView.SlackDeliveryView>> grouped = new LinkedHashMap<>();
        for (IncidentDetailView.SlackDeliveryView item : deliveries) {
            String key = item.threadKey() != null ? item.threadKey() : "-";
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(item);
        }
        List<IncidentDetailView.SlackThreadGroup> result = new ArrayList<>(grouped.size());
        for (Map.Entry<String, List<IncidentDetailView.SlackDeliveryView>> entry : grouped.entrySet()) {
            result.add(new IncidentDetailView.SlackThreadGroup(
                    entry.getKey(),
                    Collections.unmodifiableList(entry.getValue())
            ));
        }
        return Collections.unmodifiableList(result);
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
