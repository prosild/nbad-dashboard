package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentModelScore;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 사건 상세 화면(/incidents/{jobId}/rank/{queueRank}) 렌더링용 불변 View DTO 모음.
 */
public record IncidentDetailView(
        IncidentQueueItem incident,
        ScoringJob job,
        List<IncidentModelScore> modelScores,
        List<AssetNameRecord> assetNames,
        EvidenceView evidence,
        ReportView report,
        SendDecisionView sendDecision,
        List<SlackDeliveryView> slackDeliveries,
        List<SlackThreadGroup> slackThreadGroups,
        AnalystReviewView analystReview,
        String currentStatus,
        String currentResolution,
        OffsetDateTime statusUpdatedAt,
        String statusUpdatedByDisplay,
        List<StatusHistoryItem> statusHistory,
        boolean canTransition,
        String nextAllowedStatus
) {

    /** 프로토콜 로그 하위 수치. metrics가 null이면 근거에 그 프로토콜 키가 없었다(0과 구분). */
    public record ProtocolLogEntry(String protocol, Map<String, Object> metrics) {
    }

    public record EvidenceView(
            boolean available,
            String statusMessage,
            Long connectionCount,
            Long bytesSent,
            Long bytesReceived,
            Long payloadBytesInflated,
            Map<String, Object> transportCounts,
            Map<String, Object> serviceProtocolCounts,
            Map<String, Object> connStateCounts,
            List<Map<String, Object>> topPeers,
            Long uniquePeers,
            List<Map<String, Object>> topPorts,
            Long uniquePorts,
            List<ProtocolLogEntry> protocolLogs,
            List<Map<String, Object>> representativeConnections,
            List<String> limits,
            Map<String, Object> additionalFields
    ) {
        public static EvidenceView unavailable(String statusMessage) {
            return new EvidenceView(
                    false, statusMessage, null, null, null, null,
                    Map.of(), Map.of(), Map.of(), List.of(), null, List.of(), null,
                    List.of(), List.of(), List.of(), Map.of()
            );
        }
    }

    /**
     * 근거 사실 한 건. value는 화면 호환용 글(객체·배열은 JSON 글), valueJson은 T37 구조 값(역할별 마스킹,
     * 조회자는 글 잎과 객체 키의 IPv4를 가림). 가린 키가 겹치거나 값이 없으면 valueJson은 null이다.
     */
    public record FactItem(String id, String name, String value, JsonNode valueJson) {
    }

    public record ClaimItem(String claim, List<FactItem> facts) {
    }

    public record ExplanationItem(String explanation, List<FactItem> facts, List<String> attackIds) {
    }

    public record SendRecommendationItem(String choice, String reason, List<FactItem> facts) {
    }

    public record AttackCandidateItem(String attackId, String name, List<String> tactics) {
    }

    public record ReportView(
            boolean present,
            String reportKind,
            String reportVersion,
            String inputVersion,
            String llmModelRequested,
            String llmModelVersion,
            Double llmSeconds,
            Integer llmInputTokens,
            Integer llmOutputTokens,
            Integer llmThinkingTokens,
            String llmError,
            Boolean verificationPassed,
            String verificationReason,
            List<String> verificationProblems,
            OffsetDateTime createdAt,
            String sourceRun,
            Map<String, String> pseudonyms,
            String observationSummary,
            List<ClaimItem> claims,
            List<ExplanationItem> possibleExplanations,
            SendRecommendationItem sendRecommendation,
            List<String> limitations,
            List<String> followUp,
            List<AttackCandidateItem> attackCandidates,
            // T37: 근거 사실 전체(원래 순서, 인용 여부와 무관, 같은 id도 모두). 역할별 마스킹은 facts와 같다.
            List<FactItem> allFacts,
            // T37: 검증 문제 구조 목록. 객체 항목은 {kind, value, where …}(조회자는 키·글 잎 IPv4 가림), 그 밖은 글.
            List<JsonNode> verificationProblemItems
    ) {
        public static ReportView absent() {
            return new ReportView(
                    false, null, null, null, null, null, null, null, null, null, null,
                    null, null, List.of(), null, null, Map.of(), null,
                    List.of(), List.of(), null, List.of(), List.of(), List.of(),
                    List.of(), List.of()
            );
        }
    }

    public record SendDecisionView(
            boolean present,
            Boolean wouldSend,
            String decidedBy,
            String policyId,
            String policyChoice,
            Boolean policyMandatory,
            List<String> policyReasons,
            String llmChoice,
            String decisionModel,
            String decisionModelChoice,
            Double decisionModelConfidence,
            Map<String, Double> decisionModelProbabilities,
            String decisionModelError,
            boolean opinionMismatch
    ) {
        public static SendDecisionView absent() {
            return new SendDecisionView(
                    false, null, null, null, null, null, List.of(),
                    null, null, null, null, Map.of(), null, false
            );
        }
    }

    public record SlackDeliveryView(
            Long jobId,
            String messageKind,
            String messageVersion,
            String deliveryMode,
            String deliveryStatus,
            boolean dryRunOrRecorded,
            String slackTs,
            OffsetDateTime deliveredAt,
            String error,
            OffsetDateTime createdAt,
            String payloadJson,
            String threadParent,
            String threadKey,
            String threadRoleLabel,
            boolean replyBroadcast
    ) {
    }

    /**
     * 알림 묶음 하나. T40: headIsSelf = 묶음 머리가 지금 인시던트, headIncidentNo = 머리를 볼 수 있을 때만 머리 번호,
     * memberCount = 머리를 볼 수 있을 때 묶음 인시던트 가운데 허용 캡처 안 최신 큐에 있는 수(볼 수 없으면 0).
     * 머리를 볼 수 없는 묶음의 threadKey는 restricted-N 표지다.
     */
    public record SlackThreadGroup(
            String threadKey,
            List<SlackDeliveryView> deliveries,
            boolean headIsSelf,
            Long headIncidentNo,
            long memberCount
    ) {
    }

    public record AnalystReviewView(
            boolean present,
            Long reviewJobId,
            String reviewReason,
            OffsetDateTime requestedAt,
            String reviewAction,
            String analystDisplay,
            OffsetDateTime decidedAt,
            OffsetDateTime resumedAt,
            boolean resumeFailed,
            boolean pending,
            String resumeStatusLabel,
            boolean canDecide
    ) {
        public static AnalystReviewView absent() {
            return new AnalystReviewView(
                    false, null, null, null, null, null, null, null, false, false, null, false
            );
        }
    }

    public record StatusHistoryItem(
            Long jobId,
            String fromStatus,
            String toStatus,
            String resolution,
            String actorDisplay,
            String reason,
            OffsetDateTime changedAt
    ) {
    }
}
