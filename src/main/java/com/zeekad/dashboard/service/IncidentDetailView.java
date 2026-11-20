package com.zeekad.dashboard.service;

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

    public record FactItem(String id, String name, String value) {
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
            List<AttackCandidateItem> attackCandidates
    ) {
        public static ReportView absent() {
            return new ReportView(
                    false, null, null, null, null, null, null, null, null, null, null,
                    null, null, List.of(), null, null, Map.of(), null,
                    List.of(), List.of(), null, List.of(), List.of(), List.of()
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

    public record SlackThreadGroup(
            String threadKey,
            List<SlackDeliveryView> deliveries
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
