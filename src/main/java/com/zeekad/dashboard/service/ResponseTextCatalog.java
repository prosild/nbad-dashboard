package com.zeekad.dashboard.service;

import java.util.List;

/**
 * T63 응답별 글자 칸 규칙(닫힌 식별자 목록과 칸 종류). 규칙에 없는 글자 값은 "값"(1,000) 정책이다.
 *
 * <p>식별자(표지·상한을 적용하지 않음, 조회자 가림은 지금 그대로): incidentId, captureId, bundleId, hostIp, threadKey, threadParent,
 * slackTs, sourceRun·zeekadSourceRun, zeekadPickedBy·zeekadAlsoFlaggedBy의 원소와 모델 이름, ATT&amp;CK ID(attackId, attackIds, 후보 ID),
 * 열거값(상태·판정·역할·우선순위·보고서 종류·조치 종류 등), 사실 ID, 가명표의 키. 숫자 칸은 글자가 아니라 처음부터 바뀌지 않는다.
 * 근거·Slack 페이로드·구조 값 같은 자유 나무 안의 키는 이름이 같아도 식별자로 보지 않는다(경로로 적는다).
 */
public final class ResponseTextCatalog {

    private ResponseTextCatalog() {
    }

    /* ───────────────────────── 여러 응답이 같이 쓰는 모양 ───────────────────────── */

    /** 큐 행(IncidentQueueItem, 분석가는 UnifiedQueueRecord가 펼쳐진다) */
    private static ResponseTextRules queueItem() {
        return ResponseTextRules.named("queue-item")
                .skip("incidentId", "captureId", "bundleId", "hostIp", "zeekadRole", "zeekadPickedBy",
                        "zeekadAlsoFlaggedBy[]", "zeekadStatus", "zeekadResolution", "zeekadReportKind",
                        "zeekadReviewAction", "priority")
                .name("hostName[]");
    }

    /** 탐지 작업(ScoringJob, 현황판 JobRef) */
    private static ResponseTextRules job() {
        return ResponseTextRules.named("job")
                .skip("captureId", "bundleId", "status")
                .text("error");
    }

    /** 담당자(AssignmentDtos.Assignee): 표시 이름은 관리자가 정한 이름 */
    private static ResponseTextRules assignee() {
        return ResponseTextRules.named("assignee").name("displayName");
    }

    /** 수집원 선택지(UnifiedQueueResponse.Source) */
    private static ResponseTextRules sources() {
        return ResponseTextRules.named("sources").skip("[].captureId", "[].sourceType");
    }

    /** 근거 사실(FactItem): id는 사실 ID, name은 값, value와 구조 값의 잎은 글 */
    private static ResponseTextRules fact() {
        return ResponseTextRules.named("fact")
                .skip("id")
                .text("value", "valueJson", "valueJson.**");
    }

    /** 상세 Slack 행(SlackDeliveryView): payloadJson은 글 안의 JSON */
    private static ResponseTextRules slackDelivery() {
        return ResponseTextRules.named("slack-delivery")
                .skip("messageKind", "messageVersion", "deliveryMode", "deliveryStatus", "slackTs", "threadParent", "threadKey")
                .text("error")
                .embeddedJsonPretty("payloadJson");
    }

    /* ───────────────────────── 응답 ───────────────────────── */

    /** GET /api/incidents/queue (UnifiedQueueResponse). 분석가 행은 priority·detectedAt 키가 두 번 나온다(둘 다 같은 규칙) */
    public static final ResponseTextRules QUEUE = ResponseTextRules.named("queue")
            .mount("items[]", queueItem())
            .skip("items[].sourceType")
            .mount("items[].assignee", assignee())
            .skip("anchorMode", "period", "availableModels[]", "availableRoles[]")
            .mount("sources", sources())
            .skipKeys("summary.byStatus");

    /** GET /api/incidents/queue/neighbors */
    public static final ResponseTextRules QUEUE_NEIGHBORS = ResponseTextRules.named("queue-neighbors")
            .skip("current.hostIp", "prev.hostIp", "next.hostIp");

    /** GET /api/incidents/queue/new-count (글자 값은 시각뿐) */
    public static final ResponseTextRules QUEUE_NEW_COUNT = ResponseTextRules.named("queue-new-count");

    /** GET /api/incidents (옛 목록 API, IncidentQueueResponse) */
    public static final ResponseTextRules LEGACY_LIST = ResponseTextRules.named("legacy-list")
            .skip("allowedCaptures[]", "selectedCaptureId", "availableModels[]", "availableRoles[]")
            .mount("selectedJob", job())
            .mount("captureJobs[]", job())
            .mount("incidents[]", queueItem());

    /** GET /api/incidents/{jobId}/rank/{queueRank} (IncidentDetailApiResponse) */
    public static final ResponseTextRules DETAIL = ResponseTextRules.named("detail")
            .mount("detail.incident", queueItem())
            .mount("detail.job", job())
            .skip("detail.modelScores[].incidentId", "detail.modelScores[].zeekadModel")
            .skip("detail.assetNames[].captureId", "detail.assetNames[].hostIp")
            .name("detail.assetNames[].kerberosUser", "detail.assetNames[].ntlmUser", "detail.assetNames[].extraAttributes.**")
            // 보고서
            .skip("detail.report.reportKind", "detail.report.llmModelRequested", "detail.report.llmModelVersion",
                    "detail.report.sourceRun")
            .text("detail.report.llmError", "detail.report.verificationReason", "detail.report.verificationProblems[]",
                    "detail.report.observationSummary", "detail.report.claims[].claim",
                    "detail.report.possibleExplanations[].explanation", "detail.report.sendRecommendation.reason",
                    "detail.report.limitations[]", "detail.report.followUp[]",
                    "detail.report.verificationProblemItems[]", "detail.report.verificationProblemItems[].**")
            .skip("detail.report.possibleExplanations[].attackIds[]", "detail.report.sendRecommendation.choice",
                    "detail.report.attackCandidates[].attackId")
            .mount("detail.report.claims[].facts[]", fact())
            .mount("detail.report.possibleExplanations[].facts[]", fact())
            .mount("detail.report.sendRecommendation.facts[]", fact())
            .mount("detail.report.allFacts[]", fact())
            .skipKeys("detail.report.pseudonyms")
            // 발송 판단
            .skip("detail.sendDecision.decidedBy", "detail.sendDecision.policyChoice", "detail.sendDecision.llmChoice",
                    "detail.sendDecision.decisionModel", "detail.sendDecision.decisionModelChoice")
            .text("detail.sendDecision.policyReasons[]", "detail.sendDecision.decisionModelError")
            .skipKeys("detail.sendDecision.decisionModelProbabilities")
            // Slack
            .mount("detail.slackDeliveries[]", slackDelivery())
            .mount("detail.slackThreadGroups[].deliveries[]", slackDelivery())
            .skip("detail.slackThreadGroups[].threadKey")
            // 에스컬레이션
            .skip("detail.analystReview.reviewAction")
            .text("detail.analystReview.reviewReason")
            .name("detail.analystReview.analystDisplay")
            // 상태·이력
            .skip("detail.currentStatus", "detail.currentResolution", "detail.nextAllowedStatus",
                    "detail.statusHistory[].fromStatus", "detail.statusHistory[].toStatus", "detail.statusHistory[].resolution")
            .name("detail.statusUpdatedByDisplay", "detail.statusHistory[].actorDisplay")
            .text("detail.statusHistory[].reason")
            .skip("queueMeta.sourceType", "queueMeta.priority")
            // 담당·대응 조치(사람이 쓴 글)
            .mount("assignment.assignee", assignee())
            .name("assignment.assignedByDisplay")
            .mount("assignmentHistory[].from", assignee())
            .mount("assignmentHistory[].to", assignee())
            .name("assignmentHistory[].actorDisplay")
            .skip("assignmentHistory[].reason")
            .skip("responseActions[].action")
            .text("responseActions[].note")
            .name("responseActions[].actorDisplay");

    /** GET /api/incidents/{jobId}/rank/{queueRank}/related-host-incidents */
    public static final ResponseTextRules RELATED_HOST = ResponseTextRules.named("related-host")
            .skip("hostIp", "items[].captureId", "items[].hostIp", "items[].zeekadRole", "items[].priority",
                    "items[].zeekadStatus", "items[].zeekadResolution", "items[].zeekadPickedBy");

    /** GET /api/hosts (HostRiskResponse) */
    public static final ResponseTextRules HOST_RISK = ResponseTextRules.named("host-risk")
            .skip("items[].hostIp", "items[].models[]", "anchorMode", "period")
            .name("items[].hostNames[]", "items[].accounts[]")
            .mount("sources", sources());

    /** GET /api/dashboard/overview (DashboardOverviewResponse). TechniqueCount.name은 값 */
    public static final ResponseTextRules OVERVIEW = ResponseTextRules.named("overview")
            .skip("anchorMode", "period", "trend.bucket")
            .skip("sensors[].health", "sensors[].activeCaptureId")
            .mount("sensors[].latestJob", job())
            .skip("captures[].captureId", "captures[].sourceType", "captures[].state")
            .mount("captures[].latestJob", job())
            .skip("alerting.latestDeliveryMode", "alerting.latestDeliveryStatus", "alerting.latestCaptureId")
            .skip("attack.techniques[].attackId")
            .skip("topHosts.originator[].hostIp", "topHosts.responder[].hostIp")
            .skip("topThreads[].headHostIp", "topThreads[].headPickedBy");

    /** GET /api/operations (OperationsApiResponse). Slack 요약의 페이로드 잎은 글 */
    public static final ResponseTextRules OPERATIONS = ResponseTextRules.named("operations")
            .skip("allowedCaptures[]", "selectedCaptureId", "period")
            .mount("jobs[]", job())
            .skip("bundles[].bundleId")
            .skipKeys("bundles[].thresholdEntries", "bundles[].thresholds")
            .skip("feedbackSummaries[].captureId", "feedbackSummaries[].bundleId", "feedbackSummaries[].zeekadPickedBy")
            .skip("slackSummaries[].captureId", "slackSummaries[].zeekadMessageVersion",
                    "slackSummaries[].zeekadDeliveryMode", "slackSummaries[].zeekadDeliveryStatus", "slackSummaries[].slackTs")
            .text("slackSummaries[].slackPayload", "slackSummaries[].slackPayload.**",
                    "slackSummaries[].payloadTextPreview", "slackSummaries[].payloadChannel")
            .skip("latestJobs[].captureId")
            .mount("latestJobs[].latestEnded", job())
            .mount("latestJobs[].latestSucceeded", job())
            .mount("sources", sources())
            .skip("handlingTimes.resolve.byResolution[].resolution")
            .name("workload.byAssignee[].displayName");

    /** GET /api/reviews (ReviewsApiResponse, 에스컬레이션 목록) */
    public static final ResponseTextRules REVIEWS = ResponseTextRules.named("reviews")
            .skip("allowedCaptures[]", "selectedCaptureId")
            .skip("reviews[].captureId", "reviews[].incidentId", "reviews[].hostIp", "reviews[].zeekadRole",
                    "reviews[].zeekadReviewAction")
            .text("reviews[].zeekadReviewReason")
            .name("reviews[].analystDisplay");

    /** GET /api/admin/audit-logs (관리자만). 행위자·되돌려 주는 검색어는 이름, detail은 글 안의 JSON */
    public static final ResponseTextRules AUDIT_LOGS = ResponseTextRules.named("audit-logs")
            .name("logs[].actorUsername", "selectedActorUsername")
            .skip("logs[].actorRole", "logs[].actionType", "actionTypes[]")
            .embeddedJsonCompact("logs[].detailJson");

    /** GET /api/incidents/{jobId}/rank/{queueRank}/assignees */
    public static final ResponseTextRules ASSIGNEE_CANDIDATES = ResponseTextRules.named("assignee-candidates")
            .name("assignees[].displayName");

    /** POST /api/incidents/{jobId}/rank/{queueRank}/assignment 성공 응답 */
    public static final ResponseTextRules ASSIGN_RESULT = ResponseTextRules.named("assign-result")
            .mount("assignment.assignee", assignee())
            .name("assignment.assignedByDisplay");

    /** 증거 파일(handoff/T63/evidence/identifier-list.txt)용 목록 */
    public static final List<ResponseTextRules> ALL = List.of(QUEUE, QUEUE_NEIGHBORS, QUEUE_NEW_COUNT, LEGACY_LIST, DETAIL,
            RELATED_HOST, HOST_RISK, OVERVIEW, OPERATIONS, REVIEWS, AUDIT_LOGS, ASSIGNEE_CANDIDATES, ASSIGN_RESULT);
}
