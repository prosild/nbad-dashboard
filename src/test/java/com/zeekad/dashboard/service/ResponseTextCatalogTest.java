package com.zeekad.dashboard.service;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T63 식별자는 닫힌 목록이다: 규칙이 SKIP으로 빼는 칸은 인계의 식별자 종류에만 든다.
 * 뺀 칸의 JSON 경로를 build/t63/identifier-list.txt에 적는다(handoff/T63/evidence/identifier-list.txt의 원본).
 */
class ResponseTextCatalogTest {

    /** 인계 1절의 식별자 종류 → 그 종류에 드는 칸 이름(경로의 마지막 이름) */
    private static final Map<String, Set<String>> CATEGORIES = new LinkedHashMap<>();

    static {
        CATEGORIES.put("incidentId", Set.of("incidentId"));
        CATEGORIES.put("captureId(허용 캡처·선택 캡처 포함)", Set.of("captureId", "allowedCaptures", "selectedCaptureId",
                "activeCaptureId", "latestCaptureId"));
        CATEGORIES.put("bundleId", Set.of("bundleId"));
        CATEGORIES.put("hostIp", Set.of("hostIp", "headHostIp"));
        CATEGORIES.put("threadKey·threadParent", Set.of("threadKey", "threadParent"));
        CATEGORIES.put("slackTs", Set.of("slackTs"));
        CATEGORIES.put("sourceRun", Set.of("sourceRun"));
        CATEGORIES.put("zeekadPickedBy·zeekadAlsoFlaggedBy의 원소와 모델 이름", Set.of("zeekadPickedBy", "zeekadAlsoFlaggedBy",
                "headPickedBy", "availableModels", "models", "zeekadModel", "llmModelRequested", "llmModelVersion",
                "decisionModel"));
        CATEGORIES.put("ATT&CK ID", Set.of("attackId", "attackIds"));
        CATEGORIES.put("사실 ID", Set.of("id"));
        CATEGORIES.put("열거값", Set.of("zeekadRole", "availableRoles", "zeekadStatus", "zeekadResolution", "zeekadReportKind",
                "zeekadReviewAction", "priority", "priorityBase", "sourceType", "anchorMode", "period", "status", "bucket", "health", "state",
                "messageKind", "messageVersion", "deliveryMode", "deliveryStatus", "zeekadMessageVersion",
                "zeekadDeliveryMode", "zeekadDeliveryStatus", "latestDeliveryMode", "latestDeliveryStatus", "reportKind",
                "choice", "decidedBy", "policyChoice", "llmChoice", "decisionModelChoice", "reviewAction", "currentStatus",
                "currentResolution", "nextAllowedStatus", "fromStatus", "toStatus", "resolution", "reason", "action",
                "actorRole", "actionType", "actionTypes"));
    }

    /** 키를 빼는 Map(키가 식별자): 가명표 키, 열거값 키, 모델 이름 키 */
    private static final Set<String> KEY_MAPS = Set.of("summary.byStatus", "detail.report.pseudonyms",
            "detail.sendDecision.decisionModelProbabilities", "bundles[].thresholdEntries", "bundles[].thresholds");

    @Test
    void everySkippedPathIsAnIdentifierFromTheClosedListAndTheListIsWrittenAsEvidence() throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("# T63 식별자 목록(표지·상한을 적용하지 않는 칸, 조회자 가림은 지금 그대로). 응답마다 JSON 경로.");
        lines.add("# 원본: src/main/java/com/zeekad/dashboard/service/ResponseTextCatalog.java (ResponseTextCatalogTest가 적는다)");
        lines.add("# 경로 꼴: 점으로 잇고 배열 원소는 []. \"(키)\"는 그 Map의 키를 뺀다는 뜻. 숫자·참거짓 칸은 글자가 아니라 처음부터 바뀌지 않는다.");
        lines.add("# 목록에 없는 글자 값은 모두 정책을 거친다(기본 \"값\" 1,000).");
        for (ResponseTextRules rules : ResponseTextCatalog.ALL) {
            lines.add("");
            lines.add("## " + rules.name());
            for (String skip : rules.describeSkips()) {
                if (skip.endsWith(" (키)")) {
                    String map = skip.substring(0, skip.length() - " (키)".length());
                    assertThat(KEY_MAPS).as("키를 빼는 Map %s", map).contains(map);
                    lines.add("- " + skip + "  [키가 식별자인 Map]");
                    continue;
                }
                String last = lastName(skip);
                String category = CATEGORIES.entrySet().stream()
                        .filter(e -> e.getValue().contains(last)).map(Map.Entry::getKey).findFirst().orElse(null);
                assertThat(category).as("%s: %s는 인계의 식별자 종류가 아니다", rules.name(), skip).isNotNull();
                lines.add("- " + skip + "  [" + category + "]");
            }
            List<String> kinds = rules.describeKinds();
            if (!kinds.isEmpty()) {
                lines.add("  종류를 정한 칸(식별자 아님): " + String.join(", ", kinds));
            }
        }
        Path out = Path.of("build", "t63", "identifier-list.txt");
        Files.createDirectories(out.getParent());
        Files.write(out, lines, StandardCharsets.UTF_8);
    }

    private static String lastName(String path) {
        String[] parts = path.split("\\.");
        String last = parts[parts.length - 1];
        while (last.endsWith("[]")) {
            last = last.substring(0, last.length() - 2);
        }
        return last;
    }
}
