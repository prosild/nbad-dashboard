package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.dto.UnifiedQueueRow;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T63 응답 직전 구성요소: 깨끗한 값이면 응답이 바이트까지 그대로이고(칸 이름·형·순서, 분석가 큐 행의 겹친 키 포함),
 * 식별자는 손대지 않으며, 글 안의 JSON은 푼 잎에 정책을 적용한다.
 */
class ResponseTextGuardTest {

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final ResponseTextGuard guard = new ResponseTextGuard(objectMapper, new MaskingService(objectMapper));

    private UnifiedQueueResponse queue(String hostName, String incidentId, String display) {
        UnifiedQueueRecord r = new UnifiedQueueRecord();
        r.setJobId(1L);
        r.setQueueRank(1);
        r.setCaptureId("cic17-wed");
        r.setIncidentId(incidentId);
        r.setHostIp("10.0.0.1");
        r.setHostName(List.of(hostName));
        r.setZeekadPickedBy("iforest");
        r.setPriority("high");
        r.setDetectedAt(OffsetDateTime.parse("2026-11-26T10:00:00+09:00"));
        UnifiedQueueRow row = new UnifiedQueueRow(r, r.getDetectedAt(), "lab", "high", false,
                new AssignmentDtos.Assignee("kim", display, true), null, false, 7L);
        return new UnifiedQueueResponse(List.of(row), 1, 1, 50, 1,
                new UnifiedQueueResponse.Summary(1, 1, 0, 0, 0, 0, Map.of("open", 1L), 0),
                OffsetDateTime.parse("2026-11-26T10:00:00+09:00"), "now", false, "24h", null, null, null, null, 0L,
                List.of(new UnifiedQueueResponse.Source("cic17-wed", "lab", 1L, null)), false, List.of("iforest"),
                List.of("originator"));
    }

    private String write(Object o) throws Exception {
        return objectMapper.writeValueAsString(o);
    }

    @Test
    void cleanResponsesAreByteForByteUnchangedIncludingDuplicatedKeys() throws Exception {
        UnifiedQueueResponse body = queue("ws-01.lab", "cic17-wed|10.0.0.1|originator|1", "김분석");
        String plain = write(body);
        for (UserRole role : List.of(UserRole.ANALYST, UserRole.VIEWER, UserRole.ADMIN)) {
            assertThat(write(guard.apply(body, role, ResponseTextCatalog.QUEUE))).isEqualTo(plain);
        }
        // 분석가 행은 priority·detectedAt이 두 번 나온다(응답 구조 그대로)
        assertThat(plain.split("\"priority\"", -1)).hasSize(3);
    }

    @Test
    void analystGetsMarkersAndCapsButIdentifiersStayRaw() throws Exception {
        String evilId = "cic17-wed|10.0.0.1|orig‮inator|1";
        UnifiedQueueResponse body = queue("‮evil​" + "A".repeat(300), evilId, "김ㅤ분석");
        JsonNode out = objectMapper.readTree(write(guard.apply(body, UserRole.ANALYST, ResponseTextCatalog.QUEUE)));
        JsonNode item = out.get("items").get(0);
        String host = item.get("hostName").get(0).asText();
        assertThat(host).startsWith("[U+202E]evil[U+200B]AAA").endsWith("자 생략)");
        assertThat(host.codePointCount(0, host.indexOf('…'))).isEqualTo(256);
        assertThat(item.get("incidentId").asText()).isEqualTo(evilId); // 식별자는 손대지 않는다
        assertThat(item.get("assignee").get("displayName").asText()).isEqualTo("김[U+3164]분석");
    }

    @Test
    void viewerFallbackStripsFieldsTheMaskingStageDoesNotTouch() throws Exception {
        UnifiedQueueResponse body = queue("host", "cic17-wed|10.0.0.1|originator|1", "김ㅤ분석");
        JsonNode out = objectMapper.readTree(write(guard.apply(body, UserRole.VIEWER, ResponseTextCatalog.QUEUE)));
        assertThat(out.get("items").get(0).get("assignee").get("displayName").asText())
                .isEqualTo("김분석 [보이지 않는 문자 1개 제거]");
    }

    @Test
    void embeddedJsonIsProcessedOnItsParsedLeavesAndKeptVerbatimWhenClean() throws Exception {
        record Delivery(String payloadJson) {
        }
        record Detail(List<Delivery> slackDeliveries) {
        }
        record Wrapper(Detail detail) {
        }
        String clean = "{\n  \"text\" : \"경보 10.0.0.1\"\n}";
        String evil = objectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(Map.of("text", "a\u0000b‮", "k​ey", "v"));
        assertThat(evil).contains("\\u0000"); // 직렬화된 글에서는 제어 문자가 이스케이프로 숨는다
        Wrapper body = new Wrapper(new Detail(List.of(new Delivery(clean), new Delivery(evil), new Delivery("{not json ‮"))));
        JsonNode out = objectMapper.readTree(write(guard.apply(body, UserRole.ANALYST, ResponseTextCatalog.DETAIL)));
        JsonNode deliveries = out.get("detail").get("slackDeliveries");
        assertThat(deliveries.get(0).get("payloadJson").asText()).isEqualTo(clean);
        JsonNode parsed = objectMapper.readTree(deliveries.get(1).get("payloadJson").asText());
        assertThat(parsed.get("text").asText()).isEqualTo("a[U+0000]b[U+202E]");
        assertThat(parsed.has("k[U+200B]ey")).isTrue();
        assertThat(deliveries.get(2).get("payloadJson").asText()).isEqualTo("{not json [U+202E]");
    }

    @Test
    void pathRulesMatchArraysWildcardsAndDeepSuffixes() {
        ResponseTextRules rules = ResponseTextRules.named("t")
                .skip("items[].incidentId")
                .name("items[].hostName[]")
                .text("a.valueJson.**")
                .skipKeys("summary.byStatus");
        assertThat(rules.valueAction(path("items", "[]", "incidentId"))).isEqualTo(ResponseTextRules.Action.SKIP);
        assertThat(rules.valueAction(path("items", "[]", "hostName", "[]"))).isEqualTo(ResponseTextRules.Action.NAME);
        assertThat(rules.valueAction(path("items", "incidentId"))).isEqualTo(ResponseTextRules.Action.VALUE);
        assertThat(rules.valueAction(path("a", "valueJson", "x", "[]", "y"))).isEqualTo(ResponseTextRules.Action.TEXT);
        assertThat(rules.valueAction(path("a", "valueJson"))).isEqualTo(ResponseTextRules.Action.TEXT);
        assertThat(rules.keyAction(path("summary", "byStatus", "open"))).isEqualTo(ResponseTextRules.Action.SKIP);
        assertThat(rules.keyAction(path("summary", "total"))).isEqualTo(ResponseTextRules.Action.VALUE);
        // 자유 나무 안의 "[]"라는 이름의 키는 배열 마디가 아니다
        assertThat(rules.valueAction(path("items", new String("[]"), "incidentId"))).isEqualTo(ResponseTextRules.Action.VALUE);
    }

    private static List<String> path(String... segments) {
        List<String> out = new ArrayList<>();
        for (String s : segments) {
            out.add("[]".equals(s) && s == "[]" ? ResponseTextRules.ARRAY : s);
        }
        return out;
    }
}
