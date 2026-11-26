package com.zeekad.dashboard.service;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializable;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import com.zeekad.dashboard.dto.OperationsApiResponse;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

/**
 * T63 응답 직전의 글자 정책 구성요소(서비스 층). 가림·검색·정렬·묶음·필터가 원문으로 끝난 뒤 컨트롤러가 응답을 돌려주기 직전에 부른다.
 *
 * <ul>
 *   <li>분석가·관리자: 숨은 문자를 그 자리에 표지 [U+XXXX]로 바꾸고 칸 종류별 상한으로 자른다.</li>
 *   <li>조회자: 가림 단계({@link MaskingService})가 지우고 가린 값에 상한만 적용한다(제거 표시는 상한 밖). 가림 단계를 거치지 않은
 *       칸(표시 이름 등 지금 가리지 않는 칸)에 남은 숨은 문자는 여기서 지운다(주소 가림은 더하지 않는다: 가림 규칙을 넓히지 않는다).</li>
 *   <li>식별자(규칙의 SKIP)는 손대지 않는다.</li>
 * </ul>
 *
 * <p>응답 객체를 앱의 ObjectMapper로 토큰 흐름(TokenBuffer)에 적은 뒤 경로를 따라 글자 값과 키만 바꿔 새 토큰 흐름을 만든다.
 * 그래서 응답의 칸 이름·형·순서는 그대로이고(분석가 큐 행처럼 같은 키가 두 번 나오는 응답도 그대로), DTO에 새 칸이 생겨도 기본 "값" 정책을 거친다.
 * 응답 객체(UnifiedQueueRecord 등)의 실행 시점 형은 바꾸지 않고, 전역 Jackson 모듈을 쓰지 않는다(감사 로그 저장의 toJson은 그대로다).
 */
@Service
public class ResponseTextGuard {

    private final ObjectMapper objectMapper;
    private final MaskingService maskingService;

    public ResponseTextGuard(ObjectMapper objectMapper, MaskingService maskingService) {
        this.objectMapper = objectMapper;
        this.maskingService = maskingService;
    }

    /** 응답 본문(정책을 적용한 토큰 흐름). Spring의 JSON 변환기가 그대로 쓴다 */
    public static final class GuardedJson implements JsonSerializable {
        private final TokenBuffer tokens;

        GuardedJson(TokenBuffer tokens) {
            this.tokens = tokens;
        }

        @Override
        public void serialize(JsonGenerator gen, SerializerProvider serializers) throws IOException {
            tokens.serialize(gen);
        }

        @Override
        public void serializeWithType(JsonGenerator gen, SerializerProvider serializers, TypeSerializer typeSer)
                throws IOException {
            serialize(gen, serializers);
        }
    }

    public GuardedJson apply(Object body, UserRole role, ResponseTextRules rules) {
        boolean viewer = maskingService.shouldMask(role);
        try {
            TokenBuffer source = new TokenBuffer(objectMapper, false);
            objectMapper.writeValue(source, body);
            TokenBuffer out = new TokenBuffer(objectMapper, false);
            try (JsonParser p = source.asParser()) {
                rewrite(p, out, rules, viewer);
            }
            return new GuardedJson(out);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * 같은 처리를 한 뒤 원래 형으로 되읽는다. 응답 형을 그대로 돌려줘야 하는 곳(관리자 감사 로그 API는 기존 시험이 컨트롤러 메서드를 바로 불러
     * ResponseEntity&lt;AdminAuditLogsResponse&gt;를 기대한다)에만 쓴다. 되읽을 수 있는 형(기본 생성자·setter, 또는 record)이어야 한다.
     */
    public <T> T applyAs(T body, UserRole role, ResponseTextRules rules, Class<T> type) {
        GuardedJson guarded = apply(body, role, rules);
        try (JsonParser p = guarded.tokens.asParser()) {
            return objectMapper.readValue(p, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * 운영 현황: Slack 요약의 payloadTextPreview·payloadChannel은 페이로드에서 파생되는 getter라, 페이로드를 먼저 처리한 사본으로 바꾼 뒤
     * 적용한다(파생 칸이 처리한 페이로드에서 나온다). 다시 적용해도 같은 값이다(표지·자르기·제거 표시는 두 번 바뀌지 않는다).
     */
    public GuardedJson applyOperations(OperationsApiResponse body, UserRole role) {
        OperationsApiResponse prepared = body;
        if (body != null && body.slackSummaries() != null && !body.slackSummaries().isEmpty()) {
            List<SlackSummary> summaries = new ArrayList<>(body.slackSummaries().size());
            for (SlackSummary s : body.slackSummaries()) {
                summaries.add(s == null ? null : withPayload(s, processTree(s.getSlackPayload(), role, UntrustedText.Kind.TEXT)));
            }
            prepared = new OperationsApiResponse(body.maskedView(), body.allowedCaptures(), body.selectedCaptureId(),
                    body.jobs(), body.bundles(), body.feedbackSummaries(), summaries, body.period(), body.periodStart(),
                    body.periodEnd(), body.source(), body.anchor(), body.jobsTruncated(), body.jobsTotal(), body.latestJobs(),
                    body.sources(), body.handlingTimes(), body.workload());
        }
        return apply(prepared, role, ResponseTextCatalog.OPERATIONS);
    }

    private static SlackSummary withPayload(SlackSummary s, JsonNode payload) {
        SlackSummary copy = new SlackSummary();
        copy.setJobId(s.getJobId());
        copy.setCaptureId(s.getCaptureId());
        copy.setZeekadMessageVersion(s.getZeekadMessageVersion());
        copy.setZeekadDeliveryMode(s.getZeekadDeliveryMode());
        copy.setZeekadDeliveryStatus(s.getZeekadDeliveryStatus());
        copy.setSlackPayload(payload);
        copy.setSlackTs(s.getSlackTs());
        copy.setDeliveredAt(s.getDeliveredAt());
        copy.setCreatedAt(s.getCreatedAt());
        return copy;
    }

    /** 객체 하나(배열)의 경로 상태: base는 이 객체·배열을 연 때의 경로 길이 */
    private record Frame(boolean array, int base) {
    }

    private void rewrite(JsonParser p, TokenBuffer out, ResponseTextRules rules, boolean viewer) throws IOException {
        List<String> path = new ArrayList<>();
        Deque<Frame> frames = new ArrayDeque<>();
        JsonToken t;
        while ((t = p.nextToken()) != null) {
            switch (t) {
                case START_OBJECT -> {
                    frames.push(new Frame(false, path.size()));
                    out.writeStartObject();
                }
                case START_ARRAY -> {
                    frames.push(new Frame(true, path.size()));
                    path.add(ResponseTextRules.ARRAY);
                    out.writeStartArray();
                }
                case END_OBJECT, END_ARRAY -> {
                    Frame f = frames.pop();
                    truncate(path, f.base());
                    if (t == JsonToken.END_OBJECT) {
                        out.writeEndObject();
                    } else {
                        out.writeEndArray();
                    }
                }
                case FIELD_NAME -> {
                    Frame f = frames.peek();
                    truncate(path, f.base());
                    String name = p.currentName();
                    path.add(name);
                    out.writeFieldName(rules.keyAction(path) == ResponseTextRules.Action.SKIP
                            ? name : leaf(name, UntrustedText.Kind.VALUE, viewer));
                }
                case VALUE_STRING -> out.writeString(value(p.getText(), rules.valueAction(path), viewer));
                default -> out.copyCurrentEvent(p);
            }
        }
    }

    private static void truncate(List<String> path, int size) {
        while (path.size() > size) {
            path.remove(path.size() - 1);
        }
    }

    private String value(String text, ResponseTextRules.Action action, boolean viewer) {
        return switch (action) {
            case SKIP -> text;
            case NAME -> leaf(text, UntrustedText.Kind.NAME, viewer);
            case TEXT -> leaf(text, UntrustedText.Kind.TEXT, viewer);
            case VALUE -> leaf(text, UntrustedText.Kind.VALUE, viewer);
            case EMBEDDED_JSON_PRETTY -> embeddedJson(text, viewer, true);
            case EMBEDDED_JSON_COMPACT -> embeddedJson(text, viewer, false);
        };
    }

    private static String leaf(String text, UntrustedText.Kind kind, boolean viewer) {
        return viewer ? UntrustedText.forViewer(text, kind) : UntrustedText.forAnalyst(text, kind);
    }

    /**
     * 글 안에 든 JSON(Slack payloadJson, 감사 로그 detail): 푼 나무의 잎(키는 "값", 글자 값은 "글")에 정책을 적용한 뒤 다시 직렬화한다.
     * 직렬화된 글은 자르지 않는다(자르면 JSON이 깨져 화면이 본문을 통째로 잃는다). 풀 수 없으면 "글"로 다룬다.
     * Jackson은 C0 제어 문자를 \\u0000 꼴로 적어 직렬화된 글에서는 숨은 문자가 보이지 않으므로 반드시 푼 뒤에 본다.
     */
    private String embeddedJson(String text, boolean viewer, boolean pretty) {
        if (text == null) {
            return null;
        }
        JsonNode tree;
        try {
            tree = objectMapper.readTree(text);
        } catch (JsonProcessingException e) {
            tree = null;
        }
        if (tree == null || !(tree.isObject() || tree.isArray())) {
            return leaf(text, UntrustedText.Kind.TEXT, viewer);
        }
        JsonNode processed = processTree(tree, viewer, UntrustedText.Kind.TEXT);
        if (processed.equals(tree)) {
            return text; // 바뀐 잎이 없으면 원래 글 그대로(공백·순서까지)
        }
        try {
            return pretty ? objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(processed)
                    : objectMapper.writeValueAsString(processed);
        } catch (JsonProcessingException e) {
            return leaf(text, UntrustedText.Kind.TEXT, viewer);
        }
    }

    /**
     * JSON 나무의 잎에 정책을 적용한 사본(키는 "값", 글자 값은 leafKind). 숨은 문자를 지워 키가 겹치면 뒤의 값이 앞을 덮는다.
     * 운영 현황의 Slack 요약처럼 파생 칸(payloadTextPreview·payloadChannel)을 처리한 페이로드에서 얻어야 할 때 먼저 부른다.
     */
    public JsonNode processTree(JsonNode node, UserRole role, UntrustedText.Kind leafKind) {
        return node == null ? null : processTree(node, maskingService.shouldMask(role), leafKind);
    }

    private JsonNode processTree(JsonNode node, boolean viewer, UntrustedText.Kind leafKind) {
        if (node.isTextual()) {
            return TextNode.valueOf(leaf(node.asText(), leafKind, viewer));
        }
        if (node.isObject()) {
            ObjectNode copy = objectMapper.createObjectNode();
            for (Map.Entry<String, JsonNode> e : node.properties()) {
                copy.set(leaf(e.getKey(), UntrustedText.Kind.VALUE, viewer), processTree(e.getValue(), viewer, leafKind));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = objectMapper.createArrayNode();
            for (JsonNode child : node) {
                copy.add(processTree(child, viewer, leafKind));
            }
            return copy;
        }
        return node.deepCopy();
    }
}
