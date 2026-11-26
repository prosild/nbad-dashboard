package com.zeekad.dashboard.testsupport;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * T63 "모든 응답의 모든 글자 값" 시험의 훑개. 서버 구현과 따로 쓴다(서버의 판정 코드를 부르지 않는다).
 *
 * <p>스트리밍 파서로 모든 키와 글자 값을 훑는다(분석가 큐 행처럼 같은 키가 두 번 나오는 응답이 있어 readTree를 쓰지 않는다).
 * 글 안에 든 JSON(payloadJson, detailJson)은 풀어서 안쪽 키·값까지 훑는다.
 */
public final class T63JsonScan {

    private T63JsonScan() {
    }

    public enum Kind {
        NAME(256), TEXT(4000), VALUE(1000);
        public final int cap;

        Kind(int cap) {
            this.cap = cap;
        }
    }

    /**
     * path: 점과 []로 이은 경로(글 안 JSON은 ">"로 이어 붙인다). field: 값이 걸린 가장 가까운 칸 이름.
     * container: 풀 수 있는 글 안 JSON(payloadJson·detailJson)의 바깥 글. 그 공백·줄바꿈은 직렬화 구조라 안쪽 키·값으로 판정한다.
     */
    public record Entry(String path, String field, boolean key, String text, boolean embedded, boolean container) {
    }

    private static final JsonFactory FACTORY = new JsonFactory();
    private static final Set<String> EMBEDDED_JSON_FIELDS = Set.of("payloadJson", "detailJson");

    public static List<Entry> scan(String json) {
        List<Entry> out = new ArrayList<>();
        scan(json, "", false, out);
        return out;
    }

    /** 훑는 중인 객체·배열. field는 객체의 지금 칸 이름, elem은 배열 원소의 칸 이름(배열을 담은 칸) */
    private static final class Frame {
        final boolean array;
        final String path;
        final String elem;
        String field;

        Frame(boolean array, String path, String elem) {
            this.array = array;
            this.path = path;
            this.elem = elem;
        }

        String childPath() {
            return array ? path + "[]" : path + "." + field;
        }

        String childField() {
            return array ? elem : field;
        }
    }

    private static void scan(String json, String base, boolean embedded, List<Entry> out) {
        try (JsonParser p = FACTORY.createParser(json)) {
            Deque<Frame> stack = new ArrayDeque<>();
            JsonToken t;
            while ((t = p.nextToken()) != null) {
                Frame top = stack.peek();
                switch (t) {
                    case START_OBJECT, START_ARRAY -> {
                        String childPath = top == null ? base : top.childPath();
                        String elem = top == null ? null : top.childField();
                        stack.push(new Frame(t == JsonToken.START_ARRAY, childPath, elem));
                    }
                    case END_OBJECT, END_ARRAY -> stack.pop();
                    case FIELD_NAME -> {
                        top.field = p.currentName();
                        out.add(new Entry(top.path + "." + top.field, top.field, true, top.field, embedded, false));
                    }
                    case VALUE_STRING -> {
                        String text = p.getText();
                        String valuePath = top == null ? base : top.childPath();
                        String valueField = top == null ? null : top.childField();
                        boolean container = top != null && !top.array && EMBEDDED_JSON_FIELDS.contains(top.field)
                                && parses(text);
                        out.add(new Entry(valuePath, valueField, false, text, embedded, container));
                        if (container) {
                            scan(text, valuePath + ">", true, out);
                        }
                    }
                    default -> {
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("JSON 훑기 실패: " + e.getMessage(), e);
        }
    }

    private static boolean parses(String text) {
        String trimmed = text.trim();
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return false;
        }
        try (JsonParser p = FACTORY.createParser(text)) {
            while (p.nextToken() != null) {
                // 끝까지 읽힌다
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /* ───────────────────────── 시험 쪽 칸 종류 ───────────────────────── */

    private static final Set<String> NAME_FIELDS = Set.of("hostName", "hostNames", "accounts", "kerberosUser", "ntlmUser",
            "displayName", "analystDisplay", "actorDisplay", "statusUpdatedByDisplay", "assignedByDisplay",
            "actorUsername", "selectedActorUsername");
    private static final Set<String> TEXT_FIELDS = Set.of("observationSummary", "claim", "explanation", "reason",
            "limitations", "followUp", "verificationProblems", "verificationReason", "llmError", "error",
            "decisionModelError", "policyReasons", "reviewReason", "zeekadReviewReason", "note", "payloadTextPreview",
            "payloadChannel", "value");

    /** 시험이 기대하는 칸 종류(서버 규칙과 따로 정했다. 애매하면 너그러운 쪽) */
    public static Kind kindOf(Entry e) {
        if (e.key()) {
            return Kind.VALUE;
        }
        if (e.embedded() || e.path().contains(".valueJson") || e.path().contains(".verificationProblemItems")
                || e.path().contains(".slackPayload")) {
            return Kind.TEXT;
        }
        if (e.path().contains(".extraAttributes.")) {
            return Kind.NAME;
        }
        if (e.field() != null && NAME_FIELDS.contains(e.field())) {
            return Kind.NAME;
        }
        if (e.field() != null && TEXT_FIELDS.contains(e.field())) {
            return Kind.TEXT;
        }
        return Kind.VALUE;
    }

    /* ───────────────────────── 숨은 문자·길이 ───────────────────────── */

    /** 시험 쪽 숨은 문자 판정(서버 코드와 따로 쓴다). Default_Ignorable_Code_Point는 시험 자료에 쓴 글자만 본다. */
    private static final Set<Integer> TEST_IGNORABLE = Set.of(0x00AD, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFE0F,
            0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068,
            0x2069, 0xFEFF, 0xE0001, 0xE007F);

    /** 숨은 문자 목록(U+XXXX). 여러 줄 칸이면 \n·\t는 허용, \r은 늘 숨은 문자로 본다. */
    public static List<String> hidden(String s, boolean multiline) {
        List<String> found = new ArrayList<>();
        int run = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (multiline && (cp == '\n' || cp == '\t')) {
                run = 0;
                continue;
            }
            int type = Character.getType(cp);
            boolean hidden = type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR || type == Character.SURROGATE
                    || TEST_IGNORABLE.contains(cp);
            if (hidden) {
                found.add(String.format("U+%04X", cp));
                continue;
            }
            if (type == Character.NON_SPACING_MARK || type == Character.ENCLOSING_MARK) {
                run++;
                if (run > 3) {
                    found.add(String.format("U+%04X(결합 %d번째)", cp, run));
                }
                continue;
            }
            run = 0;
        }
        return found;
    }

    private static final Pattern REMOVAL_NOTE = Pattern.compile(" \\[보이지 않는 문자 (\\d+)개 제거\\]$");
    private static final Pattern TRUNCATION_NOTE = Pattern.compile("…\\((\\d+)자 생략\\)$");

    /** 붙이는 글(제거 표시, 생략 표시)을 뗀 본문의 코드 포인트 수 */
    public static int bodyLength(String s) {
        String body = s;
        Matcher r = REMOVAL_NOTE.matcher(body);
        if (r.find()) {
            body = body.substring(0, r.start());
        }
        Matcher t = TRUNCATION_NOTE.matcher(body);
        if (t.find()) {
            body = body.substring(0, t.start());
        }
        return body.codePointCount(0, body.length());
    }

    public static boolean hasRemovalNote(String s) {
        return REMOVAL_NOTE.matcher(s).find();
    }

    public static boolean hasTruncationNote(String s) {
        String body = s;
        Matcher r = REMOVAL_NOTE.matcher(body);
        if (r.find()) {
            body = body.substring(0, r.start());
        }
        return TRUNCATION_NOTE.matcher(body).find();
    }

    /** 숨은 문자를 지운 "보이는 글"(조회자 응답의 주소 가림 판정용) */
    public static String visible(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            int type = Character.getType(cp);
            boolean hidden = type == Character.CONTROL || type == Character.FORMAT || type == Character.SURROGATE
                    || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
                    || TEST_IGNORABLE.contains(cp);
            if (!hidden) {
                sb.appendCodePoint(cp);
            }
        }
        return sb.toString();
    }
}
