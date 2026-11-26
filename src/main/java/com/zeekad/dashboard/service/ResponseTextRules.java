package com.zeekad.dashboard.service;

import java.util.ArrayList;
import java.util.List;

/**
 * T63 응답 하나의 글자 칸 규칙: JSON 경로 → 처리 종류. 앞에서부터 처음 맞는 규칙을 쓰고, 맞는 규칙이 없으면 "값"(VALUE)이다
 * (목록에 없는 글자 값은 모두 정책을 거친다).
 *
 * <p>경로 꼴: 칸 이름을 점으로 잇고 배열 원소는 {@code []}를 붙인다(예 {@code items[].hostName[]}). {@code *}는 칸 이름 하나,
 * {@code **}는 0개 이상의 마디다. 규칙은 이 저장소가 쓴 DTO 칸 이름만 적는다(근거·페이로드 같은 자유 나무 안의 키를 식별자로 보지 않는다).
 *
 * <ul>
 *   <li>{@link Action#SKIP}: 식별자(닫힌 목록). 표지·상한을 적용하지 않는다(조회자 가림은 지금 그대로).</li>
 *   <li>NAME·TEXT·VALUE: {@link UntrustedText.Kind}의 칸.</li>
 *   <li>{@link Action#EMBEDDED_JSON_PRETTY}·{@link Action#EMBEDDED_JSON_COMPACT}: 글 안에 든 JSON. 직렬화된 글이 아니라 푼 나무의 잎(키와 값)에
 *       "글" 정책을 적용한 뒤 다시 직렬화한다. 직렬화된 글은 자르지 않는다. 풀 수 없으면 "글"로 다룬다.</li>
 * </ul>
 * 키는 늘 "값" 정책이고, {@link #skipKeys}로 적은 Map(식별자가 키인 Map)의 키만 뺀다.
 */
public final class ResponseTextRules {

    public enum Action { SKIP, NAME, TEXT, VALUE, EMBEDDED_JSON_PRETTY, EMBEDDED_JSON_COMPACT }

    /**
     * 경로 마디: 칸 이름이거나 배열 원소. 배열 원소는 이 객체 하나(동일성)로 가린다: 자유 나무 안에 "[]"라는 이름의 키가 와도
     * (Jackson은 키 이름을 intern한다) 배열 마디로 읽히지 않게 intern되지 않은 새 문자열로 둔다.
     */
    @SuppressWarnings("StringOperationCanBeSimplified")
    static final String ARRAY = new String("[]");
    private static final String ANY = "*";
    private static final String DEEP = "**";

    private record Rule(List<String> pattern, Action action, String source) {
    }

    private final String name;
    private final List<Rule> valueRules = new ArrayList<>();
    private final List<Rule> keyRules = new ArrayList<>();

    private ResponseTextRules(String name) {
        this.name = name;
    }

    public static ResponseTextRules named(String name) {
        return new ResponseTextRules(name);
    }

    public String name() {
        return name;
    }

    /* ───────────────────────── 만들기 ───────────────────────── */

    public ResponseTextRules skip(String... patterns) {
        return add(Action.SKIP, patterns);
    }

    public ResponseTextRules name(String... patterns) {
        return add(Action.NAME, patterns);
    }

    public ResponseTextRules text(String... patterns) {
        return add(Action.TEXT, patterns);
    }

    public ResponseTextRules embeddedJsonPretty(String pattern) {
        return add(Action.EMBEDDED_JSON_PRETTY, pattern);
    }

    public ResponseTextRules embeddedJsonCompact(String pattern) {
        return add(Action.EMBEDDED_JSON_COMPACT, pattern);
    }

    /** 이 Map의 키는 식별자(열거값·가명 등)다. 키에 정책을 적용하지 않는다 */
    public ResponseTextRules skipKeys(String... mapPatterns) {
        for (String p : mapPatterns) {
            keyRules.add(new Rule(parse(p + "." + ANY), Action.SKIP, p));
        }
        return this;
    }

    /** 다른 규칙 묶음을 경로 앞머리 아래에 붙인다(같은 모양의 칸이 여러 응답·여러 자리에 나올 때) */
    public ResponseTextRules mount(String prefix, ResponseTextRules part) {
        for (Rule r : part.valueRules) {
            valueRules.add(new Rule(join(prefix, r.pattern()), r.action(), joinText(prefix, r.source())));
        }
        for (Rule r : part.keyRules) {
            keyRules.add(new Rule(join(prefix, r.pattern()), r.action(), joinText(prefix, r.source())));
        }
        return this;
    }

    private static String joinText(String prefix, String tail) {
        return tail.startsWith(ARRAY) ? prefix + tail : prefix + "." + tail;
    }

    private ResponseTextRules add(Action action, String... patterns) {
        for (String p : patterns) {
            valueRules.add(new Rule(parse(p), action, p));
        }
        return this;
    }

    private static List<String> join(String prefix, List<String> tail) {
        List<String> out = new ArrayList<>(parse(prefix));
        out.addAll(tail);
        return out;
    }

    /** "a[].b.**" → [a, [], b, **] */
    static List<String> parse(String pattern) {
        List<String> out = new ArrayList<>();
        if (pattern == null || pattern.isEmpty()) {
            return out;
        }
        for (String seg : pattern.split("\\.")) {
            String name = seg;
            int arrays = 0;
            while (name.endsWith(ARRAY)) {
                name = name.substring(0, name.length() - 2);
                arrays++;
            }
            if (!name.isEmpty()) {
                out.add(name);
            }
            for (int i = 0; i < arrays; i++) {
                out.add(ARRAY);
            }
        }
        return out;
    }

    /* ───────────────────────── 판정 ───────────────────────── */

    /** 글자 값의 처리. path는 이름 마디와 ARRAY 마디의 목록이다 */
    public Action valueAction(List<String> path) {
        for (Rule r : valueRules) {
            if (matches(r.pattern(), 0, path, 0)) {
                return r.action();
            }
        }
        return Action.VALUE;
    }

    /** 키 처리: SKIP이거나 VALUE. path는 키까지 넣은 경로다 */
    public Action keyAction(List<String> path) {
        for (Rule r : keyRules) {
            if (matches(r.pattern(), 0, path, 0)) {
                return Action.SKIP;
            }
        }
        return Action.VALUE;
    }

    private static boolean matches(List<String> pattern, int pi, List<String> path, int si) {
        while (pi < pattern.size()) {
            String p = pattern.get(pi);
            if (DEEP.equals(p)) {
                for (int k = si; k <= path.size(); k++) {
                    if (matches(pattern, pi + 1, path, k)) {
                        return true;
                    }
                }
                return false;
            }
            if (si >= path.size()) {
                return false;
            }
            String s = path.get(si);
            if (ARRAY.equals(p)) {
                if (s != ARRAY) {
                    return false;
                }
            } else if (ANY.equals(p)) {
                if (s == ARRAY) {
                    return false;
                }
            } else if (s == ARRAY || !p.equals(s)) {
                return false;
            }
            pi++;
            si++;
        }
        return si == path.size();
    }

    /** 증거용: 식별자로 뺀 경로(값)와 키를 뺀 Map */
    public List<String> describeSkips() {
        List<String> out = new ArrayList<>();
        for (Rule r : valueRules) {
            if (r.action() == Action.SKIP) {
                out.add(r.source());
            }
        }
        for (Rule r : keyRules) {
            out.add(r.source() + " (키)");
        }
        return out;
    }

    /** 증거용: 종류를 정한 경로(식별자 밖) */
    public List<String> describeKinds() {
        List<String> out = new ArrayList<>();
        for (Rule r : valueRules) {
            if (r.action() != Action.SKIP) {
                out.add(r.action() + " " + r.source());
            }
        }
        return out;
    }
}
