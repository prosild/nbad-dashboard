package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * T45 ATT&amp;CK 조건 값의 정규화와 리포트 후보 맞추기. 통합 큐의 attack 조건이 쓰고, 현황판 분포(T45b)가 같은 규칙으로 센다.
 *
 * <ol>
 *   <li>기법 ID: 대소문자를 가리지 않고 T + 숫자 4자리(+ 선택 .숫자 3자리) → 대문자. 서브기법까지 정확히 같아야 한다
 *       (T1059와 T1059.001은 다르다).</li>
 *   <li>전술 슬러그: 소문자로 바꾸고 공백·밑줄 묶음을 하이픈 하나로 → [a-z0-9]+(-[a-z0-9]+)*, 길이 2~64.
 *       "Credential Access"·credential_access·credential-access가 같은 전술이다.</li>
 * </ol>
 * 기법 ID를 먼저 본다(순서를 바꾸면 t1059가 전술 슬러그로 읽힌다).
 * 후보 JSON 모양은 상세(IncidentDetailService.parseAttackCandidates)가 읽는 것과 같다: 배열 원소의 attack_id, tactics 글 배열.
 */
public final class AttackFilter {

    public enum Kind { TECHNIQUE, TACTIC }

    /** 정규화한 조건 값. value = 대문자 기법 ID 또는 전술 슬러그 */
    public record Value(Kind kind, String value) {
    }

    private static final Pattern TECHNIQUE = Pattern.compile("^[Tt]\\d{4}(\\.\\d{3})?$");
    private static final Pattern SEPARATORS = Pattern.compile("[\\s_]+");
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9]+(-[a-z0-9]+)*$");
    static final int SLUG_MIN = 2;
    static final int SLUG_MAX = 64;

    private AttackFilter() {
    }

    /** 조건 값 해석. 값이 없거나(null·공백) 어느 형식도 아니면 null(없음과 형식 오류는 호출 쪽이 먼저 가른다) */
    public static Value parse(String raw) {
        String technique = techniqueId(raw);
        if (technique != null) {
            return new Value(Kind.TECHNIQUE, technique);
        }
        String slug = tacticSlug(raw);
        return slug == null ? null : new Value(Kind.TACTIC, slug);
    }

    /** 기법 ID면 대문자 꼴, 아니면 null */
    public static String techniqueId(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        return TECHNIQUE.matcher(s).matches() ? s.toUpperCase(Locale.ROOT) : null;
    }

    /** 전술 슬러그 꼴, 만들 수 없으면 null */
    public static String tacticSlug(String raw) {
        if (raw == null) {
            return null;
        }
        String s = SEPARATORS.matcher(raw.trim().toLowerCase(Locale.ROOT)).replaceAll("-");
        if (s.length() < SLUG_MIN || s.length() > SLUG_MAX || !SLUG.matcher(s).matches()) {
            return null;
        }
        return s;
    }

    /** 리포트의 ATT&amp;CK 후보(zeekad_attack_candidates)에 조건 값이 있는지 */
    public static boolean matches(Value filter, JsonNode candidates) {
        if (filter == null || candidates == null || !candidates.isArray()) {
            return false;
        }
        for (JsonNode node : candidates) {
            if (node == null || !node.isObject()) {
                continue;
            }
            if (filter.kind() == Kind.TECHNIQUE) {
                String id = text(node.get("attack_id"));
                if (id != null && filter.value().equals(id.trim().toUpperCase(Locale.ROOT))) {
                    return true;
                }
            } else if (hasTactic(node.get("tactics"), filter.value())) {
                return true;
            }
        }
        return false;
    }

    /** T45b 현황판 분포: 후보 배열에서 큐 attack 조건으로 갈 수 있는 값을 받는 쪽 */
    public interface CandidateVisitor {
        /** attackId = 대문자 기법 ID, name = 그 후보의 이름(다듬은 글, 없으면 null) */
        void technique(String attackId, String name);

        /** slug = 전술 슬러그 */
        void tactic(String slug);
    }

    /**
     * T45b: 후보 배열을 돌며 큐 attack 조건으로 갈 수 있는 값만 알린다(같은 값이 여러 번 나오면 여러 번 알린다).
     * 알린 값 v는 matches(parse(v), candidates)가 참이다. 빠지는 값: ID 꼴이 아닌 attack_id, 슬러그를 만들 수 없는 전술,
     * 슬러그가 기법 ID 꼴인 전술(parse가 기법으로 읽어 큐에서 전술로 맞출 수 없다).
     */
    public static void visit(JsonNode candidates, CandidateVisitor visitor) {
        if (candidates == null || !candidates.isArray() || visitor == null) {
            return;
        }
        for (JsonNode node : candidates) {
            if (node == null || !node.isObject()) {
                continue;
            }
            String id = techniqueId(text(node.get("attack_id")));
            if (id != null) {
                String name = text(node.get("name"));
                visitor.technique(id, name == null || name.isBlank() ? null : name.trim());
            }
            JsonNode tactics = node.get("tactics");
            if (tactics == null || tactics.isNull()) {
                continue;
            }
            if (!tactics.isArray()) {
                visitTactic(text(tactics), visitor);
                continue;
            }
            for (JsonNode t : tactics) {
                visitTactic(text(t), visitor);
            }
        }
    }

    private static void visitTactic(String raw, CandidateVisitor visitor) {
        String slug = tacticSlug(raw);
        if (slug != null && techniqueId(slug) == null) {
            visitor.tactic(slug);
        }
    }

    private static boolean hasTactic(JsonNode tactics, String slug) {
        if (tactics == null || tactics.isNull()) {
            return false;
        }
        if (!tactics.isArray()) {
            return slug.equals(tacticSlug(text(tactics)));
        }
        for (JsonNode t : tactics) {
            if (slug.equals(tacticSlug(text(t)))) {
                return true;
            }
        }
        return false;
    }

    /** 글·숫자·참거짓 값만 글로 읽는다(객체·배열·null은 null) */
    private static String text(JsonNode node) {
        if (node == null || node.isNull() || node.isContainerNode()) {
            return null;
        }
        return node.asText();
    }
}
