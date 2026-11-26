package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.zeekad.dashboard.model.UserRole;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 보고서 문장 내 가명(zeekad_pseudonyms)을 단어 경계 기반 단일 패스로 "<가명>(<IP 또는 마스킹 IP>)" 치환한다.
 */
@Component
public class PseudonymAnnotator {

    private final MaskingService maskingService;

    public PseudonymAnnotator(MaskingService maskingService) {
        this.maskingService = maskingService;
    }

    /**
     * 역할별 마스킹이 반영된 가명 -> 주소 맵을 생성한다(원래 JSON 순서 유지).
     */
    public Map<String, String> buildEffectivePseudonymMap(JsonNode pseudonymsNode, UserRole role) {
        if (pseudonymsNode == null || !pseudonymsNode.isObject()) {
            return Collections.emptyMap();
        }
        JsonNode effectiveNode = maskingService.maskPseudonyms(pseudonymsNode, role);
        Map<String, String> result = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = effectiveNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey();
            JsonNode valNode = entry.getValue();
            if (key == null || key.isBlank() || valNode == null || valNode.isNull()) {
                continue;
            }
            String value = valNode.asText("").trim();
            if (!value.isEmpty()) {
                result.put(key, value);
            }
        }
        return Collections.unmodifiableMap(result);
    }

    /**
     * 단일 패스 단어 경계 정규식으로 문장 내 모든 가명을 치환한다.
     * VIEWER인 경우 원문 문장 내 IPv4 주소와 가명표 IP 모두 먼저 마스킹한 뒤 치환한다.
     */
    public String annotate(String text, JsonNode pseudonymsNode, UserRole role) {
        Map<String, String> effectiveMap = buildEffectivePseudonymMap(pseudonymsNode, role);
        return annotate(text, effectiveMap, role);
    }

    public String annotate(String text, Map<String, String> effectivePseudonyms, UserRole role) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        // T63 조회자: maskIps(strip(maskIps(text)))로 가린 뒤 치환하고, 지운 숨은 문자가 있으면 끝에 제거 표시를 붙인다
        String workingText = text;
        String removalNote = "";
        if (maskingService.shouldMask(role)) {
            UntrustedText.Stripped stripped = UntrustedText.strip(maskingService.maskIpsInText(text), true);
            workingText = maskingService.maskIpsInText(stripped.text());
            if (stripped.removed() > 0) {
                removalNote = UntrustedText.removalNote(stripped.removed());
            }
        }
        return annotateWorking(workingText, effectivePseudonyms) + removalNote;
    }

    private String annotateWorking(String workingText, Map<String, String> effectivePseudonyms) {
        if (workingText == null || workingText.isEmpty() || effectivePseudonyms == null || effectivePseudonyms.isEmpty()) {
            return workingText;
        }

        List<String> sortedKeys = effectivePseudonyms.keySet().stream()
                .filter(k -> k != null && !k.isBlank())
                .sorted(Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()))
                .toList();
        if (sortedKeys.isEmpty()) {
            return workingText;
        }

        String alternation = sortedKeys.stream()
                .map(Pattern::quote)
                .collect(Collectors.joining("|"));
        Pattern boundaryPattern = Pattern.compile("(?<![A-Za-z0-9_])(" + alternation + ")(?![A-Za-z0-9_])");

        Matcher matcher = boundaryPattern.matcher(workingText);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String key = matcher.group(1);
            String ip = effectivePseudonyms.get(key);
            if (ip != null && !ip.isEmpty()) {
                matcher.appendReplacement(sb, Matcher.quoteReplacement(key + "(" + ip + ")"));
            } else {
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matcher.group(0)));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
}
