package com.zeekad.dashboard.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 사용자 허용 capture_pattern 정규화 및 매칭 유틸리티.
 */
public final class CapturePatternMatcher {

    private CapturePatternMatcher() {
    }

    public static String normalize(String pattern) {
        if (pattern == null) {
            return "";
        }
        return pattern.trim().toLowerCase(Locale.ROOT);
    }

    public static boolean isValidPattern(String pattern) {
        String normalized = normalize(pattern);
        if (normalized.isEmpty() || normalized.length() > 128) {
            return false;
        }
        if ("*".equals(normalized)) {
            return true;
        }
        int starIndex = normalized.indexOf('*');
        if (starIndex >= 0 && starIndex != normalized.length() - 1) {
            return false;
        }
        return normalized.matches("^[a-z0-9._-]+\\*?$");
    }

    public static boolean matches(String pattern, String captureId) {
        String normPattern = normalize(pattern);
        String normCapture = normalize(captureId);
        if (normPattern.isEmpty() || normCapture.isEmpty()) {
            return false;
        }
        if ("*".equals(normPattern)) {
            return true;
        }
        if (normPattern.endsWith("*")) {
            String prefix = normPattern.substring(0, normPattern.length() - 1);
            return normCapture.startsWith(prefix);
        }
        return normPattern.equals(normCapture);
    }

    public static boolean matchesAny(List<String> patterns, String captureId) {
        if (patterns == null || patterns.isEmpty()) {
            return false;
        }
        for (String pattern : patterns) {
            if (matches(pattern, captureId)) {
                return true;
            }
        }
        return false;
    }

    public static List<String> parseAndValidateList(String rawPatterns) {
        if (rawPatterns == null || rawPatterns.isBlank()) {
            throw new IllegalArgumentException("허용 캡처 패턴을 하나 이상 입력해야 합니다.");
        }
        String[] tokens = rawPatterns.split("[,\\r\\n]+");
        List<String> result = new ArrayList<>();
        for (String token : tokens) {
            String normalized = normalize(token);
            if (normalized.isEmpty()) {
                continue;
            }
            if (!isValidPattern(normalized)) {
                throw new IllegalArgumentException("올바르지 않은 캡처 패턴입니다: " + token);
            }
            if (!result.contains(normalized)) {
                result.add(normalized);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("허용 캡처 패턴을 하나 이상 입력해야 합니다.");
        }
        return result;
    }
}
