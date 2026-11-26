package com.zeekad.dashboard.service;

/**
 * T63 이름 검색의 공용 자리: 큐 asset(목록·옛 목록 API·새 건수·이웃)과 호스트 위험도 q.
 * 검색어와 비교 대상에 같은 정규화(숨은 문자 제거 → NFKC → 소문자)를 적용한다. 그래서 숨은 문자·전각 글자를 끼운 이름도 보이는 글자로 찾힌다.
 * 비교 대상은 분석가는 원문(자르기 전), 조회자는 지금처럼 가린 값(가림 단계의 처리 뒤, 제거 표시 글은 빼고)이다.
 */
public final class TextSearch {

    /** 검색어 상한(정규화 전 UTF-16 단위, 앞뒤 공백을 뺀 값). 브라우저 maxLength와 같은 단위다 */
    public static final int MAX_LENGTH = 100;

    private TextSearch() {
    }

    /**
     * 요청 값 → 정규화한 검색어. 비었거나 정규화하면 비는 값(숨은 문자만 넣은 경우)은 null(조건 없음, 빈 검색어와 같다).
     * 앞뒤 공백을 뺀 값이 UTF-16 100단위를 넘으면 400 INVALID_REQUEST.
     */
    public static String parseQuery(String raw, String tooLongMessage) {
        if (raw == null) {
            return null;
        }
        String clean = raw.trim();
        if (clean.isEmpty()) {
            return null;
        }
        if (clean.length() > MAX_LENGTH) {
            throw new QueueQueryException("INVALID_REQUEST", tooLongMessage);
        }
        String normalized = UntrustedText.normalizeForSearch(clean).trim();
        return normalized.isEmpty() ? null : normalized;
    }

    /** 비교 대상(원문 또는 조회자의 가린 값)에 정규화한 검색어가 들어 있는가 */
    public static boolean contains(String target, String normalizedQuery) {
        if (target == null || normalizedQuery == null) {
            return false;
        }
        return UntrustedText.normalizeForSearch(UntrustedText.withoutRemovalNote(target)).contains(normalizedQuery);
    }
}
