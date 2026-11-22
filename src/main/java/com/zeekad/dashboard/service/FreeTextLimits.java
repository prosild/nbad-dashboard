package com.zeekad.dashboard.service;

/**
 * T33 분석가가 쓰는 자유 글(상태 변경 사유, 검토 메모) 길이 상한.
 * 관제 사유는 몇 문장이면 충분하고, 추가만 하는 감사 로그에 쌓이는 양을 줄인다.
 * 앞뒤 공백을 뺀 값의 코드 포인트 수로 센다(SPA textarea maxLength와 같은 값).
 */
public final class FreeTextLimits {

    /** 사유·메모 최대 길이(코드 포인트) */
    public static final int MAX_CODE_POINTS = 500;

    private FreeTextLimits() {
    }

    /** 이미 앞뒤 공백을 뺀 값이 상한을 넘는가(null은 넘지 않음) */
    public static boolean exceeds(String trimmed) {
        return trimmed != null && trimmed.codePointCount(0, trimmed.length()) > MAX_CODE_POINTS;
    }
}
