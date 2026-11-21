package com.zeekad.dashboard.dto;

/**
 * 로그인 화면 안내 문구 응답(T21). 안내 문구 외의 값은 담지 않는다. 설정이 없으면 빈 문자열이다.
 */
public record LoginNoticeResponse(String notice) {
}
