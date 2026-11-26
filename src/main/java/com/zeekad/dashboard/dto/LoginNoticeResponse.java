package com.zeekad.dashboard.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * 로그인 화면 안내 문구 응답(T21, T50). 필드는 notice, 그리고 서버 검사를 통과한 link뿐이다.
 * 설정이 없으면 notice는 빈 문자열이다. 링크가 없거나 검사에 걸리면 link 필드 자체가 없다(null로 내리지 않는다).
 */
public record LoginNoticeResponse(String notice, @JsonInclude(JsonInclude.Include.NON_NULL) Link link) {

    public LoginNoticeResponse(String notice) {
        this(notice, null);
    }

    /** 안내문 아래에 붙는 링크 하나(T50). url은 https 주소, label은 일반 텍스트다. */
    public record Link(String url, String label) {
    }
}
