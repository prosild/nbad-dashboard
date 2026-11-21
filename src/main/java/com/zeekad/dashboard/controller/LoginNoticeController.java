package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.LoginNoticeResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 로그인 화면 안내 문구(T21). 로그인 전에 읽는 공개 GET 하나이며, 응답에는 안내 문구 말고 다른 설정을 넣지 않는다.
 * 값은 일반 텍스트로만 다룬다(화면은 텍스트 노드로 그린다). 길이 상한을 넘으면 앱 시작 때 실패한다.
 */
@RestController
public class LoginNoticeController {

    /** 안내 문구 길이 상한(유니코드 코드 포인트 기준) */
    public static final int MAX_LENGTH = 300;

    private final String notice;

    public LoginNoticeController(DashboardProperties properties) {
        this.notice = normalize(properties.getLoginNotice());
    }

    static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.strip();
        int length = trimmed.codePointCount(0, trimmed.length());
        if (length > MAX_LENGTH) {
            throw new IllegalStateException(
                    "DASHBOARD_LOGIN_NOTICE가 " + MAX_LENGTH + "자를 넘습니다(" + length + "자). 줄여서 다시 시작하세요.");
        }
        return trimmed;
    }

    @GetMapping("/api/auth/login-notice")
    public LoginNoticeResponse loginNotice() {
        return new LoginNoticeResponse(notice);
    }
}
