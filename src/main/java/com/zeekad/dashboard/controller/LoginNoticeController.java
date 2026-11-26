package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.LoginNoticeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * 로그인 화면 안내 문구(T21)와 그 아래 링크 하나(T50). 로그인 전에 읽는 공개 GET 하나이며,
 * 응답 필드는 notice, 그리고 검사를 통과한 link뿐이다(다른 설정을 넣지 않는다).
 * 값은 일반 텍스트로만 다룬다(화면은 텍스트 노드로 그린다). 안내 문구가 길이 상한을 넘으면 앱 시작 때 실패한다.
 * 링크 설정이 검사에 걸리면 시작은 하고 링크만 내리지 않는다. 그때 로그에는 이유만 쓰고 값은 쓰지 않는다
 * (제어 문자가 든 값을 로그에 쓰면 로그 줄을 꾸밀 수 있다).
 */
@RestController
public class LoginNoticeController {

    private static final Logger log = LoggerFactory.getLogger(LoginNoticeController.class);

    /** 안내 문구 길이 상한(유니코드 코드 포인트 기준) */
    public static final int MAX_LENGTH = 300;
    /** 링크 URL 길이 상한(코드 포인트) */
    public static final int LINK_URL_MAX_LENGTH = 200;
    /** 링크 라벨 길이 상한(코드 포인트) */
    public static final int LINK_LABEL_MAX_LENGTH = 40;

    private final LoginNoticeResponse response;

    public LoginNoticeController(DashboardProperties properties) {
        String notice = normalize(properties.getLoginNotice());
        this.response = new LoginNoticeResponse(
                notice, resolveLink(notice, properties.getLoginNoticeLinkUrl(), properties.getLoginNoticeLinkLabel()));
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

    /**
     * 링크 설정 둘이 모두 있고 검사를 통과하고 안내문 글도 있을 때만 링크를 돌려준다. 아니면 null이다.
     * 둘 다 비었으면(기본 설정) 조용히 null이고, 그 밖에는 이유를 경고 한 줄로 남긴다(값은 쓰지 않는다).
     */
    static LoginNoticeResponse.Link resolveLink(String notice, String rawUrl, String rawLabel) {
        String url = rawUrl == null ? "" : rawUrl.strip();
        String label = rawLabel == null ? "" : rawLabel.strip();
        if (url.isEmpty() && label.isEmpty()) {
            return null;
        }
        String reason = linkRejection(notice, url, label);
        if (reason != null) {
            log.warn("로그인 안내 링크를 내리지 않습니다: {}", reason);
            return null;
        }
        return new LoginNoticeResponse.Link(url, label);
    }

    /** 링크를 내리지 않는 이유(고정 문구). 통과하면 null. 설정값을 문구에 넣지 않는다. */
    private static String linkRejection(String notice, String url, String label) {
        if (url.isEmpty() || label.isEmpty()) {
            return "DASHBOARD_LOGIN_NOTICE_LINK_URL과 DASHBOARD_LOGIN_NOTICE_LINK_LABEL 가운데 하나만 있습니다";
        }
        if (notice == null || notice.isEmpty()) {
            return "안내문(DASHBOARD_LOGIN_NOTICE)이 비어 있습니다";
        }
        if (url.codePointCount(0, url.length()) > LINK_URL_MAX_LENGTH) {
            return "URL이 " + LINK_URL_MAX_LENGTH + "자를 넘습니다";
        }
        if (label.codePointCount(0, label.length()) > LINK_LABEL_MAX_LENGTH) {
            return "라벨이 " + LINK_LABEL_MAX_LENGTH + "자를 넘습니다";
        }
        if (hasForbiddenCharacter(url) || url.codePoints().anyMatch(cp -> Character.isWhitespace(cp) || Character.isSpaceChar(cp))) {
            return "URL에 공백·제어 문자나 양방향·서식 문자가 있습니다";
        }
        if (hasForbiddenCharacter(label)) {
            return "라벨에 제어 문자나 양방향·서식 문자가 있습니다";
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return "URL을 읽을 수 없습니다";
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return "URL이 https 주소가 아닙니다";
        }
        String authority = uri.getRawAuthority();
        if (uri.getRawUserInfo() != null || (authority != null && authority.indexOf('@') >= 0)) {
            return "URL에 사용자 정보(user@)가 있습니다";
        }
        if (uri.isOpaque() || uri.getHost() == null || uri.getHost().isEmpty()) {
            return "URL에 호스트가 없습니다";
        }
        return null;
    }

    /**
     * 제어 문자(줄바꿈·탭 포함), 양방향·서식 문자(U+200B~U+200F, U+202A~U+202E, U+2066~U+2069와 그 밖의 서식 문자),
     * 줄·문단 구분자, 짝 없는 서러게이트가 있는지.
     */
    private static boolean hasForbiddenCharacter(String value) {
        return value.codePoints().anyMatch(cp -> {
            if (Character.isISOControl(cp)) {
                return true;
            }
            if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) {
                return true;
            }
            int type = Character.getType(cp);
            return type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR
                    || type == Character.SURROGATE;
        });
    }

    @GetMapping("/api/auth/login-notice")
    public LoginNoticeResponse loginNotice() {
        return response;
    }
}
