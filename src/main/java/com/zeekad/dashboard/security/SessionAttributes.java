package com.zeekad.dashboard.security;

/**
 * HttpSession에 저장되는 보안 속성 키 상수.
 */
public final class SessionAttributes {

    public static final String SESSION_CREATED_AT = "ZEEKAD_SESSION_CREATED_AT";
    public static final String SESSION_LAST_ACCESSED_AT = "ZEEKAD_SESSION_LAST_ACCESSED_AT";
    public static final String TOTP_VERIFIED = "ZEEKAD_TOTP_VERIFIED";

    private SessionAttributes() {
    }
}
