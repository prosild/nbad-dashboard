package com.zeekad.dashboard.dto;

import java.util.List;

/**
 * 인증된 현재 사용자 정보 DTO (민감 필드 제외).
 */
public record AuthUserDto(
        String username,
        String displayName,
        String role,
        boolean maskedView,
        boolean totpEnabled,
        boolean totpVerified,
        boolean totpRequired,
        List<String> allowedCapturePatterns
) {
}
