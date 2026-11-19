package com.zeekad.dashboard.dto;

import java.util.List;

/**
 * 관리자 사용자 수정 요청 DTO.
 */
public record UpdateUserRequest(
        String displayName,
        String role,
        List<String> capturePatterns
) {
}
