package com.zeekad.dashboard.dto;

import java.util.List;

/**
 * 관리자 사용자 생성 요청 DTO.
 */
public record CreateUserRequest(
        String username,
        String displayName,
        String password,
        String role,
        List<String> capturePatterns
) {
}
