package com.zeekad.dashboard.dto;

/**
 * SPA CSRF 토큰 발급 응답 DTO.
 */
public record AuthCsrfResponse(String headerName, String parameterName, String token) {
}
