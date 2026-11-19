package com.zeekad.dashboard.dto;

/**
 * 현재 세션 인증 상태 조회 응답 DTO.
 */
public record AuthMeResponse(boolean authenticated, AuthUserDto user) {
}
