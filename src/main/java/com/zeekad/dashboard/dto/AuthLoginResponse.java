package com.zeekad.dashboard.dto;

/**
 * JSON 로그인 성공 응답 DTO.
 */
public record AuthLoginResponse(boolean authenticated, AuthUserDto user, String nextRoute) {
}
