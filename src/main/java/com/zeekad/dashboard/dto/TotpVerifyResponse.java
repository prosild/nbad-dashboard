package com.zeekad.dashboard.dto;

/**
 * TOTP 등록 및 검증 완료 응답 DTO.
 */
public record TotpVerifyResponse(boolean succeeded, String code, String message, AuthUserDto user) {
}
