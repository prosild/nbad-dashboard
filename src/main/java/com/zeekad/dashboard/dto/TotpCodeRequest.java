package com.zeekad.dashboard.dto;

/**
 * TOTP 6자리 검증 코드 요청 DTO.
 */
public record TotpCodeRequest(String code) {
}
