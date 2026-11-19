package com.zeekad.dashboard.dto;

/**
 * 관리자 TOTP 최초 등록 정보 응답 DTO.
 */
public record TotpSetupResponse(String secret, String otpauthUri, String issuer, String accountName) {
}
