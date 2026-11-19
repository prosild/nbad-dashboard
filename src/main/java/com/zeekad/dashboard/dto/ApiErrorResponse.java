package com.zeekad.dashboard.dto;

/**
 * REST API 공통 오류 응답 DTO.
 */
public record ApiErrorResponse(int status, String code, String message) {
}
