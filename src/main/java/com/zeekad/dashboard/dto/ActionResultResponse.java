package com.zeekad.dashboard.dto;

/**
 * 상태 변경·검토 결정·로그아웃 등 액션 결과 응답 DTO.
 */
public record ActionResultResponse(boolean succeeded, String code, String message) {
}
