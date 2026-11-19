package com.zeekad.dashboard.dto;

/**
 * 관리자 사용자 생성/수정/상태 변경 응답 DTO.
 */
public record AdminUserMutationResponse(String message, AdminUserDto user) {
}
