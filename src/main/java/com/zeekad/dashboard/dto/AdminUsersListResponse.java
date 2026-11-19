package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.UserRole;

import java.util.List;

/**
 * 관리자 사용자 목록 응답 DTO.
 */
public record AdminUsersListResponse(List<AdminUserDto> users, List<UserRole> roles) {
}
