package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.DashboardUser;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 관리자 사용자 조회/변경 응답용 안전한 사용자 DTO (passwordHash, totpSecret 제외).
 */
public record AdminUserDto(
        Long id,
        String username,
        String displayName,
        String role,
        boolean totpEnabled,
        int failedAttempts,
        OffsetDateTime lockedUntil,
        boolean enabled,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        List<String> capturePatterns
) {

    public static AdminUserDto from(DashboardUser user) {
        return new AdminUserDto(
                user.getId(),
                user.getUsername(),
                user.getDisplayName(),
                user.getRole() != null ? user.getRole().name() : null,
                user.isTotpEnabled(),
                user.getFailedAttempts(),
                user.getLockedUntil(),
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                user.getCapturePatterns() == null ? List.of() : List.copyOf(user.getCapturePatterns())
        );
    }
}
