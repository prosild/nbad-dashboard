package com.zeekad.dashboard.model;

/**
 * 대시보드 사용자 역할.
 */
public enum UserRole {
    VIEWER("조회자"),
    ANALYST("분석가"),
    ADMIN("관리자");

    private final String koreanLabel;

    UserRole(String koreanLabel) {
        this.koreanLabel = koreanLabel;
    }

    public String getKoreanLabel() {
        return koreanLabel;
    }

    public static UserRole fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("역할 값이 비어 있습니다.");
        }
        try {
            return UserRole.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("올바르지 않은 역할 값입니다. (VIEWER, ANALYST, ADMIN 중 선택)");
        }
    }
}
