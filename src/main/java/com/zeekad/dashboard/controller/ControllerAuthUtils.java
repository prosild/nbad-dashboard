package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * REST API 컨트롤러 공통 인증 주체 추출 유틸리티.
 */
final class ControllerAuthUtils {

    private ControllerAuthUtils() {
    }

    static DashboardUserPrincipal requirePrincipal(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof DashboardUserPrincipal principal) {
            return principal;
        }
        throw new AccessDeniedException("인증된 사용자 주체를 확인할 수 없습니다.");
    }
}
