package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * 모든 Thymeleaf 화면의 공통 상단 바에서 현재 로그인 사용자 정보를 참조할 수 있도록 주입한다.
 */
@ControllerAdvice
public class CurrentUserModelAdvice {

    @ModelAttribute("currentUser")
    public DashboardUserPrincipal currentUser(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof DashboardUserPrincipal principal) {
            return principal;
        }
        return null;
    }
}
