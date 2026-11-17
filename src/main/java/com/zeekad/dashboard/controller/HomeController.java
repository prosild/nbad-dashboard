package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 로그인 후 기본 진입 홈 화면(T02에서 조사 큐로 확장할 스켈레톤).
 */
@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        if (authentication != null && authentication.getPrincipal() instanceof DashboardUserPrincipal principal) {
            model.addAttribute("currentUser", principal);
        } else if (authentication != null) {
            model.addAttribute("username", authentication.getName());
        }
        return "index";
    }
}
