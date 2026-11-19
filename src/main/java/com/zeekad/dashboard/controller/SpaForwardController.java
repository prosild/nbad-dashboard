package com.zeekad.dashboard.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 허용된 React SPA 클라이언트 라우트를 정적 셸(index.html)로 포워딩한다.
 * /api/** 경로는 절대 폴백하지 않는다.
 */
@Controller
public class SpaForwardController {

    @GetMapping({
            "/",
            "/login",
            "/login/totp",
            "/login/totp/setup",
            "/incidents",
            "/incidents/{jobId}/rank/{queueRank}",
            "/reviews",
            "/operations",
            "/admin/users",
            "/admin/audit-logs"
    })
    public String forwardToSpaShell() {
        return "forward:/index.html";
    }
}
