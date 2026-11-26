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
            // T27 인시던트 번호 고정 주소(숫자만)
            "/incidents/{incidentNo:[0-9]+}",
            // T46 호스트 위험도(정적 파일 경로 /assets/** 와 겹치지 않는 이름)
            "/hosts",
            "/reviews",
            "/operations",
            "/admin/users",
            "/admin/audit-logs",
            // T52 중요 자산(관리자만. 정적 파일 경로 /assets/** 와 겹치지 않는 이름)
            "/admin/critical-assets"
    })
    public String forwardToSpaShell() {
        return "forward:/index.html";
    }
}
