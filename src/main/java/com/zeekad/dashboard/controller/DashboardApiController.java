package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.DashboardOverviewResponse;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.DashboardOverviewService;
import com.zeekad.dashboard.service.ResponseTextCatalog;
import com.zeekad.dashboard.service.ResponseTextGuard;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 현황판 API(T24). 인증 필요, 모든 역할. 기간·수집원·캡처 조건은 통합 큐와 같다(잘못된 값 400, 허용 밖 캡처 403·감사 기록).
 */
@RestController
public class DashboardApiController {

    private final DashboardOverviewService dashboardOverviewService;
    private final ClientIpResolver clientIpResolver;
    private final ResponseTextGuard responseTextGuard;

    public DashboardApiController(DashboardOverviewService dashboardOverviewService, ClientIpResolver clientIpResolver,
                                  ResponseTextGuard responseTextGuard) {
        this.responseTextGuard = responseTextGuard;
        this.dashboardOverviewService = dashboardOverviewService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/api/dashboard/overview")
    public ResponseEntity<ResponseTextGuard.GuardedJson> overview(
            @RequestParam(name = "period", required = false) String period,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            @RequestParam(name = "source", required = false) String source,
            @RequestParam(name = "captureId", required = false) String captureId,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        DashboardOverviewResponse body = dashboardOverviewService.overview(principal, period, start, end, source, captureId,
                clientIpResolver.resolve(request));
        // T63: 응답 직전 글자 정책
        return ResponseEntity.ok(responseTextGuard.apply(body, principal.getRole(), ResponseTextCatalog.OVERVIEW));
    }
}
