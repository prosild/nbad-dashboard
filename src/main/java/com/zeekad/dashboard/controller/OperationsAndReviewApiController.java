package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ActionResultResponse;
import com.zeekad.dashboard.dto.OperationsApiResponse;
import com.zeekad.dashboard.dto.ReviewDecideRequest;
import com.zeekad.dashboard.dto.ReviewsApiResponse;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.DashboardOverviewService;
import com.zeekad.dashboard.service.IncidentQueryService;
import com.zeekad.dashboard.service.MaskingService;
import com.zeekad.dashboard.service.ResponseTextCatalog;
import com.zeekad.dashboard.service.ResponseTextGuard;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 운영 상태(/api/operations) 및 분석가 승인 대기(/api/reviews) REST API 컨트롤러.
 */
@RestController
@RequestMapping("/api")
public class OperationsAndReviewApiController {

    private final IncidentQueryService incidentQueryService;
    private final AnalystReviewDecisionService analystReviewDecisionService;
    private final ClientIpResolver clientIpResolver;
    private final MaskingService maskingService;
    private final DashboardOverviewService dashboardOverviewService;
    private final ResponseTextGuard responseTextGuard;

    public OperationsAndReviewApiController(IncidentQueryService incidentQueryService,
                                            AnalystReviewDecisionService analystReviewDecisionService,
                                            ClientIpResolver clientIpResolver,
                                            MaskingService maskingService,
                                            DashboardOverviewService dashboardOverviewService,
                                            ResponseTextGuard responseTextGuard) {
        this.responseTextGuard = responseTextGuard;
        this.dashboardOverviewService = dashboardOverviewService;
        this.incidentQueryService = incidentQueryService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
    }

    @GetMapping("/operations")
    public ResponseEntity<ResponseTextGuard.GuardedJson> operations(
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "period", required = false) String period,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            @RequestParam(name = "source", required = false) String source,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);
        // T24: period·source를 더했다. period가 없으면 지금처럼 전체다(호환).
        OperationsApiResponse body = dashboardOverviewService.operations(principal, period, start, end, source, captureId, clientIp);
        // T63: 응답 직전 글자 정책(Slack 요약의 파생 칸은 처리한 페이로드에서)
        return ResponseEntity.ok(responseTextGuard.applyOperations(body, principal.getRole()));
    }

    @GetMapping("/reviews")
    public ResponseEntity<ResponseTextGuard.GuardedJson> reviews(
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "pendingOnly", defaultValue = "false") boolean pendingOnly,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.ReviewsViewResult view = incidentQueryService.loadReviewsView(
                principal, captureId, pendingOnly, clientIp);

        boolean canDecideReview = principal.getRole() == UserRole.ANALYST || principal.getRole() == UserRole.ADMIN;
        ReviewsApiResponse body = new ReviewsApiResponse(
                maskingService.shouldMask(principal.getRole()),
                canDecideReview,
                view.allowedCaptures(),
                view.selectedCaptureId(),
                view.pendingOnly(),
                view.reviews()
        );
        // T63: 응답 직전 글자 정책
        return ResponseEntity.ok(responseTextGuard.apply(body, principal.getRole(), ResponseTextCatalog.REVIEWS));
    }

    @PostMapping("/reviews/decide")
    public ResponseEntity<ActionResultResponse> decideReview(
            @RequestBody ReviewDecideRequest body,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        AnalystReviewDecisionService.DecisionResult result = analystReviewDecisionService.decideFromReviews(
                principal,
                body.jobId(),
                body.incidentId(),
                body.action(),
                body.note(),
                clientIp);

        return ResponseEntity.status(result.httpStatus())
                .body(new ActionResultResponse(result.succeeded(), result.code(), result.message()));
    }
}
