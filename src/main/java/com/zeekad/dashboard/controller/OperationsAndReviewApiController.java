package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ActionResultResponse;
import com.zeekad.dashboard.dto.OperationsApiResponse;
import com.zeekad.dashboard.dto.ReviewDecideRequest;
import com.zeekad.dashboard.dto.ReviewsApiResponse;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.IncidentQueryService;
import com.zeekad.dashboard.service.MaskingService;
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

    public OperationsAndReviewApiController(IncidentQueryService incidentQueryService,
                                            AnalystReviewDecisionService analystReviewDecisionService,
                                            ClientIpResolver clientIpResolver,
                                            MaskingService maskingService) {
        this.incidentQueryService = incidentQueryService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
    }

    @GetMapping("/operations")
    public ResponseEntity<OperationsApiResponse> operations(
            @RequestParam(name = "captureId", required = false) String captureId,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.OperationsViewResult view = incidentQueryService.loadOperationsView(
                principal, captureId, clientIp);

        return ResponseEntity.ok(new OperationsApiResponse(
                maskingService.shouldMask(principal.getRole()),
                view.allowedCaptures(),
                view.selectedCaptureId(),
                view.jobs(),
                view.bundles(),
                view.feedbackSummaries(),
                view.slackSummaries()
        ));
    }

    @GetMapping("/reviews")
    public ResponseEntity<ReviewsApiResponse> reviews(
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "pendingOnly", defaultValue = "false") boolean pendingOnly,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.ReviewsViewResult view = incidentQueryService.loadReviewsView(
                principal, captureId, pendingOnly, clientIp);

        boolean canDecideReview = principal.getRole() == UserRole.ANALYST || principal.getRole() == UserRole.ADMIN;
        return ResponseEntity.ok(new ReviewsApiResponse(
                maskingService.shouldMask(principal.getRole()),
                canDecideReview,
                view.allowedCaptures(),
                view.selectedCaptureId(),
                view.pendingOnly(),
                view.reviews()
        ));
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
