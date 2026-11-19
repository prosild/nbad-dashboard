package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ActionResultResponse;
import com.zeekad.dashboard.dto.IncidentDetailApiResponse;
import com.zeekad.dashboard.dto.IncidentQueueResponse;
import com.zeekad.dashboard.dto.IncidentReviewDecisionRequest;
import com.zeekad.dashboard.dto.IncidentTransitionRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.IncidentDetailService;
import com.zeekad.dashboard.service.IncidentDetailView;
import com.zeekad.dashboard.service.IncidentQueryService;
import com.zeekad.dashboard.service.IncidentTransitionService;
import com.zeekad.dashboard.service.MaskingService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 이상탐지 조사 큐·사건 상세·상태 변경·사건 내 검토 결정 REST API 컨트롤러.
 */
@RestController
@RequestMapping("/api/incidents")
public class IncidentApiController {

    private final IncidentQueryService incidentQueryService;
    private final IncidentDetailService incidentDetailService;
    private final IncidentTransitionService incidentTransitionService;
    private final AnalystReviewDecisionService analystReviewDecisionService;
    private final ClientIpResolver clientIpResolver;
    private final MaskingService maskingService;

    public IncidentApiController(IncidentQueryService incidentQueryService,
                                 IncidentDetailService incidentDetailService,
                                 IncidentTransitionService incidentTransitionService,
                                 AnalystReviewDecisionService analystReviewDecisionService,
                                 ClientIpResolver clientIpResolver,
                                 MaskingService maskingService) {
        this.incidentQueryService = incidentQueryService;
        this.incidentDetailService = incidentDetailService;
        this.incidentTransitionService = incidentTransitionService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
    }

    @GetMapping
    public ResponseEntity<IncidentQueueResponse> listQueue(
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "jobId", required = false) Long jobId,
            @RequestParam(name = "pickedBy", required = false) String pickedBy,
            @RequestParam(name = "role", required = false) String role,
            @RequestParam(name = "asset", required = false) String asset,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "hasReport", required = false) String hasReport,
            @RequestParam(name = "wouldSend", required = false) String wouldSend,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.QueueViewResult view = incidentQueryService.loadQueueView(
                principal, captureId, jobId, pickedBy, role, asset, status, hasReport, wouldSend, clientIp);

        return ResponseEntity.ok(new IncidentQueueResponse(
                maskingService.shouldMask(principal.getRole()),
                view.allowedCaptures(),
                view.selectedCaptureId(),
                view.selectedJob(),
                view.captureJobs(),
                view.items(),
                view.availableModels(),
                view.availableRoles()
        ));
    }

    @GetMapping("/{jobId}/rank/{queueRank}")
    public ResponseEntity<IncidentDetailApiResponse> detail(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentDetailView detail = incidentDetailService.loadDetail(principal, jobId, queueRank, clientIp);
        boolean maskedView = maskingService.shouldMask(principal.getRole());
        boolean canDecideReview = principal.getRole() == UserRole.ANALYST || principal.getRole() == UserRole.ADMIN;

        return ResponseEntity.ok(new IncidentDetailApiResponse(maskedView, canDecideReview, detail));
    }

    @PostMapping("/{jobId}/rank/{queueRank}/transition")
    public ResponseEntity<ActionResultResponse> transition(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            @RequestBody IncidentTransitionRequest body,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentTransitionService.TransitionResult result = incidentTransitionService.transition(
                principal,
                jobId,
                queueRank,
                body.toStatus(),
                body.resolution(),
                body.reason(),
                clientIp);

        return ResponseEntity.status(result.httpStatus())
                .body(new ActionResultResponse(result.succeeded(), result.code(), result.message()));
    }

    @PostMapping("/{jobId}/rank/{queueRank}/review-decision")
    public ResponseEntity<ActionResultResponse> reviewDecision(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            @RequestBody IncidentReviewDecisionRequest body,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        AnalystReviewDecisionService.DecisionResult result = analystReviewDecisionService.decideFromIncidentDetail(
                principal,
                jobId,
                queueRank,
                body.action(),
                body.note(),
                clientIp);

        return ResponseEntity.status(result.httpStatus())
                .body(new ActionResultResponse(result.succeeded(), result.code(), result.message()));
    }
}
