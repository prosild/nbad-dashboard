package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ActionResultResponse;
import com.zeekad.dashboard.dto.ApiErrorResponse;
import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.dto.IncidentDetailApiResponse;
import com.zeekad.dashboard.dto.IncidentQueueResponse;
import com.zeekad.dashboard.dto.IncidentReviewDecisionRequest;
import com.zeekad.dashboard.dto.IncidentTransitionRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.IncidentAssignmentService;
import com.zeekad.dashboard.service.IncidentDetailService;
import com.zeekad.dashboard.service.IncidentDetailView;
import com.zeekad.dashboard.service.IncidentQueryService;
import com.zeekad.dashboard.service.IncidentNoLocationService;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentRefService;
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
    private final IncidentQueueService incidentQueueService;
    private final IncidentAssignmentService incidentAssignmentService;
    private final IncidentRefService incidentRefService;
    private final IncidentNoLocationService incidentNoLocationService;

    public IncidentApiController(IncidentQueryService incidentQueryService,
                                 IncidentDetailService incidentDetailService,
                                 IncidentTransitionService incidentTransitionService,
                                 AnalystReviewDecisionService analystReviewDecisionService,
                                 ClientIpResolver clientIpResolver,
                                 MaskingService maskingService,
                                 IncidentQueueService incidentQueueService,
                                 IncidentAssignmentService incidentAssignmentService,
                                 IncidentRefService incidentRefService,
                                 IncidentNoLocationService incidentNoLocationService) {
        this.incidentRefService = incidentRefService;
        this.incidentNoLocationService = incidentNoLocationService;
        this.incidentAssignmentService = incidentAssignmentService;
        this.incidentQueryService = incidentQueryService;
        this.incidentDetailService = incidentDetailService;
        this.incidentTransitionService = incidentTransitionService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
        this.incidentQueueService = incidentQueueService;
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

    /**
     * T27 인시던트 번호 → 지금 위치. 최신 큐에 있으면 그 작업·순위(latest=true), 없으면 그 인시던트가 든 가장 최근 성공 작업(latest=false).
     * 번호 형식이 틀리면 400(감사 없음). 없는 번호·허용 밖 캡처·zeekad에 없는 인시던트는 같은 403과 ACCESS_DENIED_IDOR 감사.
     */
    @GetMapping("/no/{incidentNo}")
    public ResponseEntity<IncidentNoLocationService.Location> locateByNo(
            @PathVariable("incidentNo") String incidentNo,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);
        return ResponseEntity.ok(incidentNoLocationService.locate(principal, incidentNo, clientIp));
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

        // T25 담당: VIEWER도 담당자 이름을 본다(상태 이력 변경자와 같은 기준). 바꾸기는 ANALYST·ADMIN이고 종결이 아닐 때만.
        String incidentId = incidentQueueService.rawIncidentId(jobId, queueRank);
        java.util.Map<String, String> displayMap = incidentQueryService.loadUserDisplayMap();
        boolean closed = "closed".equals(detail.currentStatus());
        return ResponseEntity.ok(new IncidentDetailApiResponse(maskedView, canDecideReview, detail,
                incidentQueueService.metaFor(principal, jobId, queueRank),
                incidentAssignmentService.currentView(incidentId, displayMap),
                incidentAssignmentService.historyView(incidentId, displayMap),
                canDecideReview && !closed,
                incidentRefService.numberFor(incidentId)));
    }

    /** T25 담당자 지정·변경·해제. 본문 { assignee: username|null, expected: username|null }. CSRF 필요 */
    @PostMapping("/{jobId}/rank/{queueRank}/assignment")
    public ResponseEntity<?> assign(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            @RequestBody AssignmentDtos.AssignRequest body,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);
        if (body == null) {
            return ResponseEntity.badRequest().body(new ApiErrorResponse(400, "INVALID_REQUEST", "요청 형식이 올바르지 않습니다."));
        }
        IncidentAssignmentService.AssignResult result = incidentAssignmentService.assign(
                principal, jobId, queueRank, body.assignee(), body.expected(), clientIp);
        if (!result.succeeded()) {
            return ResponseEntity.status(result.httpStatus())
                    .body(new ApiErrorResponse(result.httpStatus(), result.code(), result.message()));
        }
        return ResponseEntity.ok(new AssignmentDtos.AssignResponse(result.assignment()));
    }

    /** T25 담당자가 될 수 있는 사용자. ANALYST·ADMIN만(다른 사용자의 허용 캡처를 간접적으로 드러내므로) */
    @GetMapping("/{jobId}/rank/{queueRank}/assignees")
    public ResponseEntity<AssignmentDtos.CandidatesResponse> assignees(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);
        return ResponseEntity.ok(new AssignmentDtos.CandidatesResponse(
                incidentAssignmentService.candidates(principal, jobId, queueRank, clientIp)));
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
