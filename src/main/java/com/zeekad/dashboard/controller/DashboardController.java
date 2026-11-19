package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.IncidentQueryService;
import com.zeekad.dashboard.service.MaskingService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * 조사 큐(/, /incidents), 운영 상태(/operations), 분석가 승인 대기(/reviews) 화면 컨트롤러.
 */
@Controller
public class DashboardController {

    private final IncidentQueryService incidentQueryService;
    private final AnalystReviewDecisionService analystReviewDecisionService;
    private final ClientIpResolver clientIpResolver;
    private final MaskingService maskingService;

    public DashboardController(IncidentQueryService incidentQueryService,
                               AnalystReviewDecisionService analystReviewDecisionService,
                               ClientIpResolver clientIpResolver,
                               MaskingService maskingService) {
        this.incidentQueryService = incidentQueryService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
    }

    @GetMapping({"/", "/incidents"})
    public String incidentQueue(@RequestParam(name = "captureId", required = false) String captureId,
                                @RequestParam(name = "jobId", required = false) Long jobId,
                                @RequestParam(name = "pickedBy", required = false) String pickedBy,
                                @RequestParam(name = "role", required = false) String role,
                                @RequestParam(name = "asset", required = false) String asset,
                                @RequestParam(name = "status", required = false) String status,
                                @RequestParam(name = "hasReport", required = false) String hasReport,
                                @RequestParam(name = "wouldSend", required = false) String wouldSend,
                                Authentication authentication,
                                HttpServletRequest request,
                                Model model) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.QueueViewResult view = incidentQueryService.loadQueueView(
                principal, captureId, jobId, pickedBy, role, asset, status, hasReport, wouldSend, clientIp);

        model.addAttribute("activeMenu", "incidents");
        model.addAttribute("maskedView", maskingService.shouldMask(principal.getRole()));
        model.addAttribute("allowedCaptures", view.allowedCaptures());
        model.addAttribute("selectedCaptureId", view.selectedCaptureId());
        model.addAttribute("selectedJob", view.selectedJob());
        model.addAttribute("captureJobs", view.captureJobs());
        model.addAttribute("incidents", view.items());
        model.addAttribute("availableModels", view.availableModels());
        model.addAttribute("availableRoles", view.availableRoles());

        model.addAttribute("filterPickedBy", pickedBy == null ? "" : pickedBy.trim());
        model.addAttribute("filterRole", role == null ? "" : role.trim());
        model.addAttribute("filterAsset", asset == null ? "" : asset.trim());
        model.addAttribute("filterStatus", status == null ? "" : status.trim());
        model.addAttribute("filterHasReport", hasReport == null ? "" : hasReport.trim());
        model.addAttribute("filterWouldSend", wouldSend == null ? "" : wouldSend.trim());
        return "incidents/queue";
    }

    @GetMapping("/operations")
    public String operations(@RequestParam(name = "captureId", required = false) String captureId,
                             Authentication authentication,
                             HttpServletRequest request,
                             Model model) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.OperationsViewResult view = incidentQueryService.loadOperationsView(
                principal, captureId, clientIp);

        model.addAttribute("activeMenu", "operations");
        model.addAttribute("maskedView", maskingService.shouldMask(principal.getRole()));
        model.addAttribute("allowedCaptures", view.allowedCaptures());
        model.addAttribute("selectedCaptureId", view.selectedCaptureId() == null ? "" : view.selectedCaptureId());
        model.addAttribute("jobs", view.jobs());
        model.addAttribute("bundles", view.bundles());
        model.addAttribute("feedbackSummaries", view.feedbackSummaries());
        model.addAttribute("slackSummaries", view.slackSummaries());
        return "operations/index";
    }

    @GetMapping("/reviews")
    public String reviews(@RequestParam(name = "captureId", required = false) String captureId,
                          @RequestParam(name = "pendingOnly", defaultValue = "false") boolean pendingOnly,
                          Authentication authentication,
                          HttpServletRequest request,
                          Model model) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentQueryService.ReviewsViewResult view = incidentQueryService.loadReviewsView(
                principal, captureId, pendingOnly, clientIp);

        model.addAttribute("activeMenu", "reviews");
        model.addAttribute("maskedView", maskingService.shouldMask(principal.getRole()));
        model.addAttribute("canDecideReview",
                principal.getRole() == UserRole.ANALYST || principal.getRole() == UserRole.ADMIN);
        model.addAttribute("allowedCaptures", view.allowedCaptures());
        model.addAttribute("selectedCaptureId", view.selectedCaptureId() == null ? "" : view.selectedCaptureId());
        model.addAttribute("pendingOnly", view.pendingOnly());
        model.addAttribute("reviews", view.reviews());
        return "reviews/index";
    }

    @PostMapping("/reviews/decide")
    public String decideReview(@RequestParam(name = "jobId", required = false) Long jobId,
                               @RequestParam(name = "incidentId", required = false) String incidentId,
                               @RequestParam(name = "action", required = false) String action,
                               @RequestParam(name = "note", required = false) String note,
                               @RequestParam(name = "captureId", required = false) String captureId,
                               @RequestParam(name = "pendingOnly", defaultValue = "false") boolean pendingOnly,
                               Authentication authentication,
                               HttpServletRequest request,
                               RedirectAttributes redirectAttributes) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        AnalystReviewDecisionService.DecisionResult result = analystReviewDecisionService.decideFromReviews(
                principal, jobId, incidentId, action, note, clientIp);

        if (result.succeeded()) {
            redirectAttributes.addFlashAttribute("reviewSuccess", result.message());
        } else {
            redirectAttributes.addFlashAttribute("reviewError", result.message());
        }
        if (captureId != null && !captureId.isBlank()) {
            redirectAttributes.addAttribute("captureId", captureId.trim());
        }
        if (pendingOnly) {
            redirectAttributes.addAttribute("pendingOnly", "true");
        }
        return "redirect:/reviews";
    }

    private DashboardUserPrincipal requirePrincipal(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof DashboardUserPrincipal principal) {
            return principal;
        }
        throw new AccessDeniedException("인증된 사용자 주체를 확인할 수 없습니다.");
    }
}
