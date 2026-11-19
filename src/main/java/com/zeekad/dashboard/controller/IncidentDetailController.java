package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.AnalystReviewDecisionService;
import com.zeekad.dashboard.service.IncidentDetailService;
import com.zeekad.dashboard.service.IncidentDetailView;
import com.zeekad.dashboard.service.IncidentTransitionService;
import com.zeekad.dashboard.service.MaskingService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * 사건 상세 조회(/incidents/{jobId}/rank/{queueRank}) 및 상태 전이 컨트롤러.
 */
@Controller
@RequestMapping("/incidents/{jobId}/rank/{queueRank}")
public class IncidentDetailController {

    private final IncidentDetailService incidentDetailService;
    private final IncidentTransitionService incidentTransitionService;
    private final AnalystReviewDecisionService analystReviewDecisionService;
    private final ClientIpResolver clientIpResolver;
    private final MaskingService maskingService;

    public IncidentDetailController(IncidentDetailService incidentDetailService,
                                    IncidentTransitionService incidentTransitionService,
                                    AnalystReviewDecisionService analystReviewDecisionService,
                                    ClientIpResolver clientIpResolver,
                                    MaskingService maskingService) {
        this.incidentDetailService = incidentDetailService;
        this.incidentTransitionService = incidentTransitionService;
        this.analystReviewDecisionService = analystReviewDecisionService;
        this.clientIpResolver = clientIpResolver;
        this.maskingService = maskingService;
    }

    @GetMapping
    public String detail(@PathVariable("jobId") Long jobId,
                         @PathVariable("queueRank") Integer queueRank,
                         Authentication authentication,
                         HttpServletRequest request,
                         Model model) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentDetailView detail = incidentDetailService.loadDetail(principal, jobId, queueRank, clientIp);

        model.addAttribute("activeMenu", "incidents");
        model.addAttribute("maskedView", maskingService.shouldMask(principal.getRole()));
        model.addAttribute("detail", detail);
        return "incidents/detail";
    }

    @PostMapping("/transition")
    public String transition(@PathVariable("jobId") Long jobId,
                             @PathVariable("queueRank") Integer queueRank,
                             @RequestParam(name = "toStatus", required = false) String toStatus,
                             @RequestParam(name = "resolution", required = false) String resolution,
                             @RequestParam(name = "reason", required = false) String reason,
                             Authentication authentication,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        IncidentTransitionService.TransitionResult result = incidentTransitionService.transition(
                principal, jobId, queueRank, toStatus, resolution, reason, clientIp);

        if (result.succeeded()) {
            redirectAttributes.addFlashAttribute("transitionSuccess", result.message());
        } else {
            redirectAttributes.addFlashAttribute("transitionError", result.message());
        }
        return "redirect:/incidents/" + jobId + "/rank/" + queueRank;
    }

    @PostMapping("/review-decision")
    public String reviewDecision(@PathVariable("jobId") Long jobId,
                                 @PathVariable("queueRank") Integer queueRank,
                                 @RequestParam(name = "action", required = false) String action,
                                 @RequestParam(name = "note", required = false) String note,
                                 Authentication authentication,
                                 HttpServletRequest request,
                                 RedirectAttributes redirectAttributes) {
        DashboardUserPrincipal principal = requirePrincipal(authentication);
        String clientIp = clientIpResolver.resolve(request);

        AnalystReviewDecisionService.DecisionResult result = analystReviewDecisionService.decideFromIncidentDetail(
                principal, jobId, queueRank, action, note, clientIp);

        if (result.succeeded()) {
            redirectAttributes.addFlashAttribute("reviewSuccess", result.message());
        } else {
            redirectAttributes.addFlashAttribute("reviewError", result.message());
        }
        return "redirect:/incidents/" + jobId + "/rank/" + queueRank;
    }

    private DashboardUserPrincipal requirePrincipal(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof DashboardUserPrincipal principal) {
            return principal;
        }
        throw new AccessDeniedException("인증된 사용자 주체를 확인할 수 없습니다.");
    }
}
