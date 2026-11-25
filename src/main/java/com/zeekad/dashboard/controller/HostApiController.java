package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.HostRiskResponse;
import com.zeekad.dashboard.dto.RelatedHostIncidentsResponse;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.HostRiskService;
import com.zeekad.dashboard.service.RelatedHostIncidentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 호스트 위험도 목록과 상세의 같은 호스트 인시던트(T46). 인증 필요, 모든 역할(읽기 전용).
 * 기간·수집원·캡처 조건은 통합 큐와 같다(잘못된 값 400, 허용 밖 캡처 403·감사 기록).
 */
@RestController
public class HostApiController {

    private final HostRiskService hostRiskService;
    private final RelatedHostIncidentService relatedHostIncidentService;
    private final ClientIpResolver clientIpResolver;

    public HostApiController(HostRiskService hostRiskService,
                             RelatedHostIncidentService relatedHostIncidentService,
                             ClientIpResolver clientIpResolver) {
        this.hostRiskService = hostRiskService;
        this.relatedHostIncidentService = relatedHostIncidentService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/api/hosts")
    public ResponseEntity<HostRiskResponse> hosts(
            @RequestParam(name = "period", required = false) String period,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            @RequestParam(name = "source", required = false) String source,
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "sort", required = false) String sort,
            @RequestParam(name = "dir", required = false) String dir,
            @RequestParam(name = "roleTransitionOnly", required = false) String roleTransitionOnly,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "page", required = false) String page,
            @RequestParam(name = "size", required = false) String size,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        HostRiskService.HostParams params = new HostRiskService.HostParams(
                period, start, end, source, captureId, sort, dir, roleTransitionOnly, q, page, size);
        return ResponseEntity.ok(hostRiskService.load(principal, params, clientIpResolver.resolve(request)));
    }

    /** 상세와 같은 권한 검사·같은 경로 변수 형식(형식 오류 400, 없는 작업·순위와 허용 밖은 403·감사 기록) */
    @GetMapping("/api/incidents/{jobId}/rank/{queueRank}/related-host-incidents")
    public ResponseEntity<RelatedHostIncidentsResponse> relatedHostIncidents(
            @PathVariable("jobId") Long jobId,
            @PathVariable("queueRank") Integer queueRank,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        return ResponseEntity.ok(relatedHostIncidentService.load(principal, jobId, queueRank,
                clientIpResolver.resolve(request)));
    }
}
