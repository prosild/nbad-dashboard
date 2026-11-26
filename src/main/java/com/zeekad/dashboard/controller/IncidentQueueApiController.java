package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.QueueNeighborsResponse;
import com.zeekad.dashboard.dto.QueueNewCountResponse;
import com.zeekad.dashboard.dto.TimeContextResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.ResponseTextCatalog;
import com.zeekad.dashboard.service.ResponseTextGuard;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 통합 인시던트 큐 API(T23). 허용 캡처 안만 보고, 허용 밖 captureId·jobId는 403과 IDOR 감사 기록이다.
 * VIEWER 행은 역할 마스킹을 거친다. 작업 단위 GET /api/incidents는 그대로 둔다(작업 결과 조회·검증용).
 */
@RestController
public class IncidentQueueApiController {

    private final IncidentQueueService incidentQueueService;
    private final ClientIpResolver clientIpResolver;
    private final ResponseTextGuard responseTextGuard;

    public IncidentQueueApiController(IncidentQueueService incidentQueueService, ClientIpResolver clientIpResolver,
                                      ResponseTextGuard responseTextGuard) {
        this.responseTextGuard = responseTextGuard;
        this.incidentQueueService = incidentQueueService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/api/incidents/queue")
    public ResponseEntity<ResponseTextGuard.GuardedJson> queue(
            @RequestParam(name = "period", required = false) String period,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            @RequestParam(name = "source", required = false) String source,
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "priority", required = false) String priority,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "reviewPending", required = false) String reviewPending,
            @RequestParam(name = "alerted", required = false) String alerted,
            @RequestParam(name = "pickedBy", required = false) String pickedBy,
            @RequestParam(name = "role", required = false) String role,
            @RequestParam(name = "hasReport", required = false) String hasReport,
            @RequestParam(name = "wouldSend", required = false) String wouldSend,
            @RequestParam(name = "asset", required = false) String asset,
            @RequestParam(name = "assignee", required = false) String assignee,
            @RequestParam(name = "overdue", required = false) String overdue,
            @RequestParam(name = "thread", required = false) String thread,
            @RequestParam(name = "hostIp", required = false) String hostIp,
            @RequestParam(name = "attack", required = false) String attack,
            @RequestParam(name = "sort", required = false) String sort,
            @RequestParam(name = "dir", required = false) String dir,
            @RequestParam(name = "page", required = false) String page,
            @RequestParam(name = "size", required = false) String size,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        QueueParams params = new QueueParams(period, source, captureId, priority, status, reviewPending, alerted,
                pickedBy, role, hasReport, wouldSend, asset, sort, dir, page, size, assignee, overdue, start, end, thread,
                hostIp, attack);
        UnifiedQueueResponse body = incidentQueueService.loadQueue(principal, params, clientIpResolver.resolve(request));
        // T63: 응답 직전 글자 정책(분석가 표지·모든 역할 상한). 검색·정렬·쪽 나눔은 원문으로 끝났다
        return ResponseEntity.ok(responseTextGuard.apply(body, principal.getRole(), ResponseTextCatalog.QUEUE));
    }

    @GetMapping("/api/incidents/queue/new-count")
    public ResponseEntity<ResponseTextGuard.GuardedJson> newCount(
            @RequestParam(name = "since", required = false) String since,
            @RequestParam(name = "source", required = false) String source,
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "priority", required = false) String priority,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "reviewPending", required = false) String reviewPending,
            @RequestParam(name = "alerted", required = false) String alerted,
            @RequestParam(name = "pickedBy", required = false) String pickedBy,
            @RequestParam(name = "role", required = false) String role,
            @RequestParam(name = "hasReport", required = false) String hasReport,
            @RequestParam(name = "wouldSend", required = false) String wouldSend,
            @RequestParam(name = "asset", required = false) String asset,
            @RequestParam(name = "assignee", required = false) String assignee,
            @RequestParam(name = "overdue", required = false) String overdue,
            @RequestParam(name = "thread", required = false) String thread,
            @RequestParam(name = "hostIp", required = false) String hostIp,
            @RequestParam(name = "attack", required = false) String attack,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        // 기간 조건 없이 since 이후만 센다(period는 받지 않는다). 정렬은 수에 영향이 없다.
        QueueParams params = new QueueParams("all", source, captureId, priority, status, reviewPending, alerted,
                pickedBy, role, hasReport, wouldSend, asset, null, null, null, null, assignee, overdue, null, null, thread,
                hostIp, attack);
        QueueNewCountResponse body = incidentQueueService.countNew(principal, params, since, clientIpResolver.resolve(request));
        return ResponseEntity.ok(responseTextGuard.apply(body, principal.getRole(), ResponseTextCatalog.QUEUE_NEW_COUNT));
    }

    @GetMapping("/api/incidents/queue/neighbors")
    public ResponseEntity<ResponseTextGuard.GuardedJson> neighbors(
            @RequestParam(name = "jobId") Long jobId,
            @RequestParam(name = "queueRank") Integer queueRank,
            @RequestParam(name = "period", required = false) String period,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            @RequestParam(name = "source", required = false) String source,
            @RequestParam(name = "captureId", required = false) String captureId,
            @RequestParam(name = "priority", required = false) String priority,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "reviewPending", required = false) String reviewPending,
            @RequestParam(name = "alerted", required = false) String alerted,
            @RequestParam(name = "pickedBy", required = false) String pickedBy,
            @RequestParam(name = "role", required = false) String role,
            @RequestParam(name = "hasReport", required = false) String hasReport,
            @RequestParam(name = "wouldSend", required = false) String wouldSend,
            @RequestParam(name = "asset", required = false) String asset,
            @RequestParam(name = "assignee", required = false) String assignee,
            @RequestParam(name = "overdue", required = false) String overdue,
            @RequestParam(name = "thread", required = false) String thread,
            @RequestParam(name = "hostIp", required = false) String hostIp,
            @RequestParam(name = "attack", required = false) String attack,
            @RequestParam(name = "sort", required = false) String sort,
            @RequestParam(name = "dir", required = false) String dir,
            Authentication authentication,
            HttpServletRequest request) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        QueueParams params = new QueueParams(period, source, captureId, priority, status, reviewPending, alerted,
                pickedBy, role, hasReport, wouldSend, asset, sort, dir, null, null, assignee, overdue, start, end, thread,
                hostIp, attack);
        QueueNeighborsResponse body = incidentQueueService.neighbors(
                principal, jobId, queueRank, params, clientIpResolver.resolve(request));
        return ResponseEntity.ok(responseTextGuard.apply(body, principal.getRole(), ResponseTextCatalog.QUEUE_NEIGHBORS));
    }

    @GetMapping("/api/time-context")
    public ResponseEntity<TimeContextResponse> timeContext(Authentication authentication) {
        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        return ResponseEntity.ok(incidentQueueService.timeContext(principal));
    }
}
