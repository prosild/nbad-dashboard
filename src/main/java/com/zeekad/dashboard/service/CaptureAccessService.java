package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 캡처 단위 객체 수준 권한(IDOR 차단) 및 감사 로그 기록 서비스.
 */
@Service
public class CaptureAccessService {

    private final ZeekadReadMapper zeekadReadMapper;
    private final AuditService auditService;

    public CaptureAccessService(ZeekadReadMapper zeekadReadMapper, AuditService auditService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.auditService = auditService;
    }

    public List<String> listAllowedCaptures(DashboardUserPrincipal principal) {
        if (principal == null) {
            return List.of();
        }
        return zeekadReadMapper.findDistinctCaptureIds().stream()
                .filter(principal::isCaptureAllowed)
                .toList();
    }

    public void requireCaptureAccess(DashboardUserPrincipal principal, String captureId, String clientIp) {
        if (principal == null || captureId == null || captureId.isBlank()) {
            recordIdorAndThrow(principal, captureId, null, null, "missing_capture_or_principal", clientIp);
        }
        if (!principal.isCaptureAllowed(captureId)) {
            recordIdorAndThrow(principal, captureId, null, null, "capture_pattern_denied", clientIp);
        }
        List<String> existingCaptures = zeekadReadMapper.findDistinctCaptureIds();
        if (!existingCaptures.contains(captureId)) {
            recordIdorAndThrow(principal, captureId, null, null, "capture_not_found", clientIp);
        }
    }

    public ScoringJob requireJobAccess(DashboardUserPrincipal principal,
                                       Long jobId,
                                       String expectedCaptureId,
                                       String clientIp) {
        if (principal == null || jobId == null) {
            recordIdorAndThrow(principal, expectedCaptureId, jobId, null, "missing_job_or_principal", clientIp);
        }
        ScoringJob job = zeekadReadMapper.findScoringJobById(jobId);
        if (job == null) {
            recordIdorAndThrow(principal, expectedCaptureId, jobId, null, "job_not_found", clientIp);
        }
        if (!principal.isCaptureAllowed(job.getCaptureId())) {
            recordIdorAndThrow(principal, job.getCaptureId(), jobId, null, "job_capture_pattern_denied", clientIp);
        }
        if (expectedCaptureId != null && !expectedCaptureId.isBlank()
                && !expectedCaptureId.equals(job.getCaptureId())) {
            recordIdorAndThrow(principal, expectedCaptureId, jobId, null, "capture_job_mismatch", clientIp);
        }
        return job;
    }

    public IncidentQueueItem requireIncidentAccess(DashboardUserPrincipal principal,
                                                   Long jobId,
                                                   String incidentId,
                                                   String clientIp) {
        ScoringJob job = requireJobAccess(principal, jobId, null, clientIp);
        if (incidentId == null || incidentId.isBlank()) {
            recordIdorAndThrow(principal, job.getCaptureId(), jobId, incidentId, "missing_incident_id", clientIp);
        }
        IncidentQueueItem item = zeekadReadMapper.findIncidentQueueItemByJobAndIncident(jobId, incidentId);
        if (item == null) {
            recordIdorAndThrow(principal, job.getCaptureId(), jobId, incidentId, "incident_not_found", clientIp);
        }
        return item;
    }

    public IncidentQueueItem requireIncidentAccessByRank(DashboardUserPrincipal principal,
                                                         Long jobId,
                                                         Integer queueRank,
                                                         String clientIp) {
        ScoringJob job = requireJobAccess(principal, jobId, null, clientIp);
        if (queueRank == null || queueRank < 1) {
            recordIdorAndThrow(principal, job.getCaptureId(), jobId, null, "invalid_queue_rank", clientIp);
        }
        IncidentQueueItem item = zeekadReadMapper.findIncidentQueueItemByJobAndRank(jobId, queueRank);
        if (item == null) {
            recordIdorAndThrow(principal, job.getCaptureId(), jobId, null, "incident_rank_not_found", clientIp);
        }
        return item;
    }

    public void recordUnmaskedViewIfPrivileged(DashboardUserPrincipal principal,
                                               String captureId,
                                               Long jobId,
                                               String incidentId,
                                               String clientIp) {
        if (principal == null) {
            return;
        }
        if (principal.getRole() == UserRole.ANALYST || principal.getRole() == UserRole.ADMIN) {
            auditService.record(
                    principal.getUsername(),
                    principal.getRole().name(),
                    AuditActionType.INCIDENT_VIEW_UNMASKED,
                    captureId,
                    jobId,
                    incidentId,
                    Map.of("view", "unmasked"),
                    clientIp
            );
        }
    }

    private void recordIdorAndThrow(DashboardUserPrincipal principal,
                                    String captureId,
                                    Long jobId,
                                    String incidentId,
                                    String reason,
                                    String clientIp) {
        String actor = principal != null ? principal.getUsername() : "anonymous";
        String role = principal != null && principal.getRole() != null ? principal.getRole().name() : "UNKNOWN";
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("reason", reason);
        if (captureId != null) {
            detail.put("requestedCaptureId", captureId);
        }
        if (jobId != null) {
            detail.put("requestedJobId", jobId);
        }
        if (incidentId != null) {
            detail.put("requestedIncidentId", incidentId);
        }
        auditService.record(
                actor,
                role,
                AuditActionType.ACCESS_DENIED_IDOR,
                captureId,
                jobId,
                incidentId,
                detail,
                clientIp
        );
        throw new AccessDeniedException("요청한 캡처 또는 작업에 접근할 권한이 없습니다.");
    }
}
