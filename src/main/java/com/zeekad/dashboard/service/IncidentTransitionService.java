package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * zeekadWriteDataSource(dashboard.transition_incident) 기반 사건 상태 전이 서비스.
 */
@Service
public class IncidentTransitionService {

    private static final Logger log = LoggerFactory.getLogger(IncidentTransitionService.class);

    private static final Set<String> ALLOWED_TARGET_STATUSES = Set.of("investigating", "closed");
    private static final Set<String> ALLOWED_RESOLUTIONS = Set.of("true_positive", "false_positive", "benign");

    private final ZeekadWriteMapper zeekadWriteMapper;
    private final CaptureAccessService captureAccessService;
    private final AuditService auditService;

    public IncidentTransitionService(ZeekadWriteMapper zeekadWriteMapper,
                                     CaptureAccessService captureAccessService,
                                     AuditService auditService) {
        this.zeekadWriteMapper = zeekadWriteMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
    }

    public TransitionResult transition(DashboardUserPrincipal principal,
                                       Long jobId,
                                       Integer queueRank,
                                       String toStatus,
                                       String resolution,
                                       String reason,
                                       String clientIp) {
        IncidentQueueItem item = captureAccessService.requireIncidentAccessByRank(
                principal, jobId, queueRank, clientIp);

        if (principal == null || (principal.getRole() != UserRole.ANALYST && principal.getRole() != UserRole.ADMIN)) {
            throw new AccessDeniedException("사건 상태를 변경할 권한이 없습니다.");
        }

        String normalizedTarget = toStatus == null ? "" : toStatus.trim().toLowerCase(Locale.ROOT);
        if (!ALLOWED_TARGET_STATUSES.contains(normalizedTarget)) {
            return TransitionResult.failure(400, "INVALID_REQUEST", "허용되지 않는 상태 변경 요청입니다.");
        }

        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.isEmpty()) {
            return TransitionResult.failure(400, "INVALID_REQUEST", "상태 변경 사유를 입력해 주세요.");
        }

        String effectiveResolution = null;
        if ("closed".equals(normalizedTarget)) {
            String normalizedResolution = resolution == null ? "" : resolution.trim().toLowerCase(Locale.ROOT);
            if (!ALLOWED_RESOLUTIONS.contains(normalizedResolution)) {
                return TransitionResult.failure(
                        400,
                        "INVALID_REQUEST",
                        "사건 종료(closed) 시 결론(true_positive, false_positive, benign)을 선택해야 합니다.");
            }
            effectiveResolution = normalizedResolution;
        }

        String actorUsername = principal.getUsername();
        try {
            zeekadWriteMapper.transitionIncident(
                    jobId,
                    item.getIncidentId(),
                    normalizedTarget,
                    actorUsername,
                    cleanReason,
                    effectiveResolution
            );
        } catch (RuntimeException ex) {
            SQLException sqlEx = SqlErrorSanitizer.findSqlException(ex);
            if (sqlEx != null) {
                String sqlState = sqlEx.getSQLState();
                if ("22023".equals(sqlState)) {
                    log.warn("사건 상태 전이 거부(SQLSTATE 22023): jobId={}, rank={}, actor={}",
                            jobId, queueRank, actorUsername);
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "상태 변경 규칙에 위배되었거나 다른 사용자가 먼저 상태를 변경했습니다.");
                    return TransitionResult.failure(409, "CONFLICT", safeMsg + SqlErrorSanitizer.REFRESH_GUIDE);
                }
                if ("02000".equals(sqlState)) {
                    log.warn("사건 상태 전이 대상 없음(SQLSTATE 02000): jobId={}, rank={}", jobId, queueRank);
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "대상 사건을 찾을 수 없습니다.");
                    return TransitionResult.failure(404, "NOT_FOUND", safeMsg + SqlErrorSanitizer.REFRESH_GUIDE);
                }
            }
            log.error("사건 상태 전이 중 예기치 않은 오류: jobId={}, rank={}", jobId, queueRank, ex);
            return TransitionResult.failure(500, "INTERNAL_ERROR",
                    "상태 변경 처리 중 오류가 발생했습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        }

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("toStatus", normalizedTarget);
        if (effectiveResolution != null) {
            detail.put("resolution", effectiveResolution);
        }
        detail.put("reason", cleanReason);

        auditService.record(
                actorUsername,
                principal.getRole().name(),
                AuditActionType.INCIDENT_STATUS_TRANSITION,
                item.getCaptureId(),
                jobId,
                item.getIncidentId(),
                detail,
                clientIp
        );

        String successMessage = "closed".equals(normalizedTarget)
                ? "사건이 종료(closed, 결론: " + effectiveResolution + ") 상태로 변경되었습니다."
                : "사건이 확인 중(investigating) 상태로 변경되었습니다.";
        return TransitionResult.success(successMessage);
    }

    public record TransitionResult(boolean succeeded, int httpStatus, String code, String message) {
        public static TransitionResult success(String message) {
            return new TransitionResult(true, 200, "OK", message);
        }

        public static TransitionResult failure(int httpStatus, String code, String message) {
            return new TransitionResult(false, httpStatus, code, message);
        }
    }
}
