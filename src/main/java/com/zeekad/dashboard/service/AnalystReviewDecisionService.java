package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
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
 * zeekadWriteDataSource(dashboard.decide_review) 기반 분석가 검토 결정 서비스.
 */
@Service
public class AnalystReviewDecisionService {

    private static final Logger log = LoggerFactory.getLogger(AnalystReviewDecisionService.class);
    private static final Set<String> ALLOWED_ACTIONS = Set.of("confirm", "dismiss");

    private final ZeekadWriteMapper zeekadWriteMapper;
    private final CaptureAccessService captureAccessService;
    private final AuditService auditService;

    public AnalystReviewDecisionService(ZeekadWriteMapper zeekadWriteMapper,
                                        CaptureAccessService captureAccessService,
                                        AuditService auditService) {
        this.zeekadWriteMapper = zeekadWriteMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
    }

    public DecisionResult decideFromReviews(DashboardUserPrincipal principal,
                                            Long reviewJobId,
                                            String incidentId,
                                            String action,
                                            String note,
                                            String clientIp) {
        ScoringJob job = captureAccessService.requireJobAccess(principal, reviewJobId, null, clientIp);
        requireAnalystOrAdmin(principal);

        String cleanIncidentId = incidentId == null ? "" : incidentId.trim();
        if (cleanIncidentId.isEmpty()) {
            return DecisionResult.failure(400, "INVALID_REQUEST",
                    "검토 대상 사건 ID가 누락되었습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        }
        return executeDecision(principal, job.getCaptureId(), reviewJobId, cleanIncidentId, action, note, clientIp);
    }

    public DecisionResult decideFromIncidentDetail(DashboardUserPrincipal principal,
                                                   Long jobId,
                                                   Integer queueRank,
                                                   String action,
                                                   String note,
                                                   String clientIp) {
        IncidentQueueItem rawIncident = captureAccessService.requireIncidentAccessByRank(
                principal, jobId, queueRank, clientIp);
        requireAnalystOrAdmin(principal);

        Long reportJobId = rawIncident.getZeekadReportJobId();
        if (reportJobId == null) {
            return DecisionResult.failure(
                    404,
                    "NOT_FOUND",
                    "이 사건에는 연결된 분석가 검토 작업이 없습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        }
        captureAccessService.requireJobAccess(principal, reportJobId, rawIncident.getCaptureId(), clientIp);
        return executeDecision(
                principal,
                rawIncident.getCaptureId(),
                reportJobId,
                rawIncident.getIncidentId(),
                action,
                note,
                clientIp
        );
    }

    private void requireAnalystOrAdmin(DashboardUserPrincipal principal) {
        if (principal == null || (principal.getRole() != UserRole.ANALYST && principal.getRole() != UserRole.ADMIN)) {
            throw new AccessDeniedException("분석가 검토 결정을 처리할 권한이 없습니다.");
        }
    }

    private DecisionResult executeDecision(DashboardUserPrincipal principal,
                                           String captureId,
                                           Long reviewJobId,
                                           String incidentId,
                                           String action,
                                           String note,
                                           String clientIp) {
        String normalizedAction = action == null ? "" : action.trim().toLowerCase(Locale.ROOT);
        if (!ALLOWED_ACTIONS.contains(normalizedAction)) {
            return DecisionResult.failure(400, "INVALID_REQUEST",
                    "허용되지 않는 검토 결정 값입니다. (confirm 또는 dismiss만 허용)");
        }

        String cleanNote = (note == null || note.trim().isEmpty()) ? null : note.trim();
        String analystUsername = principal.getUsername();

        try {
            zeekadWriteMapper.decideReview(reviewJobId, incidentId, normalizedAction, analystUsername, cleanNote);
        } catch (RuntimeException ex) {
            SQLException sqlEx = SqlErrorSanitizer.findSqlException(ex);
            if (sqlEx != null) {
                String sqlState = sqlEx.getSQLState();
                if ("22023".equals(sqlState)) {
                    log.warn("분석가 검토 결정 거부(SQLSTATE 22023): reviewJobId={}, incidentId={}, analyst={}",
                            reviewJobId, incidentId, analystUsername);
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "검토 결정 규칙에 위배되었거나 이미 다른 분석가가 결정했습니다.");
                    return DecisionResult.failure(409, "CONFLICT", SqlErrorSanitizer.withRefreshGuide(safeMsg));
                }
                if ("02000".equals(sqlState)) {
                    log.warn("분석가 검토 대상 없음(SQLSTATE 02000): reviewJobId={}, incidentId={}",
                            reviewJobId, incidentId);
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "요청한 분석가 검토 항목을 찾을 수 없습니다.");
                    return DecisionResult.failure(404, "NOT_FOUND", SqlErrorSanitizer.withRefreshGuide(safeMsg));
                }
            }
            log.error("분석가 검토 결정 중 예기치 않은 오류: reviewJobId={}, incidentId={}",
                    reviewJobId, incidentId, ex);
            return DecisionResult.failure(500, "INTERNAL_ERROR",
                    "검토 결정 처리 중 오류가 발생했습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        }

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("action", normalizedAction);
        if (cleanNote != null) {
            detail.put("note", cleanNote);
        }

        auditService.record(
                analystUsername,
                principal.getRole().name(),
                AuditActionType.ANALYST_REVIEW_DECISION,
                captureId,
                reviewJobId,
                incidentId,
                detail,
                clientIp
        );

        String successMessage = "confirm".equals(normalizedAction)
                ? "판단을 '조사 진행'으로 저장했습니다. 30초 안팎으로 자동 처리에 반영됩니다."
                : "판단을 '오탐으로 종료'로 저장했습니다. 30초 안팎으로 자동 처리에 반영됩니다.";
        return DecisionResult.success(successMessage);
    }

    public record DecisionResult(boolean succeeded, int httpStatus, String code, String message) {
        public static DecisionResult success(String message) {
            return new DecisionResult(true, 200, "OK", message);
        }

        public static DecisionResult failure(int httpStatus, String code, String message) {
            return new DecisionResult(false, httpStatus, code, message);
        }
    }
}
