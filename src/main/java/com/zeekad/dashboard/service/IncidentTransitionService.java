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
    private final IncidentAssignmentService incidentAssignmentService;
    private final IncidentResponseActionService incidentResponseActionService;

    public IncidentTransitionService(ZeekadWriteMapper zeekadWriteMapper,
                                     CaptureAccessService captureAccessService,
                                     AuditService auditService,
                                     IncidentAssignmentService incidentAssignmentService,
                                     IncidentResponseActionService incidentResponseActionService) {
        this.incidentResponseActionService = incidentResponseActionService;
        this.zeekadWriteMapper = zeekadWriteMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
        this.incidentAssignmentService = incidentAssignmentService;
    }

    /** 정탐 종결에 대응 조치 기록이 없을 때의 오류 코드(T56) */
    public static final String RESPONSE_ACTION_REQUIRED = "RESPONSE_ACTION_REQUIRED";

    /** 자동 지정이 실패했을 때 성공 메시지에 덧붙이는 문장(T25) */
    public static final String AUTO_ASSIGN_FAILED_NOTE = " 담당자 자동 지정은 실패했습니다.";

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
            throw new AccessDeniedException("인시던트 상태를 변경할 권한이 없습니다.");
        }

        String normalizedTarget = toStatus == null ? "" : toStatus.trim().toLowerCase(Locale.ROOT);
        if (!ALLOWED_TARGET_STATUSES.contains(normalizedTarget)) {
            return TransitionResult.failure(400, "INVALID_REQUEST", "허용되지 않는 상태 변경 요청입니다.");
        }

        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.isEmpty()) {
            return TransitionResult.failure(400, "INVALID_REQUEST", "상태 변경 사유를 입력해 주세요.");
        }
        if (FreeTextLimits.exceeds(cleanReason)) {
            return TransitionResult.failure(400, "INVALID_REQUEST",
                    "상태 변경 사유는 " + FreeTextLimits.MAX_CODE_POINTS + "자까지 입력할 수 있습니다.");
        }

        String effectiveResolution = null;
        if ("closed".equals(normalizedTarget)) {
            String normalizedResolution = resolution == null ? "" : resolution.trim().toLowerCase(Locale.ROOT);
            if (!ALLOWED_RESOLUTIONS.contains(normalizedResolution)) {
                return TransitionResult.failure(
                        400,
                        "INVALID_REQUEST",
                        "인시던트를 종결하려면 판정(정탐·오탐·정상)을 선택해야 합니다.");
            }
            effectiveResolution = normalizedResolution;
        }

        // T56: 분석 중인 인시던트를 정탐으로 종결하려면 대응 조치 기록이 하나 이상 있어야 한다(조치가 없었다면 "조치 없음"과 사유).
        // 지금 상태가 분석 중이 아니면(신규에서 바로 종결, 이미 종결) 이 규칙을 적용하지 않고 zeek_AD 함수가 전이 오류를 내게 둔다.
        // 두 DB에 걸친 검사라 원자적이지 않다(기록 수를 본 뒤 전이한다). 기록은 초기화 말고는 지워지지 않으므로 받아들인다.
        if ("true_positive".equals(effectiveResolution)
                && "investigating".equals(incidentResponseActionService.currentStatus(item))
                && incidentResponseActionService.countFor(item.getIncidentId()) == 0) {
            return TransitionResult.failure(409, RESPONSE_ACTION_REQUIRED,
                    IncidentResponseActionService.REQUIRED_FOR_TRUE_POSITIVE_MESSAGE);
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
                    // T63: 사용자 이름은 표지로 찍는다(줄바꿈으로 로그 줄을 만들지 못한다)
                    log.warn("사건 상태 전이 거부(SQLSTATE 22023): jobId={}, rank={}, actor={}",
                            jobId, queueRank, UntrustedText.forLog(actorUsername));
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "상태 변경 규칙에 위배되었거나 다른 사용자가 먼저 상태를 변경했습니다.");
                    return TransitionResult.failure(409, "CONFLICT", SqlErrorSanitizer.withRefreshGuide(safeMsg));
                }
                if ("02000".equals(sqlState)) {
                    log.warn("사건 상태 전이 대상 없음(SQLSTATE 02000): jobId={}, rank={}", jobId, queueRank);
                    String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(
                            sqlEx.getMessage(),
                            "대상 인시던트를 찾을 수 없습니다.");
                    return TransitionResult.failure(404, "NOT_FOUND", SqlErrorSanitizer.withRefreshGuide(safeMsg));
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
                ? "인시던트를 종결했습니다. 판정: " + resolutionDisplayName(effectiveResolution)
                : "인시던트를 분석 중으로 바꿨습니다.";
        if ("investigating".equals(normalizedTarget)) {
            // T25: 조사 시작 때 미배정이면 시작한 사람을 담당자로. 다른 DB라 한 트랜잭션이 아니다.
            // 실패해도 상태 변경은 이미 성공했으므로 성공으로 응답하고 안내 문장을 덧붙인다.
            try {
                incidentAssignmentService.autoAssignOnStart(principal, item, jobId, clientIp);
            } catch (RuntimeException ex) {
                log.error("분석 시작 뒤 담당자 자동 지정 실패: jobId={}, rank={}, actor={}", jobId, queueRank,
                        UntrustedText.forLog(actorUsername), ex);
                successMessage = successMessage + AUTO_ASSIGN_FAILED_NOTE;
            }
        }
        return TransitionResult.success(successMessage);
    }

    /** 화면 표시용 판정 이름(docs/ui-terminology.md 표시 이름 사전과 같다). */
    static String resolutionDisplayName(String resolution) {
        return switch (resolution == null ? "" : resolution) {
            case "true_positive" -> "정탐";
            case "false_positive" -> "오탐";
            case "benign" -> "정상";
            default -> resolution;
        };
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
