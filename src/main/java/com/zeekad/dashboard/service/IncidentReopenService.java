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
 * T53 종결한 인시던트 다시 열기. zeek_AD migration 018의 dashboard.reopen_incident를 부른다(전이 함수와 따로다).
 * 순서는 상태 전이와 같은 뼈대다: 캡처 접근 → 역할(ANALYST·ADMIN) → 사유 → 화면의 판정 → 쓰기 함수.
 * 화면의 판정(expectedResolution)은 필수다. 다른 사람이 그사이 다시 열어 다른 판정으로 다시 종결했으면 함수가 거부해
 * 오래된 화면의 요청이 새 판정을 지우지 않는다. 기존 전이 경로(transition)의 closed → investigating은 지금처럼 거부된다.
 */
@Service
public class IncidentReopenService {

    private static final Logger log = LoggerFactory.getLogger(IncidentReopenService.class);

    private static final Set<String> ALLOWED_RESOLUTIONS = Set.of("true_positive", "false_positive", "benign");

    /** 함수가 없거나(42883) 실행 권한이 없을 때(42501)의 오류 코드 */
    public static final String REOPEN_UNAVAILABLE = "REOPEN_UNAVAILABLE";
    public static final String REOPEN_UNAVAILABLE_MESSAGE = "이 환경의 탐지 DB에는 다시 열기 기능이 아직 없습니다.";
    /** 22023(종결이 아님, 판정이 화면과 다름). DB 문구의 상태·판정 코드 원문을 내보내지 않는다 */
    public static final String CONFLICT_MESSAGE = "다른 사람이 먼저 상태나 판정을 바꿨습니다. 새로고침한 뒤 다시 확인하세요.";
    public static final String SUCCESS_MESSAGE = "인시던트를 다시 열었습니다. 상태는 분석 중입니다.";

    private final ZeekadWriteMapper zeekadWriteMapper;
    private final CaptureAccessService captureAccessService;
    private final AuditService auditService;
    private final IncidentAssignmentService incidentAssignmentService;

    public IncidentReopenService(ZeekadWriteMapper zeekadWriteMapper,
                                 CaptureAccessService captureAccessService,
                                 AuditService auditService,
                                 IncidentAssignmentService incidentAssignmentService) {
        this.zeekadWriteMapper = zeekadWriteMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
        this.incidentAssignmentService = incidentAssignmentService;
    }

    /** 다시 열 수 있는 역할(상태를 바꿀 수 있는 역할과 같다). 종결한 사람이 아니어도 된다. */
    public static boolean canReopen(UserRole role, String currentStatus) {
        return (role == UserRole.ANALYST || role == UserRole.ADMIN) && "closed".equals(currentStatus);
    }

    public IncidentTransitionService.TransitionResult reopen(DashboardUserPrincipal principal,
                                                             Long jobId,
                                                             Integer queueRank,
                                                             String reason,
                                                             String expectedResolution,
                                                             String clientIp) {
        IncidentQueueItem item = captureAccessService.requireIncidentAccessByRank(principal, jobId, queueRank, clientIp);

        if (principal == null || (principal.getRole() != UserRole.ANALYST && principal.getRole() != UserRole.ADMIN)) {
            throw new AccessDeniedException("인시던트를 다시 열 권한이 없습니다.");
        }

        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.isEmpty()) {
            return IncidentTransitionService.TransitionResult.failure(400, "INVALID_REQUEST", "다시 여는 사유를 입력해 주세요.");
        }
        if (FreeTextLimits.exceeds(cleanReason)) {
            return IncidentTransitionService.TransitionResult.failure(400, "INVALID_REQUEST",
                    "다시 여는 사유는 " + FreeTextLimits.MAX_CODE_POINTS + "자까지 입력할 수 있습니다.");
        }

        String expected = expectedResolution == null ? "" : expectedResolution.trim().toLowerCase(Locale.ROOT);
        if (!ALLOWED_RESOLUTIONS.contains(expected)) {
            return IncidentTransitionService.TransitionResult.failure(400, "INVALID_REQUEST",
                    "다시 열려면 화면에 보이는 판정(정탐·오탐·정상)을 함께 보내야 합니다.");
        }

        String actorUsername = principal.getUsername();
        try {
            zeekadWriteMapper.reopenIncident(jobId, item.getIncidentId(), actorUsername, cleanReason, expected);
        } catch (RuntimeException ex) {
            SQLException sqlEx = SqlErrorSanitizer.findSqlException(ex);
            String sqlState = sqlEx == null ? null : sqlEx.getSQLState();
            if ("22023".equals(sqlState)) {
                // 종결이 아님(동시에 두 번 포함) 또는 판정이 화면과 다름. 원문은 로그에도 남기지 않는다(상태·판정 코드뿐이다).
                log.warn("다시 열기 거부(SQLSTATE 22023): jobId={}, rank={}, actor={}", jobId, queueRank, actorUsername);
                return IncidentTransitionService.TransitionResult.failure(409, "CONFLICT", CONFLICT_MESSAGE);
            }
            if ("02000".equals(sqlState)) {
                log.warn("다시 열기 대상 없음(SQLSTATE 02000): jobId={}, rank={}", jobId, queueRank);
                String safeMsg = SqlErrorSanitizer.sanitizeSqlMessage(sqlEx.getMessage(), "대상 인시던트를 찾을 수 없습니다.");
                return IncidentTransitionService.TransitionResult.failure(404, "NOT_FOUND", SqlErrorSanitizer.withRefreshGuide(safeMsg));
            }
            if ("42883".equals(sqlState) || "42501".equals(sqlState)) {
                // 함수가 없는 스냅샷 DB(migration 018 전)이거나 쓰기 계정에 실행 권한이 없다. 원인은 서버 로그에만 남긴다.
                log.error("다시 열기 함수를 부를 수 없음(SQLSTATE {}): jobId={}, rank={}", sqlState, jobId, queueRank, ex);
                return IncidentTransitionService.TransitionResult.failure(501, REOPEN_UNAVAILABLE, REOPEN_UNAVAILABLE_MESSAGE);
            }
            log.error("다시 열기 중 예기치 않은 오류: jobId={}, rank={}", jobId, queueRank, ex);
            return IncidentTransitionService.TransitionResult.failure(500, "INTERNAL_ERROR",
                    "다시 열기 처리 중 오류가 발생했습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        }

        // 감사 유형은 늘리지 않는다(상태 변경과 같은 유형, operation으로 가른다)
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("operation", "reopen");
        detail.put("toStatus", "investigating");
        detail.put("previousResolution", expected);
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

        String successMessage = SUCCESS_MESSAGE;
        // 조사 시작과 같은 자동 지정: 미배정일 때만 다시 연 사람을 담당자로(이미 담당자가 있으면 그대로 둔다).
        // 다른 DB라 한 트랜잭션이 아니다. 실패해도 다시 열기는 이미 성공했으므로 성공으로 응답하고 안내 문장을 덧붙인다.
        try {
            incidentAssignmentService.autoAssignOnStart(principal, item, jobId, clientIp);
        } catch (RuntimeException ex) {
            log.error("다시 열기 뒤 담당자 자동 지정 실패: jobId={}, rank={}, actor={}", jobId, queueRank, actorUsername, ex);
            successMessage = successMessage + IncidentTransitionService.AUTO_ASSIGN_FAILED_NOTE;
        }
        return IncidentTransitionService.TransitionResult.success(successMessage);
    }
}
