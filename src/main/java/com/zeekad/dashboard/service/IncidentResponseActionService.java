package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.dto.ResponseActionDtos;
import com.zeekad.dashboard.mapper.app.IncidentResponseActionMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.IncidentResponseAction;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 인시던트 대응 조치 기록(T56). 대시보드 자체 DB(incident_response_actions)에 덧붙이기만 한다.
 * 이 콘솔은 방화벽·EDR에 명령을 내리지 않는다. 누가 언제 무엇을 했다고 적었는지만 남긴다.
 * <ul>
 *   <li>검증 순서: 인시던트 접근(허용 밖 403 + ACCESS_DENIED_IDOR) → 역할(VIEWER 403, 감사 없음) → 상태(신규면 409
 *       INCIDENT_NOT_STARTED) → 종류(일곱 값 밖이면 400) → 메모(500 코드 포인트 상한, 조치 없음·기타는 필수).</li>
 *   <li>기록은 고치거나 지우지 않는다(이 서비스와 매퍼에 그런 문장이 없다). 종결된 인시던트에도 덧붙일 수 있다(뒤늦은 조치).</li>
 *   <li>상태 확인(zeekad DB)과 쓰기(대시보드 DB)는 다른 DB라 한 트랜잭션이 아니다.</li>
 * </ul>
 */
@Service
public class IncidentResponseActionService {

    /** 조치 종류(값 → 화면 라벨). docs/ui-terminology.md 표시 이름 사전과 같다. 순서는 화면의 선택 순서다. */
    public static final Map<String, String> ACTION_LABELS;

    static {
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("block_ip", "IP 차단");
        labels.put("isolate_host", "호스트 격리");
        labels.put("lock_account", "사용자 계정 잠금·비밀번호 초기화");
        labels.put("handover", "침해사고 대응팀 이관");
        labels.put("monitor", "모니터링 강화");
        labels.put("none", "조치 없음");
        labels.put("other", "기타");
        ACTION_LABELS = java.util.Collections.unmodifiableMap(labels);
    }

    /** 메모가 필수인 종류(왜 조치가 없는지, 무엇을 했는지 적어야 뜻이 통한다) */
    private static final java.util.Set<String> NOTE_REQUIRED = java.util.Set.of("none", "other");

    /** 정탐 종결을 막을 때의 메시지(화면의 상태 변경 폼도 같은 글을 보인다) */
    public static final String REQUIRED_FOR_TRUE_POSITIVE_MESSAGE =
            "정탐으로 종결하려면 대응 조치를 먼저 기록하세요. 조치가 없었다면 '조치 없음'을 기록하세요.";

    private final IncidentResponseActionMapper responseActionMapper;
    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final AuditService auditService;
    private final IncidentQueryService incidentQueryService;
    private final Clock clock;

    public IncidentResponseActionService(IncidentResponseActionMapper responseActionMapper,
                                         ZeekadReadMapper zeekadReadMapper,
                                         CaptureAccessService captureAccessService,
                                         AuditService auditService,
                                         IncidentQueryService incidentQueryService,
                                         Clock clock) {
        this.responseActionMapper = responseActionMapper;
        this.zeekadReadMapper = zeekadReadMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
        this.incidentQueryService = incidentQueryService;
        this.clock = clock;
    }

    public record RecordResult(boolean succeeded, int httpStatus, String code, String message) {
        static RecordResult ok(String message) {
            return new RecordResult(true, 200, "OK", message);
        }

        static RecordResult fail(int status, String code, String message) {
            return new RecordResult(false, status, code, message);
        }
    }

    /* ───────────────────────── 기록 ───────────────────────── */

    public RecordResult record(DashboardUserPrincipal principal, Long jobId, Integer queueRank,
                               String actionRaw, String noteRaw, String clientIp) {
        IncidentQueueItem item = captureAccessService.requireIncidentAccessByRank(principal, jobId, queueRank, clientIp);
        if (!canRecord(principal == null ? null : principal.getRole())) {
            throw new AccessDeniedException("대응 조치를 기록할 권한이 없습니다.");
        }
        if (!statusAllowsRecord(currentStatus(item))) {
            return RecordResult.fail(409, "INCIDENT_NOT_STARTED", "착수한 뒤(분석 중) 대응 조치를 기록할 수 있습니다.");
        }
        String action = actionRaw == null ? "" : actionRaw.trim().toLowerCase(Locale.ROOT);
        if (!ACTION_LABELS.containsKey(action)) {
            return RecordResult.fail(400, "INVALID_REQUEST", "허용되지 않는 대응 조치 종류입니다.");
        }
        String note = noteRaw == null ? "" : noteRaw.trim();
        if (FreeTextLimits.exceeds(note)) {
            return RecordResult.fail(400, "INVALID_REQUEST",
                    "대응 조치 메모는 " + FreeTextLimits.MAX_CODE_POINTS + "자까지 입력할 수 있습니다.");
        }
        if (note.isEmpty() && NOTE_REQUIRED.contains(action)) {
            return RecordResult.fail(400, "INVALID_REQUEST",
                    "조치 종류가 '" + ACTION_LABELS.get(action) + "'이면 메모를 입력해 주세요.");
        }
        String storedNote = note.isEmpty() ? null : note;

        IncidentResponseAction row = new IncidentResponseAction();
        row.setIncidentId(item.getIncidentId());
        row.setCaptureId(item.getCaptureId());
        row.setJobId(jobId);
        row.setActionType(action);
        row.setNote(storedNote);
        row.setActorUsername(principal.getUsername());
        row.setRecordedAt(OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC));
        responseActionMapper.insert(row);

        // 상태 변경 사유를 원문으로 넣는 관례와 같다(감사 로그는 관리자만 본다).
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("action", action);
        detail.put("note", storedNote);
        auditService.record(principal.getUsername(), principal.getRole().name(), AuditActionType.INCIDENT_RESPONSE_ACTION,
                item.getCaptureId(), jobId, item.getIncidentId(), detail, clientIp);
        return RecordResult.ok("대응 조치를 기록했습니다. 조치: " + ACTION_LABELS.get(action));
    }

    /* ───────────────────────── 읽기 ───────────────────────── */

    /**
     * 상세의 조치 기록(시간 역순). includeNote=false면 메모를 싣지 않는다(조회자: 종류·기록자·시각만).
     */
    public List<ResponseActionDtos.Item> listView(String incidentId, Map<String, String> userDisplayMap, boolean includeNote) {
        if (incidentId == null) {
            return List.of();
        }
        return responseActionMapper.findByIncidentId(incidentId).stream()
                .map(r -> new ResponseActionDtos.Item(r.getActionType(), includeNote ? r.getNote() : null,
                        incidentQueryService.formatActorDisplay(r.getActorUsername(), userDisplayMap), r.getRecordedAt()))
                .toList();
    }

    /** 그 인시던트의 조치 기록 수(정탐 종결 규칙이 쓴다) */
    public int countFor(String incidentId) {
        return incidentId == null ? 0 : responseActionMapper.countByIncidentId(incidentId);
    }

    /** 지금 상태(open · investigating · closed). 상태 행이 없으면 큐 행의 값, 그것도 없으면 open(상세와 같은 규칙) */
    public String currentStatus(IncidentQueueItem item) {
        IncidentStatus status = zeekadReadMapper.findIncidentStatus(item.getIncidentId());
        String s = status != null && status.getZeekadStatus() != null && !status.getZeekadStatus().isBlank()
                ? status.getZeekadStatus() : item.getZeekadStatus();
        return s == null || s.isBlank() ? "open" : s.trim().toLowerCase(Locale.ROOT);
    }

    /** 기록할 수 있는 역할: ANALYST·ADMIN */
    public static boolean canRecord(UserRole role) {
        return role == UserRole.ANALYST || role == UserRole.ADMIN;
    }

    /** 착수 전(신규)에는 기록하지 않는다. 분석 중과 종결은 된다. */
    public static boolean statusAllowsRecord(String status) {
        return "investigating".equals(status) || "closed".equals(status);
    }
}
