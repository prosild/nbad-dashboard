package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.mapper.app.IncidentAssignmentMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.IncidentAssignment;
import com.zeekad.dashboard.model.IncidentAssignmentHistory;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.security.CapturePatternMatcher;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 인시던트 담당자(T25). 대시보드 자체 DB(incident_assignments·incident_assignment_history)에만 쓴다.
 * <ul>
 *   <li>권한: 인시던트 접근 검사(허용 밖 403 + ACCESS_DENIED_IDOR) → 역할 검사(VIEWER 403, 감사 없음). 상태 변경과 같은 순서다.</li>
 *   <li>담당 가능: 활성 ANALYST·ADMIN이고 그 인시던트의 캡처가 허용 캡처 패턴에 맞는 사용자(자기 자신도 같은 규칙)</li>
 *   <li>종결이면 바꾸지 않는다(409 INCIDENT_CLOSED). 상태 확인(zeekad DB)과 담당 쓰기(대시보드 DB)는 다른 DB라
 *       확인 직후 종결되면 종결 뒤 변경이 한 번 남을 수 있다(막지 않는 경쟁, 이력에 그대로 남는다).</li>
 *   <li>동시 변경: 화면이 본 담당자(expected)와 서버 값이 다르면 409 ASSIGNMENT_CONFLICT, 같은 값이면 409 NO_CHANGE.
 *       비교·쓰기는 대시보드 DB 한 트랜잭션에서 version 조건 UPDATE(첫 지정은 INSERT … ON CONFLICT DO NOTHING 뒤 행 수)로 한다.</li>
 * </ul>
 */
@Service
public class IncidentAssignmentService {

    public static final String REASON_MANUAL = "manual";
    public static final String REASON_AUTO_ON_START = "auto_on_start";
    /** IN 목록 한 번에 넣는 incident_id 수(바인드 변수 한계보다 충분히 작게) */
    static final int LOOKUP_CHUNK = 1000;

    private final IncidentAssignmentMapper assignmentMapper;
    private final UserMapper userMapper;
    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final AuditService auditService;
    private final IncidentQueryService incidentQueryService;
    private final TransactionTemplate tx;
    private final Clock clock;

    public IncidentAssignmentService(IncidentAssignmentMapper assignmentMapper,
                                     UserMapper userMapper,
                                     ZeekadReadMapper zeekadReadMapper,
                                     CaptureAccessService captureAccessService,
                                     AuditService auditService,
                                     IncidentQueryService incidentQueryService,
                                     @Qualifier("appTransactionManager") PlatformTransactionManager appTransactionManager,
                                     Clock clock) {
        this.assignmentMapper = assignmentMapper;
        this.userMapper = userMapper;
        this.zeekadReadMapper = zeekadReadMapper;
        this.captureAccessService = captureAccessService;
        this.auditService = auditService;
        this.incidentQueryService = incidentQueryService;
        this.tx = new TransactionTemplate(appTransactionManager);
        this.clock = clock;
    }

    /** 지정·변경·해제 결과. 성공이면 assignment가 바뀐 뒤의 값이다. */
    public record AssignResult(int httpStatus, String code, String message, AssignmentDtos.Assignment assignment) {
        static AssignResult ok(AssignmentDtos.Assignment a) {
            return new AssignResult(200, "OK", null, a);
        }

        static AssignResult fail(int status, String code, String message) {
            return new AssignResult(status, code, message, null);
        }

        public boolean succeeded() {
            return httpStatus == 200;
        }
    }

    /* ───────────────────────── 지정·변경·해제 ───────────────────────── */

    public AssignResult assign(DashboardUserPrincipal principal, Long jobId, Integer queueRank,
                               String assigneeRaw, String expectedRaw, String clientIp) {
        IncidentQueueItem item = captureAccessService.requireIncidentAccessByRank(principal, jobId, queueRank, clientIp);
        requireAnalyst(principal);

        if (isClosed(item)) {
            return AssignResult.fail(409, "INCIDENT_CLOSED", "종결된 인시던트는 담당자를 바꿀 수 없습니다.");
        }
        String assigneeName = trimToNull(assigneeRaw);
        String expected = trimToNull(expectedRaw);
        DashboardUser target = null;
        if (assigneeName != null) {
            target = userMapper.findByUsername(assigneeName);
            if (!isEligible(target, item.getCaptureId())) {
                return AssignResult.fail(400, "ASSIGNEE_NOT_ELIGIBLE",
                        "이 인시던트의 담당자로 지정할 수 없는 사용자입니다(활성 분석가·관리자이고 이 캡처를 볼 수 있어야 합니다).");
            }
        }
        Long targetId = target == null ? null : target.getId();
        OffsetDateTime now = OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);

        Outcome outcome = tx.execute(status -> write(item, jobId, targetId, expected, principal.getUsername(),
                REASON_MANUAL, now, true));
        if (outcome == null || outcome.code() != null) {
            String code = outcome == null ? "ASSIGNMENT_CONFLICT" : outcome.code();
            if ("NO_CHANGE".equals(code)) {
                return AssignResult.fail(409, code, "이미 그 담당 상태입니다. 바뀐 것이 없습니다.");
            }
            return AssignResult.fail(409, "ASSIGNMENT_CONFLICT",
                    "다른 사용자가 먼저 담당자를 바꿨습니다. 화면을 새로 고쳐 지금 담당자를 확인하세요.");
        }
        auditAssignment(principal.getUsername(), principal.getRole().name(), item, jobId, outcome, REASON_MANUAL, clientIp);
        return AssignResult.ok(currentView(item.getIncidentId(), incidentQueryService.loadUserDisplayMap()));
    }

    /**
     * 조사 시작(open → investigating) 성공 뒤 미배정이면 변경한 사람을 담당자로 지정한다.
     * 이미 담당이 있으면(그 사이 다른 사람이 먼저 지정해 충돌한 경우도) 조용히 넘어간다. 예외는 호출한 쪽이 받는다.
     *
     * @return 지정했으면 true
     */
    public boolean autoAssignOnStart(DashboardUserPrincipal principal, IncidentQueueItem item, Long jobId, String clientIp) {
        OffsetDateTime now = OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
        Outcome outcome = tx.execute(status -> {
            IncidentAssignment current = assignmentMapper.findByIncidentId(item.getIncidentId());
            if (current != null && current.getAssigneeUserId() != null) {
                return new Outcome("ALREADY_ASSIGNED", null, null);
            }
            return write(item, jobId, principal.getId(), null, principal.getUsername(), REASON_AUTO_ON_START, now, false);
        });
        if (outcome == null || outcome.code() != null) {
            return false;
        }
        auditAssignment(principal.getUsername(), principal.getRole().name(), item, jobId, outcome, REASON_AUTO_ON_START, clientIp);
        return true;
    }

    private record Outcome(String code, String fromUsername, String toUsername) {
    }

    /**
     * 비교와 쓰기(현재 값 + 이력 행). 트랜잭션 안에서만 부른다.
     * checkExpected=false(자동 지정)이면 expected 비교 없이 "지금 미배정"만 조건으로 쓴다.
     */
    private Outcome write(IncidentQueueItem item, Long jobId, Long targetId, String expected, String actor,
                          String reason, OffsetDateTime now, boolean checkExpected) {
        IncidentAssignment current = assignmentMapper.findByIncidentId(item.getIncidentId());
        Long currentId = current == null ? null : current.getAssigneeUserId();
        String currentName = current == null ? null : current.getAssigneeUsername();
        if (checkExpected && !sameUsername(currentName, expected)) {
            return new Outcome("ASSIGNMENT_CONFLICT", null, null);
        }
        if (Objects.equals(currentId, targetId)) {
            return new Outcome("NO_CHANGE", null, null);
        }
        int changed;
        if (current == null) {
            changed = assignmentMapper.insertIfAbsent(item.getIncidentId(), item.getCaptureId(), targetId, now, actor);
        } else {
            changed = assignmentMapper.updateIfVersion(item.getIncidentId(), targetId, now, actor, current.getVersion());
        }
        if (changed != 1) {
            return new Outcome("ASSIGNMENT_CONFLICT", null, null);
        }
        IncidentAssignmentHistory h = new IncidentAssignmentHistory();
        h.setIncidentId(item.getIncidentId());
        h.setCaptureId(item.getCaptureId());
        h.setJobId(jobId);
        h.setFromUserId(currentId);
        h.setToUserId(targetId);
        h.setActorUsername(actor);
        h.setReason(reason);
        h.setChangedAt(now);
        assignmentMapper.insertHistory(h);
        String toName = null;
        if (targetId != null) {
            DashboardUser u = userMapper.findById(targetId);
            toName = u == null ? null : u.getUsername();
        }
        return new Outcome(null, currentName, toName);
    }

    private void auditAssignment(String actor, String actorRole, IncidentQueueItem item, Long jobId, Outcome outcome,
                                 String reason, String clientIp) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("from", outcome.fromUsername());
        detail.put("to", outcome.toUsername());
        detail.put("reason", reason);
        auditService.record(actor, actorRole, AuditActionType.INCIDENT_ASSIGNMENT, item.getCaptureId(), jobId,
                item.getIncidentId(), detail, clientIp);
    }

    /* ───────────────────────── 담당 가능자 ───────────────────────── */

    public List<AssignmentDtos.Candidate> candidates(DashboardUserPrincipal principal, Long jobId, Integer queueRank,
                                                     String clientIp) {
        IncidentQueueItem item = captureAccessService.requireIncidentAccessByRank(principal, jobId, queueRank, clientIp);
        requireAnalyst(principal);
        List<AssignmentDtos.Candidate> out = new ArrayList<>();
        for (DashboardUser u : userMapper.findAll()) {
            if (isEligible(u, item.getCaptureId())) {
                out.add(new AssignmentDtos.Candidate(u.getUsername(), displayOf(u.getDisplayName(), u.getUsername())));
            }
        }
        out.sort(Comparator.comparing(AssignmentDtos.Candidate::displayName).thenComparing(AssignmentDtos.Candidate::username));
        return out;
    }

    boolean isEligible(DashboardUser user, String captureId) {
        if (user == null || !user.isEnabled()) {
            return false;
        }
        if (user.getRole() != UserRole.ANALYST && user.getRole() != UserRole.ADMIN) {
            return false;
        }
        return CapturePatternMatcher.matchesAny(userMapper.findCapturePatternsByUserId(user.getId()), captureId);
    }

    /* ───────────────────────── 읽기 ───────────────────────── */

    /** 상세의 현재 담당 */
    public AssignmentDtos.Assignment currentView(String incidentId, Map<String, String> userDisplayMap) {
        IncidentAssignment a = assignmentMapper.findByIncidentId(incidentId);
        if (a == null) {
            return AssignmentDtos.Assignment.none();
        }
        return new AssignmentDtos.Assignment(toAssignee(a), a.getAssignedAt(),
                incidentQueryService.formatActorDisplay(a.getAssignedBy(), userDisplayMap));
    }

    /** 상세의 담당 이력(시간 역순) */
    public List<AssignmentDtos.HistoryItem> historyView(String incidentId, Map<String, String> userDisplayMap) {
        Map<String, AssignmentDtos.Assignee> users = new HashMap<>();
        for (DashboardUser u : userMapper.findAll()) {
            users.put(u.getUsername().toLowerCase(Locale.ROOT),
                    new AssignmentDtos.Assignee(u.getUsername(), displayOf(u.getDisplayName(), u.getUsername()), u.isEnabled()));
        }
        return assignmentMapper.findHistory(incidentId).stream()
                .map(h -> new AssignmentDtos.HistoryItem(h.getJobId(),
                        lookup(users, h.getFromUsername()), lookup(users, h.getToUsername()),
                        incidentQueryService.formatActorDisplay(h.getActorUsername(), userDisplayMap),
                        h.getReason(), h.getChangedAt()))
                .toList();
    }

    /** 큐 행·담당 현황용: 주어진 incident_id 가운데 담당자가 있는 것의 담당자(해제된 행은 없음) */
    public Map<String, AssignmentDtos.Assignee> assigneesFor(Collection<String> incidentIds) {
        Map<String, AssignmentDtos.Assignee> out = new HashMap<>();
        if (incidentIds == null || incidentIds.isEmpty()) {
            return out;
        }
        List<String> ids = new ArrayList<>(Set.copyOf(incidentIds));
        for (int from = 0; from < ids.size(); from += LOOKUP_CHUNK) {
            List<String> chunk = ids.subList(from, Math.min(ids.size(), from + LOOKUP_CHUNK));
            for (IncidentAssignment a : assignmentMapper.findAssignedByIncidentIds(chunk)) {
                AssignmentDtos.Assignee assignee = toAssignee(a);
                if (assignee != null) {
                    out.put(a.getIncidentId(), assignee);
                }
            }
        }
        return out;
    }

    /**
     * 큐 assignee 조건용 담당 incident_id 목록(담당자가 있는 행만, 해제된 행 제외). userId가 있으면 그 사용자 담당만.
     * 담당 행의 capture_id로 captureIds 안만 남긴다(미리 줄이기). 권한의 최종 경계는 zeekad 질의의 허용 캡처 조건이다.
     */
    public List<String> assignedIncidentIds(Long userId, Collection<String> captureIds) {
        Set<String> caps = Set.copyOf(captureIds);
        return assignmentMapper.findAssignedRows(userId).stream()
                .filter(a -> caps.contains(a.getCaptureId()))
                .map(IncidentAssignment::getIncidentId)
                .toList();
    }

    /* ───────────────────────── 내부 ───────────────────────── */

    private boolean isClosed(IncidentQueueItem item) {
        IncidentStatus status = zeekadReadMapper.findIncidentStatus(item.getIncidentId());
        String s = status != null && status.getZeekadStatus() != null && !status.getZeekadStatus().isBlank()
                ? status.getZeekadStatus() : item.getZeekadStatus();
        return s != null && "closed".equals(s.trim().toLowerCase(Locale.ROOT));
    }

    private static void requireAnalyst(DashboardUserPrincipal principal) {
        if (principal == null || (principal.getRole() != UserRole.ANALYST && principal.getRole() != UserRole.ADMIN)) {
            throw new AccessDeniedException("담당자를 바꿀 권한이 없습니다.");
        }
    }

    private static AssignmentDtos.Assignee toAssignee(IncidentAssignment a) {
        if (a == null || a.getAssigneeUserId() == null || a.getAssigneeUsername() == null) {
            return null;
        }
        return new AssignmentDtos.Assignee(a.getAssigneeUsername(),
                displayOf(a.getAssigneeDisplayName(), a.getAssigneeUsername()),
                Boolean.TRUE.equals(a.getAssigneeEnabled()));
    }

    private static AssignmentDtos.Assignee lookup(Map<String, AssignmentDtos.Assignee> users, String username) {
        return username == null ? null : users.get(username.toLowerCase(Locale.ROOT));
    }

    private static String displayOf(String displayName, String username) {
        return displayName == null || displayName.isBlank() ? username : displayName;
    }

    private static boolean sameUsername(String a, String b) {
        if (a == null || b == null) {
            return a == null && b == null;
        }
        return a.equalsIgnoreCase(b);
    }

    private static String trimToNull(String v) {
        if (v == null) {
            return null;
        }
        String t = v.trim();
        return t.isEmpty() ? null : t;
    }
}
