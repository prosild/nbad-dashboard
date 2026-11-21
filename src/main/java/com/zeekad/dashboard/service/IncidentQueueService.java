package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.dto.IncidentQueueMeta;
import com.zeekad.dashboard.dto.QueueNeighborsResponse;
import com.zeekad.dashboard.dto.QueueNewCountResponse;
import com.zeekad.dashboard.dto.TimeContextResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.dto.UnifiedQueueRow;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.CaptureQueueStat;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueSummaryRow;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 통합 인시던트 큐(T23). 허용된 모든 캡처의 최신 작업 행을 합쳐 탐지 시각 기간·수집원으로 거르고,
 * 우선순위·정렬·쪽 나눔·요약을 SQL로 한다. 자산 검색(asset)은 VIEWER 마스킹 누출을 막으려고 SQL로 옮기지 않고
 * 역할 마스킹 뒤 Java(IncidentQueryService.matchesAssetFilter)로 거른다(상한 ASSET_SEARCH_CAP건).
 */
@Service
public class IncidentQueueService {

    /** 자산 검색 경로에서 SQL 결과 상한. 넘으면 400 QUERY_TOO_BROAD */
    public static final int ASSET_SEARCH_CAP = 5000;
    /** 진행 중 판정: 캡처 최신 윈도우 끝이 기준 시각 −15분 이상(경계 포함) */
    public static final Duration ONGOING_WINDOW = Duration.ofMinutes(15);

    public static final List<Integer> PAGE_SIZES = List.of(25, 50, 100);
    public static final int DEFAULT_PAGE_SIZE = 50;
    public static final String DEFAULT_PERIOD = "24h";

    private static final Map<String, Duration> PERIODS = Map.of(
            "1h", Duration.ofHours(1),
            "24h", Duration.ofHours(24),
            "7d", Duration.ofDays(7),
            "30d", Duration.ofDays(30));
    private static final Set<String> SORT_KEYS = Set.of("priority", "detected", "start", "connections", "status");
    /** 처음 정렬 방향(화면과 같다): 우선순위·상태는 오름, 시각·세션 수는 내림 */
    private static final Map<String, Boolean> DEFAULT_ASC = Map.of(
            "priority", true, "detected", false, "start", false, "connections", false, "status", true);
    private static final Set<String> PRIORITIES = Set.of("high", "medium", "low");

    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final MaskingService maskingService;
    private final TimeContextService timeContextService;
    private final AckTargetService ackTargetService;
    private final IncidentAssignmentService incidentAssignmentService;

    public IncidentQueueService(ZeekadReadMapper zeekadReadMapper,
                                CaptureAccessService captureAccessService,
                                MaskingService maskingService,
                                TimeContextService timeContextService,
                                AckTargetService ackTargetService,
                                IncidentAssignmentService incidentAssignmentService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.captureAccessService = captureAccessService;
        this.maskingService = maskingService;
        this.timeContextService = timeContextService;
        this.ackTargetService = ackTargetService;
        this.incidentAssignmentService = incidentAssignmentService;
    }

    public static final String ASSIGNEE_ME = "me";
    public static final String ASSIGNEE_NONE = "none";

    /** 요청 거르기·정렬·쪽(문자열 그대로). 해석은 이 서비스가 한다. */
    public record QueueParams(String period,
                              String source,
                              String captureId,
                              String priority,
                              String status,
                              String reviewPending,
                              String alerted,
                              String pickedBy,
                              String role,
                              String hasReport,
                              String wouldSend,
                              String asset,
                              String sort,
                              String dir,
                              String page,
                              String size,
                              /* T25: 담당 조건 me·none, 착수 지연 띠 축 */
                              String assignee,
                              String overdue) {
        /** T25 앞 호출 호환(담당·착수 지연 조건 없음) */
        public QueueParams(String period, String source, String captureId, String priority, String status,
                           String reviewPending, String alerted, String pickedBy, String role, String hasReport,
                           String wouldSend, String asset, String sort, String dir, String page, String size) {
            this(period, source, captureId, priority, status, reviewPending, alerted, pickedBy, role, hasReport,
                    wouldSend, asset, sort, dir, page, size, null, null);
        }
    }

    /** 요청마다 정해지는 공통 맥락(허용 캡처·기준 시각·조회 범위) */
    private record Scope(List<String> allowed,
                         List<String> captureIds,
                         OffsetDateTime anchor,
                         String period,
                         UnifiedQueueCriteria criteria,
                         String asset,
                         UserRole role) {
    }

    /* ───────────────────────── 큐 ───────────────────────── */

    public UnifiedQueueResponse loadQueue(DashboardUserPrincipal principal, QueueParams params, String clientIp) {
        Scope scope = resolveScope(principal, params, clientIp, true);
        int size = parseSize(params.size());
        boolean masked = maskingService.shouldMask(scope.role());

        List<CaptureQueueStat> stats = scope.allowed().isEmpty()
                ? List.of() : zeekadReadMapper.findCaptureQueueStats(scope.allowed());
        Map<String, CaptureQueueStat> statByCapture = new HashMap<>();
        for (CaptureQueueStat s : stats) {
            statByCapture.put(s.getCaptureId(), s);
        }
        List<UnifiedQueueResponse.Source> sources = scope.allowed().stream()
                .map(cap -> new UnifiedQueueResponse.Source(
                        cap,
                        timeContextService.sourceType(cap),
                        statByCapture.get(cap) != null ? statByCapture.get(cap).getLatestJobId() : null))
                .toList();
        List<String> models = scope.allowed().isEmpty() ? List.of() : zeekadReadMapper.findDistinctLatestPickedBy(scope.allowed());
        List<String> roles = scope.allowed().isEmpty() ? List.of() : zeekadReadMapper.findDistinctLatestRoles(scope.allowed());

        if (scope.captureIds().isEmpty()) {
            return new UnifiedQueueResponse(List.of(), 0, 1, size, 1, emptySummary(), scope.anchor(),
                    timeContextService.mode(), timeContextService.isSnapshot(), scope.period(), null, null,
                    sources, masked, models, roles);
        }

        long total;
        int page;
        int pageCount;
        List<UnifiedQueueRecord> pageRecords;
        List<IncidentQueueItem> pageMasked;
        UnifiedQueueResponse.Summary summary;
        OffsetDateTime latestDetectedAt;

        if (scope.asset() == null) {
            UnifiedQueueCriteria c = scope.criteria();
            total = zeekadReadMapper.countUnifiedQueue(c);
            pageCount = pageCount(total, size);
            page = clampPage(params.page(), pageCount);
            UnifiedQueueCriteria paged = c.copy();
            paged.setLimit(size);
            paged.setOffset((page - 1) * size);
            pageRecords = zeekadReadMapper.findUnifiedQueue(paged);
            pageMasked = pageRecords.stream()
                    .map(r -> maskingService.maskIncidentQueueItem(r, scope.role()))
                    .toList();
            UnifiedQueueCriteria summaryCriteria = c.copy();
            summaryCriteria.setApplyStripFilters(false);
            summary = toSummary(zeekadReadMapper.summarizeUnifiedQueue(summaryCriteria));
            latestDetectedAt = zeekadReadMapper.findMaxUnifiedDetectedAt(c);
        } else {
            List<Masked> base = assetFiltered(scope.criteria(), scope.asset(), scope.role());
            summary = summarize(base, scope.criteria());
            List<Masked> filtered = applyStripFilters(base, scope.criteria());
            total = filtered.size();
            pageCount = pageCount(total, size);
            page = clampPage(params.page(), pageCount);
            int from = Math.min(filtered.size(), (page - 1) * size);
            int to = Math.min(filtered.size(), from + size);
            List<Masked> slice = filtered.subList(from, to);
            pageRecords = slice.stream().map(Masked::record).toList();
            pageMasked = slice.stream().map(Masked::item).toList();
            latestDetectedAt = filtered.stream()
                    .map(m -> m.record().getDetectedAt())
                    .filter(Objects::nonNull)
                    .max(OffsetDateTime::compareTo)
                    .orElse(null);
        }

        OffsetDateTime newestOutsidePeriod = null;
        if (total == 0 && !"all".equals(scope.period())) {
            UnifiedQueueCriteria noPeriod = scope.criteria().copy();
            noPeriod.setDetectedAfter(null);
            noPeriod.setDetectedUntil(null);
            if (scope.asset() == null) {
                newestOutsidePeriod = zeekadReadMapper.findMaxUnifiedDetectedAt(noPeriod);
            } else {
                newestOutsidePeriod = applyStripFilters(assetFilteredOrEmpty(noPeriod, scope.asset(), scope.role()), noPeriod)
                        .stream()
                        .map(m -> m.record().getDetectedAt())
                        .filter(Objects::nonNull)
                        .max(OffsetDateTime::compareTo)
                        .orElse(null);
            }
        }

        // T25 담당자: 이 쪽의 incident_id들로 대시보드 DB를 한 번 읽는다
        Map<String, AssignmentDtos.Assignee> assignees = incidentAssignmentService.assigneesFor(
                pageRecords.stream().map(UnifiedQueueRecord::getIncidentId).toList());
        List<UnifiedQueueRow> items = new ArrayList<>(pageRecords.size());
        for (int i = 0; i < pageRecords.size(); i++) {
            UnifiedQueueRecord record = pageRecords.get(i);
            OffsetDateTime due = ackTargetService.dueAt(record.getCaptureId(), record.getZeekadStatus(),
                    record.getPriority(), record.getDetectedAt());
            items.add(new UnifiedQueueRow(
                    pageMasked.get(i),
                    record.getDetectedAt(),
                    timeContextService.sourceType(record.getCaptureId()),
                    record.getPriority(),
                    isOngoing(record, statByCapture.get(record.getCaptureId()), scope.anchor()),
                    assignees.get(record.getIncidentId()),
                    due,
                    AckTargetService.isOverdue(due, scope.anchor())));
        }

        return new UnifiedQueueResponse(items, total, page, size, pageCount, summary, scope.anchor(),
                timeContextService.mode(), timeContextService.isSnapshot(), scope.period(), latestDetectedAt,
                newestOutsidePeriod, sources, masked, models, roles);
    }

    /* ───────────────────────── 새 인시던트 수 ───────────────────────── */

    public QueueNewCountResponse countNew(DashboardUserPrincipal principal, QueueParams params, String since, String clientIp) {
        OffsetDateTime sinceTime = parseTime(since);
        Scope scope = resolveScope(principal, params, clientIp, false);
        if (scope.captureIds().isEmpty()) {
            return new QueueNewCountResponse(0, null, sinceTime);
        }
        UnifiedQueueCriteria c = scope.criteria().copy();
        c.setDetectedAfter(sinceTime);
        c.setDetectedUntil(null);
        if (scope.asset() == null) {
            long count = zeekadReadMapper.countUnifiedQueue(c);
            OffsetDateTime latest = count > 0 ? zeekadReadMapper.findMaxUnifiedDetectedAt(c) : null;
            return new QueueNewCountResponse(count, latest, sinceTime);
        }
        List<Masked> filtered = applyStripFilters(assetFiltered(c, scope.asset(), scope.role()), c);
        OffsetDateTime latest = filtered.stream()
                .map(m -> m.record().getDetectedAt())
                .filter(Objects::nonNull)
                .max(OffsetDateTime::compareTo)
                .orElse(null);
        return new QueueNewCountResponse(filtered.size(), latest, sinceTime);
    }

    /* ───────────────────────── 이전·다음 ───────────────────────── */

    public QueueNeighborsResponse neighbors(DashboardUserPrincipal principal,
                                            Long jobId,
                                            Integer queueRank,
                                            QueueParams params,
                                            String clientIp) {
        // 허용 밖 작업이면 403과 IDOR 감사 기록(상세와 같은 검사)
        IncidentQueueItem viewed = captureAccessService.requireIncidentAccessByRank(principal, jobId, queueRank, clientIp);
        Scope scope = resolveScope(principal, params, clientIp, true);

        UnifiedQueueRecord latest = findLatestRow(scope.allowed(), viewed.getCaptureId(), viewed.getIncidentId());
        QueueNeighborsResponse.Key current = latest == null ? null : key(latest, scope.role());
        if (scope.captureIds().isEmpty()) {
            return new QueueNeighborsResponse(current, null, 0, null, null);
        }

        List<UnifiedQueueRecord> ordered;
        if (scope.asset() == null) {
            ordered = zeekadReadMapper.findUnifiedQueue(scope.criteria());
        } else {
            ordered = applyStripFilters(assetFiltered(scope.criteria(), scope.asset(), scope.role()), scope.criteria())
                    .stream().map(Masked::record).toList();
        }
        int index = -1;
        if (latest != null) {
            for (int i = 0; i < ordered.size(); i++) {
                UnifiedQueueRecord r = ordered.get(i);
                if (Objects.equals(r.getJobId(), latest.getJobId()) && Objects.equals(r.getQueueRank(), latest.getQueueRank())) {
                    index = i;
                    break;
                }
            }
        }
        if (index < 0) {
            return new QueueNeighborsResponse(current, null, ordered.size(), null, null);
        }
        QueueNeighborsResponse.Key prev = index > 0 ? key(ordered.get(index - 1), scope.role()) : null;
        QueueNeighborsResponse.Key next = index < ordered.size() - 1 ? key(ordered.get(index + 1), scope.role()) : null;
        return new QueueNeighborsResponse(current, index + 1, ordered.size(), prev, next);
    }

    /* ───────────────────────── 기준 시각·상세 메타데이터 ───────────────────────── */

    public TimeContextResponse timeContext(DashboardUserPrincipal principal) {
        List<String> allowed = captureAccessService.listAllowedCaptures(principal);
        return new TimeContextResponse(timeContextService.anchorFor(allowed), timeContextService.mode(),
                timeContextService.isSnapshot());
    }

    /**
     * 상세 헤더 메타데이터. 상세 조회(loadDetail)가 이미 권한을 검사한 작업·순위에만 부른다.
     * VIEWER 상세의 incident_id는 마스킹돼 있으므로 원본 행을 다시 읽어 찾는다(응답에는 원본 값을 넣지 않는다).
     */
    public IncidentQueueMeta metaFor(DashboardUserPrincipal principal, Long jobId, Integer queueRank) {
        IncidentQueueItem incident = zeekadReadMapper.findIncidentQueueItemByJobAndRank(jobId, queueRank);
        if (incident == null || principal == null || !principal.isCaptureAllowed(incident.getCaptureId())) {
            return null;
        }
        String sourceType = timeContextService.sourceType(incident.getCaptureId());
        List<String> allowed = captureAccessService.listAllowedCaptures(principal);
        UnifiedQueueRecord latest = findLatestRow(allowed, incident.getCaptureId(), incident.getIncidentId());
        OffsetDateTime anchor = timeContextService.anchorFor(allowed);
        if (latest == null) {
            return new IncidentQueueMeta(sourceType, null, null, false, null, null, anchor, null, false);
        }
        CaptureQueueStat stat = zeekadReadMapper.findCaptureQueueStats(List.of(incident.getCaptureId())).stream()
                .findFirst().orElse(null);
        OffsetDateTime due = ackTargetService.dueAt(latest.getCaptureId(), latest.getZeekadStatus(), latest.getPriority(),
                latest.getDetectedAt());
        return new IncidentQueueMeta(sourceType, latest.getDetectedAt(), latest.getPriority(),
                isOngoing(latest, stat, anchor), latest.getJobId(), latest.getQueueRank(),
                anchor, due, AckTargetService.isOverdue(due, anchor));
    }

    /**
     * 상세가 이미 권한을 검사한 작업·순위의 원본 incident_id(VIEWER 상세 응답의 incident_id는 가려져 있어 다시 읽는다).
     * 응답에 넣지 않고 담당 조회 키로만 쓴다.
     */
    public String rawIncidentId(Long jobId, Integer queueRank) {
        IncidentQueueItem incident = zeekadReadMapper.findIncidentQueueItemByJobAndRank(jobId, queueRank);
        return incident == null ? null : incident.getIncidentId();
    }

    /* ───────────────────────── 현황판·운영 현황 조건(T24) ───────────────────────── */

    /**
     * 기간·수집원·캡처 조건(T24 현황판·운영 현황이 큐와 같은 조건 조립을 쓴다).
     * allowed = 허용 캡처 전체, captureIds = 허용 ∩ 수집원 ∩ 고른 캡처, after = 기간 시작(불포함, all이면 null),
     * criteria = 같은 조건 큐(띠 축 없음)의 조회 조건. 잘못된 값은 큐와 같은 400, 허용 밖 captureId는 403·감사 기록이다.
     */
    public record Condition(List<String> allowed,
                            List<String> captureIds,
                            OffsetDateTime anchor,
                            String period,
                            OffsetDateTime after,
                            UnifiedQueueCriteria criteria) {
    }

    public Condition resolveCondition(DashboardUserPrincipal principal, String period, String source, String captureId,
                                      String clientIp) {
        QueueParams p = new QueueParams(period, source, captureId, null, null, null, null, null, null, null, null,
                null, null, null, null, null);
        Scope scope = resolveScope(principal, p, clientIp, true);
        return new Condition(scope.allowed(), scope.captureIds(), scope.anchor(), scope.period(),
                scope.criteria().getDetectedAfter(), scope.criteria());
    }

    /** 기간 이름 → 길이(all이면 null) */
    public static Duration periodLength(String period) {
        return PERIODS.get(period);
    }

    /* ───────────────────────── 내부 ───────────────────────── */

    private record Masked(UnifiedQueueRecord record, IncidentQueueItem item) {
    }

    private UnifiedQueueRecord findLatestRow(List<String> allowed, String captureId, String incidentId) {
        if (captureId == null || incidentId == null || !allowed.contains(captureId)) {
            return null;
        }
        UnifiedQueueCriteria c = new UnifiedQueueCriteria();
        c.setCaptureIds(List.of(captureId));
        c.setIncidentId(incidentId);
        c.setLimit(1);
        List<UnifiedQueueRecord> rows = zeekadReadMapper.findUnifiedQueue(c);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private QueueNeighborsResponse.Key key(UnifiedQueueRecord r, UserRole role) {
        String host = maskingService.shouldMask(role) ? maskingService.maskIp(r.getHostIp()) : r.getHostIp();
        return new QueueNeighborsResponse.Key(r.getJobId(), r.getQueueRank(), host);
    }

    /** 진행 중: 실습망 센서 · 종결 아님 · 이 인시던트의 event_end = 캡처 최신 작업의 최대 event_end · 그 값 ≥ 기준 시각 −15분 */
    public boolean isOngoing(UnifiedQueueRecord record, CaptureQueueStat stat, OffsetDateTime anchor) {
        if (record == null || stat == null || anchor == null) {
            return false;
        }
        if (!timeContextService.isLive(record.getCaptureId())) {
            return false;
        }
        if (isClosed(record.getZeekadStatus())) {
            return false;
        }
        OffsetDateTime maxEnd = stat.getMaxEventEnd();
        if (maxEnd == null || record.getEventEnd() == null || !record.getEventEnd().isEqual(maxEnd)) {
            return false;
        }
        return !maxEnd.isBefore(anchor.minus(ONGOING_WINDOW));
    }

    private static boolean isClosed(String status) {
        return status != null && "closed".equals(status.trim().toLowerCase(Locale.ROOT));
    }

    private Scope resolveScope(DashboardUserPrincipal principal, QueueParams p, String clientIp, boolean applyPeriod) {
        List<String> allowed = captureAccessService.listAllowedCaptures(principal);
        String captureId = trimToNull(p.captureId());
        if (captureId != null) {
            captureAccessService.requireCaptureAccess(principal, captureId, clientIp);
        }
        String period = trimToNull(p.period()) == null ? DEFAULT_PERIOD : p.period().trim().toLowerCase(Locale.ROOT);
        if (!"all".equals(period) && !PERIODS.containsKey(period)) {
            throw invalid("기간 값이 올바르지 않습니다.");
        }
        String source = trimToNull(p.source());
        if (source != null) {
            source = source.toLowerCase(Locale.ROOT);
            if (!TimeContextService.SOURCE_LIVE.equals(source) && !TimeContextService.SOURCE_IMPORTED.equals(source)) {
                throw invalid("수집원 값이 올바르지 않습니다.");
            }
        }
        String priority = trimToNull(p.priority());
        if (priority != null) {
            priority = priority.toLowerCase(Locale.ROOT);
            if (!PRIORITIES.contains(priority)) {
                throw invalid("우선순위 값이 올바르지 않습니다.");
            }
        }
        String sortKey = trimToNull(p.sort()) == null ? "priority" : p.sort().trim().toLowerCase(Locale.ROOT);
        if (!SORT_KEYS.contains(sortKey)) {
            throw invalid("정렬 값이 올바르지 않습니다.");
        }
        String dir = trimToNull(p.dir());
        boolean asc;
        if (dir == null) {
            asc = DEFAULT_ASC.get(sortKey);
        } else if ("asc".equalsIgnoreCase(dir.trim())) {
            asc = true;
        } else if ("desc".equalsIgnoreCase(dir.trim())) {
            asc = false;
        } else {
            throw invalid("정렬 방향 값이 올바르지 않습니다.");
        }

        String assignee = trimToNull(p.assignee());
        if (assignee != null) {
            assignee = assignee.toLowerCase(Locale.ROOT);
            if (!ASSIGNEE_ME.equals(assignee) && !ASSIGNEE_NONE.equals(assignee)) {
                throw invalid("담당 값이 올바르지 않습니다.");
            }
        }

        List<String> captureIds = new ArrayList<>();
        for (String cap : allowed) {
            if (captureId != null && !captureId.equals(cap)) {
                continue;
            }
            if (source != null && !source.equals(timeContextService.sourceType(cap))) {
                continue;
            }
            captureIds.add(cap);
        }

        OffsetDateTime anchor = timeContextService.anchorFor(allowed);
        UnifiedQueueCriteria c = new UnifiedQueueCriteria();
        // T25 담당 조건: 담당 행(담당자가 있는 것만)의 incident_id 목록을 배열 바인드 하나로 넘긴다.
        // me는 목록 안, none은 목록 밖. me인데 목록이 비면 빈 결과(VIEWER의 me도 빈 결과), none인데 비면 조건 없음.
        if (assignee != null) {
            boolean me = ASSIGNEE_ME.equals(assignee);
            Long userId = me && principal != null ? principal.getId() : null;
            List<String> ids = me && (userId == null || principal.getRole() == UserRole.VIEWER)
                    ? List.of()
                    : incidentAssignmentService.assignedIncidentIds(userId, captureIds);
            if (me && ids.isEmpty()) {
                captureIds = new ArrayList<>();
            }
            c.setAssigneeMode(assignee);
            c.setAssigneeIncidentIds(ids.toArray(new String[0]));
        }
        c.setCaptureIds(List.copyOf(captureIds));
        // T25 착수 지연 식(큐 행·요약·띠 축이 같은 경계를 쓴다)
        c.setLiveCaptureIds(captureIds.stream().filter(timeContextService::isLive).toList());
        c.setAckHighBefore(anchor.minus(ackTargetService.high()));
        c.setAckMediumBefore(anchor.minus(ackTargetService.medium()));
        c.setAckLowBefore(anchor.minus(ackTargetService.low()));
        c.setOverdue("true".equalsIgnoreCase(trimToNull(p.overdue())));
        if (applyPeriod && !"all".equals(period)) {
            c.setDetectedAfter(anchor.minus(PERIODS.get(period)));
            c.setDetectedUntil(anchor);
        }
        c.setPickedBy(trimToNull(p.pickedBy()));
        c.setRole(trimToNull(p.role()));
        String status = trimToNull(p.status());
        c.setStatus(status == null ? null : status.toLowerCase(Locale.ROOT));
        c.setHasReport(parseOptionalBoolean(p.hasReport()));
        c.setWouldSend(parseOptionalBoolean(p.wouldSend()));
        c.setPriority(priority);
        c.setReviewPending("true".equalsIgnoreCase(trimToNull(p.reviewPending())));
        c.setAlerted("true".equalsIgnoreCase(trimToNull(p.alerted())));
        c.setSortKey(sortKey);
        c.setSortAsc(asc);

        UserRole role = principal != null ? principal.getRole() : UserRole.VIEWER;
        return new Scope(allowed, c.getCaptureIds(), anchor, period, c, trimToNull(p.asset()), role);
    }

    /**
     * 자산 검색 경로: 띠 축을 뺀 거르기·정렬을 SQL로 한 전체 결과(상한 ASSET_SEARCH_CAP)를 받아
     * 역할 마스킹 → matchesAssetFilter로 거른다(VIEWER는 가려진 값에만 맞는다). 순서는 SQL 순서 그대로다.
     */
    private List<Masked> assetFiltered(UnifiedQueueCriteria criteria, String asset, UserRole role) {
        UnifiedQueueCriteria c = criteria.copy();
        c.setApplyStripFilters(false);
        c.setLimit(ASSET_SEARCH_CAP + 1);
        c.setOffset(null);
        List<UnifiedQueueRecord> rows = zeekadReadMapper.findUnifiedQueue(c);
        if (rows.size() > ASSET_SEARCH_CAP) {
            throw new QueueQueryException("QUERY_TOO_BROAD", "기간이나 수집원을 좁혀 주세요");
        }
        List<Masked> out = new ArrayList<>();
        for (UnifiedQueueRecord r : rows) {
            IncidentQueueItem masked = maskingService.maskIncidentQueueItem(r, role);
            if (IncidentQueryService.matchesAssetFilter(masked, asset)) {
                out.add(new Masked(r, masked));
            }
        }
        return out;
    }

    private List<Masked> assetFilteredOrEmpty(UnifiedQueueCriteria criteria, String asset, UserRole role) {
        try {
            return assetFiltered(criteria, asset, role);
        } catch (QueueQueryException e) {
            return List.of();
        }
    }

    private static List<Masked> applyStripFilters(List<Masked> rows, UnifiedQueueCriteria c) {
        return rows.stream().filter(m -> {
            UnifiedQueueRecord r = m.record();
            if (c.getPriority() != null && !c.getPriority().equals(r.getPriority())) {
                return false;
            }
            if (c.isReviewPending() && !r.isZeekadReviewPending()) {
                return false;
            }
            if (c.isOverdue() && !isOverdueRecord(r, c)) {
                return false;
            }
            return !c.isAlerted() || r.isAlerted();
        }).toList();
    }

    /** SQL 착수 지연 식(ackOverdueCond)과 같은 판정: 실습망 · 신규 · detected_at &lt; 기준 시각 − 우선순위 목표 */
    static boolean isOverdueRecord(UnifiedQueueRecord r, UnifiedQueueCriteria c) {
        if (!c.isAckReady() || r.getDetectedAt() == null || !AckTargetService.isOpen(r.getZeekadStatus())
                || !c.getLiveCaptureIds().contains(r.getCaptureId()) || r.getPriority() == null) {
            return false;
        }
        OffsetDateTime before = switch (r.getPriority()) {
            case "high" -> c.getAckHighBefore();
            case "medium" -> c.getAckMediumBefore();
            case "low" -> c.getAckLowBefore();
            default -> null;
        };
        return before != null && r.getDetectedAt().isBefore(before);
    }

    private static UnifiedQueueResponse.Summary summarize(List<Masked> rows, UnifiedQueueCriteria c) {
        long high = 0, medium = 0, low = 0, review = 0, alerted = 0, open = 0, inv = 0, closed = 0, other = 0, overdue = 0;
        for (Masked m : rows) {
            UnifiedQueueRecord r = m.record();
            if (isOverdueRecord(r, c)) overdue++;
            if ("high".equals(r.getPriority())) high++;
            else if ("medium".equals(r.getPriority())) medium++;
            else if ("low".equals(r.getPriority())) low++;
            if (r.isZeekadReviewPending()) review++;
            if (r.isAlerted()) alerted++;
            String s = r.getZeekadStatus() == null ? "" : r.getZeekadStatus().trim().toLowerCase(Locale.ROOT);
            if (s.isEmpty() || "open".equals(s)) open++;
            else if ("investigating".equals(s)) inv++;
            else if ("closed".equals(s)) closed++;
            else other++;
        }
        return new UnifiedQueueResponse.Summary(rows.size(), high, medium, low, review, alerted,
                statusMap(open, inv, closed, other), overdue);
    }

    private static UnifiedQueueResponse.Summary toSummary(UnifiedQueueSummaryRow row) {
        if (row == null) {
            return emptySummary();
        }
        return new UnifiedQueueResponse.Summary(row.getTotal(), row.getHigh(), row.getMedium(), row.getLow(),
                row.getReviewPending(), row.getAlerted(),
                statusMap(row.getStatusOpen(), row.getStatusInvestigating(), row.getStatusClosed(), row.getStatusOther()),
                row.getOverdue());
    }

    private static UnifiedQueueResponse.Summary emptySummary() {
        return new UnifiedQueueResponse.Summary(0, 0, 0, 0, 0, 0, statusMap(0, 0, 0, 0), 0);
    }

    private static Map<String, Long> statusMap(long open, long inv, long closed, long other) {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put("open", open);
        m.put("investigating", inv);
        m.put("closed", closed);
        m.put("other", other);
        return m;
    }

    static int parseSize(String raw) {
        try {
            int n = Integer.parseInt(raw == null ? "" : raw.trim());
            return PAGE_SIZES.contains(n) ? n : DEFAULT_PAGE_SIZE;
        } catch (NumberFormatException e) {
            return DEFAULT_PAGE_SIZE;
        }
    }

    private static int pageCount(long total, int size) {
        return (int) Math.max(1, (total + size - 1) / size);
    }

    /** 숫자가 아니거나 1보다 작으면 1쪽, 범위 밖이면 마지막 쪽 */
    private static int clampPage(String raw, int pageCount) {
        int page;
        try {
            page = Integer.parseInt(raw == null ? "" : raw.trim());
        } catch (NumberFormatException e) {
            page = 1;
        }
        if (page < 1) {
            page = 1;
        }
        return Math.min(page, pageCount);
    }

    private static OffsetDateTime parseTime(String raw) {
        if (raw == null || raw.isBlank()) {
            throw invalid("since 값이 필요합니다.");
        }
        try {
            return OffsetDateTime.parse(raw.trim());
        } catch (DateTimeParseException e) {
            throw invalid("since 시각 형식이 올바르지 않습니다.");
        }
    }

    private static QueueQueryException invalid(String message) {
        return new QueueQueryException("INVALID_REQUEST", message);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static Boolean parseOptionalBoolean(String value) {
        String clean = trimToNull(value);
        if ("true".equalsIgnoreCase(clean)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(clean)) {
            return Boolean.FALSE;
        }
        return null;
    }
}
