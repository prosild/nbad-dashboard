package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.DashboardOverviewResponse.Attack;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.HostRow;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.TacticCount;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.TechniqueCount;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.ThreadRow;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.TopHosts;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.IncidentRef;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentAttackCandidates;
import com.zeekad.dashboard.model.zeekad.IncidentPoint;
import com.zeekad.dashboard.model.zeekad.ThreadHeadRow;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * T45b 현황판 위협 가시성: ATT&amp;CK 전술·기법 후보 분포, 통신 방향별 위험 호스트 상위, 주요 알림 묶음 상위.
 * 세 집계 모두 현황판이 이미 읽은 같은 조건의 큐 행(points)에서 센다. 그래서 각 수가 같은 조건 큐의 total과 같다.
 * 읽기 횟수는 행·호스트·묶음 수와 무관하다: 후보 1번, Slack 짝 1번, 번호 행 읽기 1번(readRefsOnly), 답글 짝 1번,
 * 최신 큐 소속 1번, 머리 행 1번. 조건의 행이 없으면 아무것도 읽지 않는다. 번호 동기화 쓰기를 일으키지 않는다.
 */
@Service
public class DashboardThreatService {

    public static final int TOP_TECHNIQUES = 10;
    public static final int TOP_HOSTS = 5;
    public static final int TOP_THREADS = 5;
    public static final String ROLE_ORIGINATOR = "originator";
    public static final String ROLE_RESPONDER = "responder";

    private final ZeekadReadMapper zeekadReadMapper;
    private final IncidentQueueService incidentQueueService;
    private final SlackThreadService slackThreadService;
    private final MaskingService maskingService;

    public DashboardThreatService(ZeekadReadMapper zeekadReadMapper,
                                  IncidentQueueService incidentQueueService,
                                  SlackThreadService slackThreadService,
                                  MaskingService maskingService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.incidentQueueService = incidentQueueService;
        this.slackThreadService = slackThreadService;
        this.maskingService = maskingService;
    }

    public record Result(Attack attack, TopHosts topHosts, List<ThreadRow> topThreads, boolean topThreadsOmitted) {
    }

    private record Threads(List<ThreadRow> rows, boolean omitted) {
    }

    /** incident_id별 조건 안 행 수와 가장 늦은 탐지 시각 */
    private static final class IncidentAcc {
        long rows;
        OffsetDateTime latest;
    }

    public static Result empty() {
        return new Result(new Attack(0, List.of(), List.of(), 0), new TopHosts(List.of(), List.of()), List.of(), false);
    }

    /**
     * @param cond   현황판 조건(allowed = 허용 캡처 전체, captureIds = 조건의 캡처)
     * @param points cond.criteria()로 읽은 큐 행(현황판 추이·캡처 행과 같은 목록)
     */
    public Result compute(IncidentQueueService.Condition cond, List<IncidentPoint> points, UserRole role) {
        if (cond.captureIds().isEmpty() || points.isEmpty()) {
            return empty();
        }
        boolean mask = maskingService.shouldMask(role);
        Map<String, IncidentAcc> byIncident = new HashMap<>();
        for (IncidentPoint p : points) {
            if (p.getIncidentId() == null) {
                continue;
            }
            IncidentAcc acc = byIncident.computeIfAbsent(p.getIncidentId(), k -> new IncidentAcc());
            acc.rows++;
            acc.latest = later(acc.latest, p.getDetectedAt());
        }
        Threads threads = topThreads(cond.allowed(), byIncident, mask);
        return new Result(attack(cond.captureIds(), byIncident, mask), topHosts(points, mask), threads.rows(),
                threads.omitted());
    }

    /* ───────────────────────── ATT&CK 전술·기법 후보 분포 ───────────────────────── */

    /**
     * 값마다 큐 attack 조건과 같은 방법으로 맞는 incident_id 집합을 만들고(AttackFilter.visit), 조건 안 행 가운데
     * incident_id가 그 집합에 든 행 수를 센다. 한 인시던트의 후보에 같은 값이 여러 번 나와도 한 번이다.
     */
    private Attack attack(List<String> captureIds, Map<String, IncidentAcc> byIncident, boolean mask) {
        if (byIncident.isEmpty()) {
            return new Attack(0, List.of(), List.of(), 0);
        }
        Map<String, Set<String>> tacticIncidents = new HashMap<>();
        Map<String, Set<String>> techniqueIncidents = new HashMap<>();
        // 기법 ID → 이름 → 그 이름이 붙은 incident_id
        Map<String, Map<String, Set<String>>> nameIncidents = new HashMap<>();
        Set<String> withCandidates = new HashSet<>();
        for (IncidentAttackCandidates row : zeekadReadMapper.findLatestAttackCandidates(captureIds)) {
            if (row == null || row.getIncidentId() == null || !byIncident.containsKey(row.getIncidentId())) {
                continue;
            }
            String incidentId = row.getIncidentId();
            AttackFilter.visit(row.getCandidates(), new AttackFilter.CandidateVisitor() {
                @Override
                public void technique(String attackId, String name) {
                    withCandidates.add(incidentId);
                    techniqueIncidents.computeIfAbsent(attackId, k -> new HashSet<>()).add(incidentId);
                    // 조회자: 이름에 주소가 섞여 와도 나가지 않게 가린 글로 센다
                    String shown = name != null && mask ? maskingService.maskIpsInText(name) : name;
                    if (shown != null) {
                        nameIncidents.computeIfAbsent(attackId, k -> new HashMap<>())
                                .computeIfAbsent(shown, k -> new HashSet<>()).add(incidentId);
                    }
                }

                @Override
                public void tactic(String slug) {
                    withCandidates.add(incidentId);
                    tacticIncidents.computeIfAbsent(slug, k -> new HashSet<>()).add(incidentId);
                }
            });
        }
        List<TacticCount> tactics = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : tacticIncidents.entrySet()) {
            tactics.add(new TacticCount(e.getKey(), rowCount(e.getValue(), byIncident)));
        }
        tactics.sort(Comparator.comparingLong(TacticCount::count).reversed().thenComparing(TacticCount::tactic));
        List<TechniqueCount> techniques = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : techniqueIncidents.entrySet()) {
            techniques.add(new TechniqueCount(e.getKey(), commonName(nameIncidents.get(e.getKey())),
                    rowCount(e.getValue(), byIncident)));
        }
        techniques.sort(Comparator.comparingLong(TechniqueCount::count).reversed()
                .thenComparing(TechniqueCount::attackId));
        int techniqueCount = techniques.size();
        return new Attack(rowCount(withCandidates, byIncident), List.copyOf(tactics),
                List.copyOf(techniques.subList(0, Math.min(TOP_TECHNIQUES, techniqueCount))), techniqueCount);
    }

    private static long rowCount(Set<String> incidentIds, Map<String, IncidentAcc> byIncident) {
        long n = 0;
        for (String id : incidentIds) {
            IncidentAcc acc = byIncident.get(id);
            if (acc != null) {
                n += acc.rows;
            }
        }
        return n;
    }

    /** 가장 많은 인시던트에 붙은 이름. 같으면 글자 순으로 앞, 없으면 null(읽는 순서에 기대지 않는다) */
    private static String commonName(Map<String, Set<String>> names) {
        if (names == null) {
            return null;
        }
        String best = null;
        int bestCount = 0;
        for (Map.Entry<String, Set<String>> e : names.entrySet()) {
            int n = e.getValue().size();
            if (n > bestCount || (n == bestCount && best != null && e.getKey().compareTo(best) < 0)) {
                best = e.getKey();
                bestCount = n;
            }
        }
        return best;
    }

    /* ───────────────────────── 통신 방향별 위험 호스트 ───────────────────────── */

    private static final class HostAcc {
        long high;
        long medium;
        long low;
        long total;
        OffsetDateTime last;
    }

    /**
     * 통신 방향은 큐 role 조건(LOWER(zeekad_role) = LOWER(값))과 같게 소문자로만 바꿔 비교한다(공백을 떼지 않는다).
     * 묶는 단위는 조회자면 가린 주소, 아니면 원문이다. 원문으로 묶은 뒤 가리지 않는다(줄 수·순서로 원문 호스트 수가 드러난다).
     * 주소가 없는 행은 호스트 줄을 만들지 않는다(큐 hostIp 조건으로 갈 수 없다).
     */
    private TopHosts topHosts(List<IncidentPoint> points, boolean mask) {
        Map<String, HostAcc> originator = new HashMap<>();
        Map<String, HostAcc> responder = new HashMap<>();
        for (IncidentPoint p : points) {
            String role = p.getZeekadRole() == null ? null : p.getZeekadRole().toLowerCase(Locale.ROOT);
            Map<String, HostAcc> target = ROLE_ORIGINATOR.equals(role) ? originator
                    : ROLE_RESPONDER.equals(role) ? responder : null;
            String host = p.getHostIp();
            if (target == null || host == null || host.isBlank()) {
                continue;
            }
            HostAcc acc = target.computeIfAbsent(mask ? maskingService.maskIp(host) : host, k -> new HostAcc());
            acc.total++;
            if ("high".equals(p.getPriority())) acc.high++;
            else if ("medium".equals(p.getPriority())) acc.medium++;
            else if ("low".equals(p.getPriority())) acc.low++;
            acc.last = later(acc.last, p.getDetectedAt());
        }
        return new TopHosts(hostRows(originator), hostRows(responder));
    }

    private static List<HostRow> hostRows(Map<String, HostAcc> hosts) {
        List<HostRow> rows = new ArrayList<>();
        for (Map.Entry<String, HostAcc> e : hosts.entrySet()) {
            HostAcc a = e.getValue();
            rows.add(new HostRow(e.getKey(), a.high, a.medium, a.low, a.total, a.last));
        }
        rows.sort(Comparator.comparingLong(HostRow::high).reversed()
                .thenComparing(Comparator.comparingLong(HostRow::medium).reversed())
                .thenComparing(Comparator.comparingLong(HostRow::low).reversed())
                .thenComparing(Comparator.comparingLong(HostRow::total).reversed())
                .thenComparing(r -> instant(r.lastDetectedAt()), Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(HostRow::hostIp));
        return List.copyOf(rows.subList(0, Math.min(TOP_HOSTS, rows.size())));
    }

    /* ───────────────────────── 주요 알림 묶음 ───────────────────────── */

    private record ThreadCandidate(String head, IncidentRef ref, long periodCount, long totalCount,
                                   OffsetDateTime latest) {
    }

    /**
     * 묶음과 구성원의 정의는 큐 행 묶음 표지(T45)와 같다: 조건 안 인시던트의 후보 머리(candidateHeads) 가운데 보이는 머리
     * (visibleThreadHeads)의 구성원 집합과 허용 캡처 전체 최신 큐의 구성원 수(visibleThreadMembers)를 쓴다.
     * 대상은 조건 안 구성원 행이 1건 이상이고 전체 구성원이 2건 이상인 묶음이다.
     * 큐 표지와 같은 한계: 조건 안의 머리에 자기 Slack 행이 없고 조건 안 답글도 없으면 후보에 오르지 않는다.
     */
    private Threads topThreads(List<String> allowed, Map<String, IncidentAcc> byIncident, boolean mask) {
        if (allowed.isEmpty() || byIncident.isEmpty()) {
            return new Threads(List.of(), false);
        }
        Set<String> heads = new LinkedHashSet<>();
        slackThreadService.candidateHeads(byIncident.keySet()).values().forEach(heads::addAll);
        if (heads.isEmpty()) {
            return new Threads(List.of(), false);
        }
        Map<String, IncidentRef> visible = incidentQueueService.visibleThreadHeads(allowed, heads);
        if (visible.isEmpty()) {
            return new Threads(List.of(), false);
        }
        SlackThreadService.ThreadMembers threads = slackThreadService.visibleThreadMembers(allowed, visible.keySet());
        if (threads.omitted()) {
            return new Threads(List.of(), true);
        }
        List<ThreadCandidate> candidates = new ArrayList<>();
        for (Map.Entry<String, Long> e : threads.visibleCounts().entrySet()) {
            long total = e.getValue();
            Set<String> members = threads.members().get(e.getKey());
            if (total < 2 || members == null) {
                continue;
            }
            long inPeriod = 0;
            OffsetDateTime latest = null;
            for (String member : members) {
                IncidentAcc acc = byIncident.get(member);
                if (acc != null) {
                    inPeriod += acc.rows;
                    latest = later(latest, acc.latest);
                }
            }
            if (inPeriod >= 1) {
                candidates.add(new ThreadCandidate(e.getKey(), visible.get(e.getKey()), inPeriod, total, latest));
            }
        }
        candidates.sort(Comparator.comparingLong(ThreadCandidate::periodCount).reversed()
                .thenComparing(Comparator.comparingLong(ThreadCandidate::totalCount).reversed())
                .thenComparing(c -> instant(c.latest()), Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(Comparator.comparingLong((ThreadCandidate c) -> c.ref().getIncidentNo()).reversed()));
        List<ThreadCandidate> top = candidates.subList(0, Math.min(TOP_THREADS, candidates.size()));
        if (top.isEmpty()) {
            return new Threads(List.of(), false);
        }
        // 머리는 지금 조건 밖(기간 앞, 다른 수집원, 고르지 않은 캡처)일 수 있어 허용 캡처 전체에서 한 번 읽는다
        Map<String, ThreadHeadRow> headRows = new HashMap<>();
        String[] headIds = top.stream().map(ThreadCandidate::head).toArray(String[]::new);
        for (ThreadHeadRow row : zeekadReadMapper.findLatestQueueHeadRows(allowed, headIds)) {
            IncidentRef ref = row.getIncidentId() == null ? null : visible.get(row.getIncidentId());
            // 번호 행의 캡처와 같은 행만 쓴다(같으면 순위가 앞선 행)
            if (ref != null && ref.getCaptureId().equals(row.getCaptureId())) {
                headRows.putIfAbsent(row.getIncidentId(), row);
            }
        }
        List<ThreadRow> rows = new ArrayList<>();
        for (ThreadCandidate c : top) {
            ThreadHeadRow head = headRows.get(c.head());
            String host = head == null ? null : head.getHostIp();
            rows.add(new ThreadRow(c.ref().getIncidentNo(),
                    host != null && mask ? maskingService.maskIp(host) : host,
                    head == null ? null : head.getZeekadPickedBy(),
                    c.periodCount(), c.totalCount(), c.latest()));
        }
        return new Threads(List.copyOf(rows), false);
    }

    private static OffsetDateTime later(OffsetDateTime a, OffsetDateTime b) {
        if (a == null) return b;
        if (b == null) return a;
        return b.toInstant().isAfter(a.toInstant()) ? b : a;
    }

    private static Instant instant(OffsetDateTime t) {
        return t == null ? null : t.toInstant();
    }
}
