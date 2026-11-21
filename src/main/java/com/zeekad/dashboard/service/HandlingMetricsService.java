package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.dto.OperationsApiResponse.AssigneeLoad;
import com.zeekad.dashboard.dto.OperationsApiResponse.HandlingTimes;
import com.zeekad.dashboard.dto.OperationsApiResponse.ResolutionStat;
import com.zeekad.dashboard.dto.OperationsApiResponse.ResolveTimes;
import com.zeekad.dashboard.dto.OperationsApiResponse.TimeStat;
import com.zeekad.dashboard.dto.OperationsApiResponse.Workload;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.zeekad.HandlingPoint;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 처리 시간 지표와 담당 현황(T25). 모두 기준 시각 기준이고 기간은 (anchor − P, anchor](period all이면 경계 없음, T24와 같다).
 * <ul>
 *   <li>탐지 지연(MTTD): detectedAt − event_start. 실습망 수집원이고 detectedAt이 기간 안. 가져온 데이터는 event_start가
 *       원본 데이터셋 시각이라 뺀다.</li>
 *   <li>착수 시간(MTTA): 착수 시각(첫 investigating 이력) − detectedAt. 착수 시각이 기간 안. 조사 중 기록 없이 종결된 건(종결 시각이
 *       기간 안)은 제외 수에 센다.</li>
 *   <li>처리 시간(MTTR): 종결 시각(status_updated_at) − detectedAt. 종결 시각이 기간 안. 판정별로도(판정 없음 = none).</li>
 *   <li>값마다 건수·중앙값·p90(가장 가까운 순위: 정렬 뒤 ceil(p·n)번째)·제외(음수·필요한 시각 없음)·표본 부족(0 &lt; n &lt; 10).</li>
 * </ul>
 * 담당 현황은 기간과 무관한 지금 값이다: 수집원 조건 안의 미종결(open·investigating) 인시던트.
 */
@Service
public class HandlingMetricsService {

    public static final int SMALL_SAMPLE = 10;
    public static final List<String> RESOLUTION_ORDER = List.of("true_positive", "false_positive", "benign", "none");

    private final ZeekadReadMapper zeekadReadMapper;
    private final TimeContextService timeContextService;
    private final AckTargetService ackTargetService;
    private final IncidentAssignmentService incidentAssignmentService;

    public HandlingMetricsService(ZeekadReadMapper zeekadReadMapper,
                                  TimeContextService timeContextService,
                                  AckTargetService ackTargetService,
                                  IncidentAssignmentService incidentAssignmentService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.timeContextService = timeContextService;
        this.ackTargetService = ackTargetService;
        this.incidentAssignmentService = incidentAssignmentService;
    }

    public record Result(HandlingTimes handlingTimes, Workload workload) {
    }

    /**
     * cond(수집원·캡처 조건)의 인시던트로 계산한다. periodGiven=false면 handlingTimes는 null(옛 응답 호환)이고 SQL 하한도 없다.
     */
    public Result compute(IncidentQueueService.Condition cond, boolean periodGiven) {
        if (cond.captureIds().isEmpty()) {
            return new Result(periodGiven ? handlingTimes(List.of(), null, null) : null, workload(List.of(), cond.anchor()));
        }
        OffsetDateTime after = periodGiven ? cond.after() : null;
        List<HandlingPoint> points = zeekadReadMapper.findHandlingPoints(cond.criteria(), after);
        OffsetDateTime until = after == null ? null : cond.anchor();
        HandlingTimes times = periodGiven ? handlingTimes(points, after, until) : null;
        return new Result(times, workload(points, cond.anchor()));
    }

    /* ───────────────────────── 처리 시간 ───────────────────────── */

    HandlingTimes handlingTimes(List<HandlingPoint> points, OffsetDateTime after, OffsetDateTime until) {
        Acc detection = new Acc();
        Acc acknowledge = new Acc();
        Acc resolve = new Acc();
        Map<String, Acc> byResolution = new LinkedHashMap<>();
        for (String r : RESOLUTION_ORDER) {
            byResolution.put(r, new Acc());
        }
        for (HandlingPoint p : points) {
            if (timeContextService.isLive(p.getCaptureId()) && inRange(p.getDetectedAt(), after, until)) {
                detection.add(p.getEventStart(), p.getDetectedAt());
            }
            if (inRange(p.getAckAt(), after, until)) {
                acknowledge.add(p.getDetectedAt(), p.getAckAt());
            }
            if (isClosed(p) && inRange(p.getStatusUpdatedAt(), after, until)) {
                resolve.add(p.getDetectedAt(), p.getStatusUpdatedAt());
                byResolution.computeIfAbsent(resolutionKey(p.getZeekadResolution()), k -> new Acc())
                        .add(p.getDetectedAt(), p.getStatusUpdatedAt());
                if (p.getAckAt() == null) {
                    acknowledge.excluded++; // 조사 중 기록 없이 종결(파이프라인 반영·옛 자료)
                }
            }
        }
        List<ResolutionStat> rows = new ArrayList<>();
        byResolution.forEach((k, acc) -> rows.add(new ResolutionStat(k, acc.stat())));
        return new HandlingTimes(detection.stat(), acknowledge.stat(), new ResolveTimes(resolve.stat(), rows));
    }

    /** 한 지표의 값 모음(초) */
    static final class Acc {
        final List<Long> values = new ArrayList<>();
        long excluded;

        void add(OffsetDateTime from, OffsetDateTime to) {
            if (from == null || to == null) {
                excluded++;
                return;
            }
            long seconds = Duration.between(from.toInstant(), to.toInstant()).getSeconds();
            if (seconds < 0) {
                excluded++;
                return;
            }
            values.add(seconds);
        }

        TimeStat stat() {
            List<Long> sorted = new ArrayList<>(values);
            sorted.sort(Comparator.naturalOrder());
            int n = sorted.size();
            return new TimeStat(n, nearestRank(sorted, 1, 2), nearestRank(sorted, 9, 10), excluded,
                    n > 0 && n < SMALL_SAMPLE);
        }
    }

    /** 가장 가까운 순위 백분위(p = num/den): 정렬 뒤 ceil(p·n)번째(1부터). PostgreSQL percentile_disc와 같다. 비면 null */
    static Long nearestRank(List<Long> sorted, int num, int den) {
        int n = sorted.size();
        if (n == 0) {
            return null;
        }
        int rank = (int) ((num * (long) n + den - 1) / den); // ceil(num·n/den), 정수 계산
        return sorted.get(Math.max(1, rank) - 1);
    }

    static String resolutionKey(String resolution) {
        String r = resolution == null ? "" : resolution.trim().toLowerCase(Locale.ROOT);
        return r.isEmpty() ? "none" : r;
    }

    private static boolean isClosed(HandlingPoint p) {
        return "closed".equals(p.getStatusNorm());
    }

    /** (after, until]. 둘 다 null이면(기간 all) 시각만 있으면 든다 */
    static boolean inRange(OffsetDateTime t, OffsetDateTime after, OffsetDateTime until) {
        if (t == null) {
            return false;
        }
        if (after != null && !t.isAfter(after)) {
            return false;
        }
        return until == null || !t.isAfter(until);
    }

    /* ───────────────────────── 담당 현황 ───────────────────────── */

    Workload workload(List<HandlingPoint> points, OffsetDateTime anchor) {
        List<HandlingPoint> unclosed = points.stream()
                .filter(p -> "open".equals(p.getStatusNorm()) || "investigating".equals(p.getStatusNorm()))
                .toList();
        Map<String, AssignmentDtos.Assignee> assignees = incidentAssignmentService.assigneesFor(
                unclosed.stream().map(HandlingPoint::getIncidentId).toList());
        long overdue = 0;
        Map<String, long[]> counts = new HashMap<>();
        Map<String, AssignmentDtos.Assignee> people = new HashMap<>();
        for (HandlingPoint p : unclosed) {
            OffsetDateTime due = ackTargetService.dueAt(p.getCaptureId(), p.getStatusNorm(), p.getPriority(), p.getDetectedAt());
            if (AckTargetService.isOverdue(due, anchor)) {
                overdue++;
            }
            AssignmentDtos.Assignee a = assignees.get(p.getIncidentId());
            if (a != null) {
                String key = a.username().toLowerCase(Locale.ROOT);
                people.putIfAbsent(key, a);
                long[] c = counts.computeIfAbsent(key, k -> new long[2]);
                if ("open".equals(p.getStatusNorm())) c[0]++;
                else c[1]++;
            }
        }
        List<AssigneeLoad> byAssignee = new ArrayList<>();
        counts.forEach((k, c) -> {
            AssignmentDtos.Assignee a = people.get(k);
            byAssignee.add(new AssigneeLoad(a.username(), a.displayName(), a.enabled(), c[0], c[1]));
        });
        byAssignee.sort(Comparator.comparingLong((AssigneeLoad l) -> -(l.open() + l.investigating()))
                .thenComparing(AssigneeLoad::displayName)
                .thenComparing(AssigneeLoad::username));
        long assigned = byAssignee.stream().mapToLong(l -> l.open() + l.investigating()).sum();
        return new Workload(unclosed.size(), assigned, unclosed.size() - assigned, overdue, byAssignee);
    }
}
