package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.DashboardOverviewResponse;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Alerting;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Bucket;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.CaptureRow;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.JobRef;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.SensorRow;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Trend;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Unbucketed;
import com.zeekad.dashboard.dto.OperationsApiResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.CaptureJobStat;
import com.zeekad.dashboard.model.zeekad.CaptureQueueStat;
import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.IncidentPoint;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 현황판 overview와 운영 현황(T24). 기간·수집원·캡처 조건은 통합 큐(IncidentQueueService.resolveCondition)와 같은 조립을 쓴다.
 * <ul>
 *   <li>탐지 추이: 큐와 같은 조건의 행을 가벼운 투영(캡처·탐지 시각·우선순위·경보 발송)으로 읽어 Java로 구간을 나눈다.
 *       구간은 표시 시간대(KST) 시계에 맞춘 고정 폭이고 (start, end]다.</li>
 *   <li>센서: live-patterns 패턴 하나가 센서 하나, 그 패턴에 맞는 허용 캡처(날짜별)가 묶음이다. 상태는 묶음 전체로 본다.</li>
 *   <li>숨긴 캡처(허용 밖)는 어떤 값에도 섞이지 않는다. VIEWER면 작업 오류 글의 IPv4를 가린다.</li>
 * </ul>
 */
@Service
public class DashboardOverviewService {

    /** 표시 시간대(서버 상수 한 곳). 프론트엔드 utils/format.ts DISPLAY_TIME_ZONE과 같아야 한다(정적 시험). */
    public static final String DISPLAY_TIME_ZONE = "Asia/Seoul";
    public static final ZoneId DISPLAY_ZONE = ZoneId.of(DISPLAY_TIME_ZONE);
    /** 운영 현황 작업 기록 상한(기간이 있을 때) */
    public static final int JOBS_LIMIT = 500;
    /** 기간 all: 첫 탐지 날부터 기준 시각 날까지 일 단위 구간 수가 이 값을 넘으면 주 단위 */
    public static final int ALL_DAILY_MAX = 92;

    public static final String HEALTH_OK = "ok";
    public static final String HEALTH_STALE = "stale";
    public static final String HEALTH_DOWN = "down";
    public static final String HEALTH_FAILED = "failed";
    public static final String HEALTH_NONE = "none";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_ENDED = "ended";
    public static final String STATE_IMPORTED = "imported";
    public static final String STATE_FAILED = "failed";
    public static final String STATE_NONE = "none";

    private final ZeekadReadMapper zeekadReadMapper;
    private final IncidentQueueService incidentQueueService;
    private final TimeContextService timeContextService;
    private final MaskingService maskingService;

    public DashboardOverviewService(ZeekadReadMapper zeekadReadMapper,
                                    IncidentQueueService incidentQueueService,
                                    TimeContextService timeContextService,
                                    MaskingService maskingService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.incidentQueueService = incidentQueueService;
        this.timeContextService = timeContextService;
        this.maskingService = maskingService;
    }

    /* ───────────────────────── overview ───────────────────────── */

    public DashboardOverviewResponse overview(DashboardUserPrincipal principal, String period, String source,
                                              String captureId, String clientIp) {
        IncidentQueueService.Condition cond = incidentQueueService.resolveCondition(principal, period, source, captureId, clientIp);
        UserRole role = roleOf(principal);
        OffsetDateTime anchor = cond.anchor();
        OffsetDateTime after = cond.after();
        OffsetDateTime until = after == null ? null : anchor;

        List<IncidentPoint> points = cond.captureIds().isEmpty()
                ? List.of() : zeekadReadMapper.findUnifiedQueuePoints(cond.criteria());
        Trend trend = buildTrend(cond.period(), anchor, points);

        SourceStatus status = sourceStatus(cond.allowed(), anchor, after, until, role);
        Map<String, long[]> counts = new HashMap<>();
        for (IncidentPoint p : points) {
            long[] c = counts.computeIfAbsent(p.getCaptureId(), k -> new long[3]);
            c[0]++;
            if ("high".equals(p.getPriority())) c[1]++;
            if (p.isAlerted()) c[2]++;
        }

        List<CaptureRow> captures = new ArrayList<>();
        for (String cap : cond.captureIds()) {
            long[] c = counts.getOrDefault(cap, new long[3]);
            CaptureInfo info = status.captures().get(cap);
            captures.add(new CaptureRow(cap, timeContextService.sourceType(cap), timeContextService.sensorKey(cap),
                    info.state(), info.latestEnded(), info.lastScoredAt(), info.lastActivityAt(),
                    c[0], c[1], c[2], info.failedInPeriod()));
        }

        List<SensorRow> sensors = new ArrayList<>();
        for (String pattern : timeContextService.sensorPatterns()) {
            List<CaptureRow> shown = captures.stream().filter(r -> pattern.equals(r.sensorKey())).toList();
            if (shown.isEmpty()) {
                continue;
            }
            SensorInfo s = status.sensors().get(pattern);
            sensors.add(new SensorRow(pattern, TimeContextService.sensorLabel(pattern), s.health(), s.latestEnded(),
                    s.activeCaptureId(), s.lastScoredAt(), s.lastActivityAt(),
                    shown.stream().mapToLong(CaptureRow::total).sum(),
                    shown.stream().mapToLong(CaptureRow::high).sum(),
                    shown.stream().mapToLong(CaptureRow::alerted).sum(),
                    shown.stream().mapToLong(CaptureRow::failedJobs).sum(),
                    s.captureCount()));
        }

        Alerting alerting = alerting(cond.captureIds(), after, until);
        return new DashboardOverviewResponse(anchor, timeContextService.mode(), timeContextService.isSnapshot(),
                cond.period(), DISPLAY_TIME_ZONE, timeContextService.staleAfter().toSeconds(),
                timeContextService.downAfter().toSeconds(), trend, sensors, captures, alerting,
                maskingService.shouldMask(role));
    }

    /* ───────────────────────── /api/operations ───────────────────────── */

    /**
     * 운영 현황. period가 없으면 지금처럼 전체다(jobs 상한 없음). period가 있으면 jobs·slackSummaries는 기간 안만이다.
     * feedbackSummaries는 기간 없이 누적이고 수집원 조건만 적용한다. bundles는 조건 수집원의 작업이 쓴 것만이다.
     */
    public OperationsApiResponse operations(DashboardUserPrincipal principal, String period, String source,
                                            String captureId, String clientIp) {
        boolean periodGiven = period != null && !period.isBlank();
        IncidentQueueService.Condition cond = incidentQueueService.resolveCondition(
                principal, periodGiven ? period : "all", source, captureId, clientIp);
        UserRole role = roleOf(principal);
        List<String> caps = cond.captureIds();
        OffsetDateTime after = cond.after();
        OffsetDateTime until = after == null ? null : cond.anchor();
        String cleanCaptureId = captureId == null || captureId.isBlank() ? null : captureId.trim();

        List<ScoringJob> jobs;
        long jobsTotal;
        boolean truncated;
        if (caps.isEmpty()) {
            jobs = List.of();
            jobsTotal = 0;
            truncated = false;
        } else if (!periodGiven) {
            jobs = zeekadReadMapper.findScoringJobsForCaptures(caps, null, null, null);
            jobsTotal = jobs.size();
            truncated = false;
        } else {
            jobs = zeekadReadMapper.findScoringJobsForCaptures(caps, after, until, JOBS_LIMIT);
            jobsTotal = jobs.size() < JOBS_LIMIT ? jobs.size() : zeekadReadMapper.countScoringJobsForCaptures(caps, after, until);
            truncated = jobsTotal > jobs.size();
        }
        jobs = jobs.stream().map(j -> maskingService.maskScoringJob(j, role)).toList();

        List<ModelBundle> bundles = caps.isEmpty() ? List.of() : zeekadReadMapper.findModelBundlesUsedByCaptures(caps);

        Set<String> capSet = new HashSet<>(caps);
        Comparator<FeedbackSummaryRecord> summaryOrder = Comparator
                .comparing(FeedbackSummaryRecord::getCaptureId, Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparing(FeedbackSummaryRecord::getBundleId, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(r -> r.isAllModel() ? 0 : 1, Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparing(FeedbackSummaryRecord::getZeekadPickedBy, Comparator.nullsLast(Comparator.naturalOrder()));
        List<FeedbackSummaryRecord> feedback = caps.isEmpty() ? List.of()
                : zeekadReadMapper.findRawFeedbackSummaries(cleanCaptureId).stream()
                .map(FeedbackSummaryRecord::fromRawMap)
                .filter(r -> r.getCaptureId() != null && capSet.contains(r.getCaptureId()))
                .sorted(summaryOrder)
                .toList();

        List<SlackSummary> slack = caps.isEmpty() ? List.of()
                : zeekadReadMapper.findSlackSummariesForCaptures(caps, after, until).stream()
                .map(s -> maskingService.maskSlackSummary(s, role))
                .toList();

        List<OperationsApiResponse.LatestJobs> latestJobs = new ArrayList<>();
        if (!caps.isEmpty()) {
            List<CaptureJobStat> stats = zeekadReadMapper.findCaptureJobStats(caps, null, null);
            Map<Long, ScoringJob> byId = jobsById(stats);
            stats.stream()
                    .sorted(Comparator.comparing(CaptureJobStat::getCaptureId))
                    .forEach(s -> latestJobs.add(new OperationsApiResponse.LatestJobs(s.getCaptureId(),
                            jobRef(byId.get(s.getLatestEndedJobId()), role),
                            jobRef(byId.get(s.getLatestSucceededJobId()), role))));
        }

        return new OperationsApiResponse(maskingService.shouldMask(role), cond.allowed(), cleanCaptureId, jobs, bundles,
                feedback, slack, periodGiven ? cond.period() : null,
                source == null || source.isBlank() ? null : source.trim().toLowerCase(Locale.ROOT),
                cond.anchor(), truncated, jobsTotal, latestJobs,
                cond.allowed().stream()
                        .map(c -> new UnifiedQueueResponse.Source(c, timeContextService.sourceType(c), null))
                        .toList());
    }

    /* ───────────────────────── 센서·캡처 상태 ───────────────────────── */

    record CaptureInfo(String state, JobRef latestEnded, OffsetDateTime lastScoredAt, OffsetDateTime lastActivityAt,
                       long failedInPeriod) {
    }

    record SensorInfo(String health, JobRef latestEnded, String activeCaptureId, OffsetDateTime lastScoredAt,
                      OffsetDateTime lastActivityAt, int captureCount) {
    }

    record SourceStatus(Map<String, CaptureInfo> captures, Map<String, SensorInfo> sensors) {
    }

    /**
     * 허용 캡처 전체로 센서 묶음 상태와 캡처 상태를 계산한다(조건으로 고른 캡처만 보이더라도 센서 상태는 묶음 전체 기준).
     * 실패 작업 수는 (after, until] 안(finished_at, 없으면 started_at)이고 after·until이 null이면 전체다.
     */
    SourceStatus sourceStatus(List<String> allowed, OffsetDateTime anchor, OffsetDateTime after, OffsetDateTime until,
                              UserRole role) {
        if (allowed.isEmpty()) {
            return new SourceStatus(Map.of(), Map.of());
        }
        List<CaptureJobStat> stats = zeekadReadMapper.findCaptureJobStats(allowed, after, until);
        Map<String, CaptureJobStat> statBy = new HashMap<>();
        for (CaptureJobStat s : stats) statBy.put(s.getCaptureId(), s);
        Map<String, CaptureQueueStat> queueBy = new HashMap<>();
        for (CaptureQueueStat q : zeekadReadMapper.findCaptureQueueStats(allowed)) queueBy.put(q.getCaptureId(), q);
        Map<Long, ScoringJob> jobs = jobsById(stats);

        // 센서 묶음: 최근 끝난 작업, 최근 성공 작업(job_id 최대)
        Map<String, SensorInfo> sensors = new LinkedHashMap<>();
        Map<String, Long> sensorLatestSucceeded = new HashMap<>();
        for (String pattern : timeContextService.sensorPatterns()) {
            List<String> members = allowed.stream().filter(c -> pattern.equals(timeContextService.sensorKey(c))).toList();
            if (members.isEmpty()) {
                continue;
            }
            Long endedId = null;
            Long succeededId = null;
            for (String m : members) {
                CaptureJobStat s = statBy.get(m);
                if (s == null) continue;
                endedId = maxId(endedId, s.getLatestEndedJobId());
                succeededId = maxId(succeededId, s.getLatestSucceededJobId());
            }
            sensorLatestSucceeded.put(pattern, succeededId);
            ScoringJob ended = endedId == null ? null : jobs.get(endedId);
            ScoringJob succeeded = succeededId == null ? null : jobs.get(succeededId);
            String activeCapture = succeeded == null ? null : succeeded.getCaptureId();
            OffsetDateTime lastScored = succeeded == null ? null : succeeded.getFinishedAt();
            CaptureQueueStat activeQueue = activeCapture == null ? null : queueBy.get(activeCapture);
            sensors.put(pattern, new SensorInfo(
                    sensorHealth(ended, succeeded, anchor, timeContextService.staleAfter(), timeContextService.downAfter()),
                    jobRef(ended, role), activeCapture, lastScored,
                    activeQueue == null ? null : activeQueue.getMaxEventEnd(), members.size()));
        }

        Map<String, CaptureInfo> captures = new HashMap<>();
        for (String cap : allowed) {
            CaptureJobStat s = statBy.get(cap);
            ScoringJob ended = s == null || s.getLatestEndedJobId() == null ? null : jobs.get(s.getLatestEndedJobId());
            ScoringJob succeeded = s == null || s.getLatestSucceededJobId() == null ? null : jobs.get(s.getLatestSucceededJobId());
            String sensor = timeContextService.sensorKey(cap);
            Long bundleLatest = sensor == null ? null : sensorLatestSucceeded.get(sensor);
            String state = captureState(ended, succeeded, sensor != null, bundleLatest);
            CaptureQueueStat q = queueBy.get(cap);
            captures.put(cap, new CaptureInfo(state, jobRef(ended, role),
                    succeeded == null ? null : succeeded.getFinishedAt(),
                    succeeded == null || q == null ? null : q.getMaxEventEnd(),
                    s == null ? 0 : s.getFailedInPeriod()));
        }
        return new SourceStatus(captures, sensors);
    }

    /**
     * 센서 상태: 묶음 안 가장 최근의 끝난 작업이 실패면 failed → 성공 작업이 없으면 none →
     * 기준 시각 − 마지막 성공 작업 finished_at이 staleAfter 이하면 ok, downAfter 이하면 stale, 넘으면 down.
     * 마지막 성공 작업의 finished_at이 없으면(자료 이상) 신선도를 알 수 없어 down이다.
     */
    static String sensorHealth(ScoringJob latestEnded, ScoringJob latestSucceeded, OffsetDateTime anchor,
                               Duration staleAfter, Duration downAfter) {
        if (latestEnded != null && isFailed(latestEnded)) {
            return HEALTH_FAILED;
        }
        if (latestSucceeded == null) {
            return HEALTH_NONE;
        }
        if (latestSucceeded.getFinishedAt() == null || anchor == null) {
            return HEALTH_DOWN;
        }
        Duration elapsed = Duration.between(latestSucceeded.getFinishedAt().toInstant(), anchor.toInstant());
        if (elapsed.compareTo(staleAfter) <= 0) {
            return HEALTH_OK;
        }
        if (elapsed.compareTo(downAfter) <= 0) {
            return HEALTH_STALE;
        }
        return HEALTH_DOWN;
    }

    /** 캡처 상태: 최근 끝난 작업 실패 → failed / 성공 작업 없음 → none / 센서 캡처면 묶음 최근 성공 작업이 여기 있으면 active, 아니면 ended / 가져온 데이터면 imported */
    static String captureState(ScoringJob latestEnded, ScoringJob latestSucceeded, boolean sensorCapture, Long bundleLatestSucceededId) {
        if (latestEnded != null && isFailed(latestEnded)) {
            return STATE_FAILED;
        }
        if (latestSucceeded == null) {
            return STATE_NONE;
        }
        if (!sensorCapture) {
            return STATE_IMPORTED;
        }
        return latestSucceeded.getJobId().equals(bundleLatestSucceededId) ? STATE_ACTIVE : STATE_ENDED;
    }

    private static boolean isFailed(ScoringJob job) {
        return job.getStatus() != null && "failed".equalsIgnoreCase(job.getStatus().trim());
    }

    private static Long maxId(Long a, Long b) {
        if (a == null) return b;
        if (b == null) return a;
        return Math.max(a, b);
    }

    private Map<Long, ScoringJob> jobsById(List<CaptureJobStat> stats) {
        List<Long> ids = new ArrayList<>();
        for (CaptureJobStat s : stats) {
            if (s.getLatestEndedJobId() != null) ids.add(s.getLatestEndedJobId());
            if (s.getLatestSucceededJobId() != null && !s.getLatestSucceededJobId().equals(s.getLatestEndedJobId())) {
                ids.add(s.getLatestSucceededJobId());
            }
        }
        Map<Long, ScoringJob> out = new HashMap<>();
        if (!ids.isEmpty()) {
            for (ScoringJob j : zeekadReadMapper.findScoringJobsByIds(ids)) out.put(j.getJobId(), j);
        }
        return out;
    }

    private JobRef jobRef(ScoringJob job, UserRole role) {
        if (job == null) {
            return null;
        }
        ScoringJob m = maskingService.maskScoringJob(job, role);
        return new JobRef(m.getJobId(), m.getCaptureId(), m.getBundleId(), m.getStatus(), m.getStartedAt(),
                m.getFinishedAt(), isFailed(m) ? m.getError() : null);
    }

    /* ───────────────────────── 경보 발송 상태 ───────────────────────── */

    private Alerting alerting(List<String> captureIds, OffsetDateTime after, OffsetDateTime until) {
        if (captureIds.isEmpty()) {
            return new Alerting(null, null, false, null, null, null, 0);
        }
        List<SlackSummary> all = zeekadReadMapper.findSlackSummariesForCaptures(captureIds, null, null);
        long inPeriod = all.stream().filter(s -> inRange(s.getCreatedAt(), after, until)).count();
        SlackSummary latest = all.isEmpty() ? null : all.get(0);
        if (latest == null) {
            return new Alerting(null, null, false, null, null, null, inPeriod);
        }
        return new Alerting(latest.getZeekadDeliveryMode(), latest.getZeekadDeliveryStatus(), latest.isDryRunOrRecorded(),
                latest.getCreatedAt(), latest.getDeliveredAt(), latest.getCaptureId(), inPeriod);
    }

    private static boolean inRange(OffsetDateTime t, OffsetDateTime after, OffsetDateTime until) {
        if (after == null && until == null) return true;
        if (t == null) return false;
        if (after != null && !t.isAfter(after)) return false;
        return until == null || !t.isAfter(until);
    }

    /* ───────────────────────── 탐지 추이 구간 ───────────────────────── */

    /** 구간 폭 이름과 표시 시간대 시계에 맞춘 경계 계산 */
    enum BucketUnit {
        MIN5("5m"), HOUR1("1h"), HOUR6("6h"), DAY1("1d"), WEEK1("1w");

        final String name;

        BucketUnit(String name) {
            this.name = name;
        }

        /** t 이하인 가장 큰 경계 */
        ZonedDateTime floor(Instant t) {
            ZonedDateTime z = t.atZone(DISPLAY_ZONE);
            return switch (this) {
                case MIN5 -> {
                    ZonedDateTime m = z.truncatedTo(ChronoUnit.MINUTES);
                    yield m.withMinute(m.getMinute() - m.getMinute() % 5);
                }
                case HOUR1 -> z.truncatedTo(ChronoUnit.HOURS);
                case HOUR6 -> {
                    ZonedDateTime h = z.truncatedTo(ChronoUnit.HOURS);
                    yield h.withHour(h.getHour() - h.getHour() % 6);
                }
                case DAY1 -> z.truncatedTo(ChronoUnit.DAYS);
                case WEEK1 -> z.truncatedTo(ChronoUnit.DAYS).with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
            };
        }

        ZonedDateTime next(ZonedDateTime b) {
            return switch (this) {
                case MIN5 -> b.plusMinutes(5);
                case HOUR1 -> b.plusHours(1);
                case HOUR6 -> b.plusHours(6);
                case DAY1 -> b.plusDays(1);
                case WEEK1 -> b.plusWeeks(1);
            };
        }

        ZonedDateTime prev(ZonedDateTime b) {
            return switch (this) {
                case MIN5 -> b.minusMinutes(5);
                case HOUR1 -> b.minusHours(1);
                case HOUR6 -> b.minusHours(6);
                case DAY1 -> b.minusDays(1);
                case WEEK1 -> b.minusWeeks(1);
            };
        }

        /** t를 담는 구간 (start, end]의 end: t 이상인 가장 작은 경계 */
        ZonedDateTime endFor(Instant t) {
            ZonedDateTime f = floor(t);
            return f.toInstant().equals(t) ? f : next(f);
        }
    }

    static BucketUnit unitFor(String period) {
        return switch (period) {
            case "1h" -> BucketUnit.MIN5;
            case "24h" -> BucketUnit.HOUR1;
            case "7d" -> BucketUnit.HOUR6;
            default -> BucketUnit.DAY1;
        };
    }

    /**
     * 탐지 추이. 기간 안 행만 센다(기간 경계는 큐와 같다). 구간은 (start, end]이고 첫·마지막 구간은 일부만 기간 안일 수 있다(partial).
     * all: 탐지 시각 없음·기준 시각 뒤 행은 unbucketed로 따로 센다. 첫 탐지 날부터 기준 시각 날까지 일 단위가 92개를 넘으면 주 단위다.
     */
    static Trend buildTrend(String period, OffsetDateTime anchor, List<IncidentPoint> points) {
        long noDetected = 0;
        long afterAnchor = 0;
        Instant anchorI = anchor.toInstant();
        List<IncidentPoint> in = new ArrayList<>();
        for (IncidentPoint p : points) {
            if (p.getDetectedAt() == null) {
                noDetected++;
            } else if (p.getDetectedAt().toInstant().isAfter(anchorI)) {
                afterAnchor++;
            } else {
                in.add(p);
            }
        }
        Unbucketed unbucketed = new Unbucketed(noDetected, afterAnchor);

        BucketUnit unit;
        ZonedDateTime firstEnd;
        Instant periodStart;
        if ("all".equals(period)) {
            if (in.isEmpty()) {
                return new Trend(BucketUnit.DAY1.name, List.of(), unbucketed);
            }
            Instant min = in.stream().map(p -> p.getDetectedAt().toInstant()).min(Instant::compareTo).orElseThrow();
            unit = BucketUnit.DAY1;
            long days = countBuckets(unit, unit.endFor(min), unit.endFor(anchorI));
            if (days > ALL_DAILY_MAX) {
                unit = BucketUnit.WEEK1;
            }
            firstEnd = unit.endFor(min);
            periodStart = null;
        } else {
            unit = unitFor(period);
            periodStart = anchorI.minus(IncidentQueueService.periodLength(period));
            firstEnd = unit.next(unit.floor(periodStart)); // periodStart보다 큰 가장 작은 경계
        }
        ZonedDateTime lastEnd = unit.endFor(anchorI);

        List<ZonedDateTime> ends = new ArrayList<>();
        for (ZonedDateTime e = firstEnd; !e.isAfter(lastEnd); e = unit.next(e)) {
            ends.add(e);
        }
        Map<Instant, Integer> index = new HashMap<>();
        for (int i = 0; i < ends.size(); i++) index.put(ends.get(i).toInstant(), i);
        long[][] counts = new long[ends.size()][4];
        for (IncidentPoint p : in) {
            Integer i = index.get(unit.endFor(p.getDetectedAt().toInstant()).toInstant());
            if (i == null) {
                continue; // 일어나지 않는다(구간이 기간 전체를 덮는다)
            }
            int k = switch (p.getPriority() == null ? "" : p.getPriority()) {
                case "high" -> 0;
                case "medium" -> 1;
                case "low" -> 2;
                default -> 3;
            };
            counts[i][k]++;
        }
        List<Bucket> buckets = new ArrayList<>(ends.size());
        for (int i = 0; i < ends.size(); i++) {
            ZonedDateTime end = ends.get(i);
            ZonedDateTime start = unit.prev(end);
            boolean partial = end.toInstant().isAfter(anchorI)
                    || (periodStart != null && start.toInstant().isBefore(periodStart));
            long[] c = counts[i];
            buckets.add(new Bucket(utc(start), utc(end), partial, c[0], c[1], c[2], c[3], c[0] + c[1] + c[2] + c[3]));
        }
        return new Trend(unit.name, buckets, unbucketed);
    }

    private static long countBuckets(BucketUnit unit, ZonedDateTime firstEnd, ZonedDateTime lastEnd) {
        long n = 0;
        for (ZonedDateTime e = firstEnd; !e.isAfter(lastEnd); e = unit.next(e)) {
            n++;
            if (n > ALL_DAILY_MAX + 1) break;
        }
        return n;
    }

    private static OffsetDateTime utc(ZonedDateTime z) {
        return z.toOffsetDateTime().withOffsetSameInstant(ZoneOffset.UTC);
    }

    private static UserRole roleOf(DashboardUserPrincipal principal) {
        return principal != null ? principal.getRole() : UserRole.VIEWER;
    }
}
