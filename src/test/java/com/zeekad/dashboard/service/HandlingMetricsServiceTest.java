package com.zeekad.dashboard.service;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.AssignmentDtos;
import com.zeekad.dashboard.dto.OperationsApiResponse.HandlingTimes;
import com.zeekad.dashboard.dto.OperationsApiResponse.ResolutionStat;
import com.zeekad.dashboard.dto.OperationsApiResponse.TimeStat;
import com.zeekad.dashboard.dto.OperationsApiResponse.Workload;
import com.zeekad.dashboard.model.zeekad.HandlingPoint;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T25 처리 시간 지표(세 정의·기간 경계·백분위·제외·가져온 데이터·판정별)와 담당 현황 불변식, 착수 목표 설정 검증.
 * 기준 시각은 고정 값이다.
 */
class HandlingMetricsServiceTest {

    static final OffsetDateTime ANCHOR = OffsetDateTime.parse("2026-11-21T00:00:00Z");
    static final OffsetDateTime AFTER = ANCHOR.minusHours(24);

    private final DashboardProperties props = new DashboardProperties();
    private final TimeContextService tcs = new TimeContextService(props, null,
            Clock.fixed(ANCHOR.toInstant(), ZoneOffset.UTC));
    private final AckTargetService ack = new AckTargetService(props, tcs);
    private final IncidentAssignmentService assignments = Mockito.mock(IncidentAssignmentService.class);
    private final HandlingMetricsService service = new HandlingMetricsService(null, tcs, ack, assignments);

    /* ───────────── 백분위 ───────────── */

    @Test
    void nearestRankPercentiles() {
        assertThat(HandlingMetricsService.nearestRank(List.of(), 1, 2)).isNull();
        assertThat(HandlingMetricsService.nearestRank(List.of(7L), 1, 2)).isEqualTo(7);
        assertThat(HandlingMetricsService.nearestRank(List.of(7L), 9, 10)).isEqualTo(7);
        // n = 2: 중앙값 ceil(1) = 1번째, p90 ceil(1.8) = 2번째
        assertThat(HandlingMetricsService.nearestRank(List.of(1L, 2L), 1, 2)).isEqualTo(1);
        assertThat(HandlingMetricsService.nearestRank(List.of(1L, 2L), 9, 10)).isEqualTo(2);
        List<Long> ten = seq(10);
        assertThat(HandlingMetricsService.nearestRank(ten, 1, 2)).isEqualTo(5);   // ceil(5)
        assertThat(HandlingMetricsService.nearestRank(ten, 9, 10)).isEqualTo(9);  // ceil(9)
        List<Long> eleven = seq(11);
        assertThat(HandlingMetricsService.nearestRank(eleven, 1, 2)).isEqualTo(6);  // ceil(5.5)
        assertThat(HandlingMetricsService.nearestRank(eleven, 9, 10)).isEqualTo(10); // ceil(9.9)
    }

    @Test
    void smallSampleFlagAndEmpty() {
        List<HandlingPoint> pts = new ArrayList<>();
        for (int i = 1; i <= 9; i++) {
            pts.add(point("lab-x", i, "2026-11-20T11:00:00Z", "2026-11-20T12:00:00Z", null, null, "open", null));
        }
        TimeStat nine = service.handlingTimes(pts, AFTER, ANCHOR).detection();
        assertThat(nine.n()).isEqualTo(9);
        assertThat(nine.smallSample()).isTrue();
        pts.add(point("lab-x", 10, "2026-11-20T11:00:00Z", "2026-11-20T12:00:00Z", null, null, "open", null));
        assertThat(service.handlingTimes(pts, AFTER, ANCHOR).detection().smallSample()).isFalse();
        TimeStat none = service.handlingTimes(List.of(), AFTER, ANCHOR).resolve().all();
        assertThat(none.n()).isZero();
        assertThat(none.medianSeconds()).isNull();
        assertThat(none.p90Seconds()).isNull();
        assertThat(none.smallSample()).isFalse();
    }

    /* ───────────── 세 정의 ───────────── */

    @Test
    void definitionsExclusionsImportedAndResolutions() {
        List<HandlingPoint> pts = List.of(
                // m1: MTTD 1시간, MTTA 10분, MTTR 1시간(정탐). 종결 시각은 status_updated_at
                point("lab-m", 1, "2026-11-20T11:00:00Z", "2026-11-20T12:00:00Z", "2026-11-20T12:10:00Z",
                        "2026-11-20T13:00:00Z", "closed", "true_positive"),
                // m2: MTTD 30분, MTTA 30분, 조사 중
                point("lab-m", 2, "2026-11-20T11:30:00Z", "2026-11-20T12:00:00Z", "2026-11-20T12:30:00Z",
                        "2026-11-20T12:30:00Z", "investigating", null),
                // m3: 탐지 지연 음수 → 제외
                point("lab-m", 3, "2026-11-20T12:30:00Z", "2026-11-20T12:00:00Z", null, null, "open", null),
                // m4: 조사 중 기록 없이 종결(판정 없음) → MTTA 제외 수, MTTR 2시간
                point("lab-m", 4, "2026-11-20T11:00:00Z", "2026-11-20T12:00:00Z", null,
                        "2026-11-20T14:00:00Z", "closed", null),
                // m5: 종결 시각이 탐지보다 앞(자료 이상) → MTTR 제외(오탐 하위 행도 제외 1), MTTA 5분
                point("lab-m", 5, "2026-11-20T11:00:00Z", "2026-11-20T12:00:00Z", "2026-11-20T12:05:00Z",
                        "2026-11-20T11:59:00Z", "closed", "false_positive"),
                // 가져온 데이터: 탐지 지연에서 뺀다(event_start가 원본 데이터셋 시각), 착수 20분·처리 40분(정상)
                point("cic-imp", 6, "2017-07-05T10:00:00Z", "2026-11-20T12:00:00Z", "2026-11-20T12:20:00Z",
                        "2026-11-20T12:40:00Z", "closed", "benign"),
                // 탐지 시각 없음: 착수 시간 제외
                point("lab-m", 7, "2026-11-20T11:00:00Z", null, "2026-11-20T12:00:00Z", null, "investigating", null));
        HandlingTimes h = service.handlingTimes(pts, AFTER, ANCHOR);

        assertThat(h.detection().n()).isEqualTo(4); // 3600, 1800, 3600, 3600 (m3 제외, 가져온 데이터·m7 없음)
        assertThat(h.detection().excluded()).isEqualTo(1);
        assertThat(h.detection().medianSeconds()).isEqualTo(3600);
        assertThat(h.detection().p90Seconds()).isEqualTo(3600);

        assertThat(h.acknowledge().n()).isEqualTo(4); // 600, 1800, 300, 1200
        assertThat(h.acknowledge().medianSeconds()).isEqualTo(600);
        assertThat(h.acknowledge().p90Seconds()).isEqualTo(1800);
        assertThat(h.acknowledge().excluded()).isEqualTo(2); // m7 탐지 시각 없음 + m4 조사 중 기록 없이 종결

        assertThat(h.resolve().all().n()).isEqualTo(3); // 3600, 7200, 2400
        assertThat(h.resolve().all().medianSeconds()).isEqualTo(3600);
        assertThat(h.resolve().all().p90Seconds()).isEqualTo(7200);
        assertThat(h.resolve().all().excluded()).isEqualTo(1);
        Map<String, TimeStat> by = new java.util.HashMap<>();
        for (ResolutionStat r : h.resolve().byResolution()) by.put(r.resolution(), r.stat());
        assertThat(h.resolve().byResolution()).extracting(ResolutionStat::resolution)
                .containsExactly("true_positive", "false_positive", "benign", "none");
        assertThat(by.get("true_positive").medianSeconds()).isEqualTo(3600);
        assertThat(by.get("false_positive").n()).isZero();
        assertThat(by.get("false_positive").excluded()).isEqualTo(1);
        assertThat(by.get("benign").medianSeconds()).isEqualTo(2400);
        assertThat(by.get("none").medianSeconds()).isEqualTo(7200);
    }

    @Test
    void periodBoundaryExcludesStartIncludesEnd() {
        List<HandlingPoint> pts = List.of(
                point("lab-b", 1, AFTER.minusMinutes(10).toString(), AFTER.toString(), AFTER.toString(),
                        AFTER.toString(), "closed", "benign"),
                point("lab-b", 2, ANCHOR.minusMinutes(10).toString(), ANCHOR.toString(), ANCHOR.toString(),
                        ANCHOR.toString(), "closed", "benign"),
                point("lab-b", 3, ANCHOR.toString(), ANCHOR.plusSeconds(1).toString(), ANCHOR.plusSeconds(1).toString(),
                        ANCHOR.plusSeconds(1).toString(), "closed", "benign"));
        HandlingTimes h = service.handlingTimes(pts, AFTER, ANCHOR);
        assertThat(h.detection().n()).isEqualTo(1);
        assertThat(h.detection().medianSeconds()).isEqualTo(600);
        assertThat(h.acknowledge().n()).isEqualTo(1);
        assertThat(h.resolve().all().n()).isEqualTo(1);
        // 기간 all: 경계 없음
        HandlingTimes all = service.handlingTimes(pts, null, null);
        assertThat(all.detection().n()).isEqualTo(3);
        assertThat(all.resolve().all().n()).isEqualTo(3);
    }

    /* ───────────── 담당 현황 ───────────── */

    @Test
    void workloadInvariantsAndOverdue() {
        List<HandlingPoint> pts = List.of(
                pointP("lab-w", 1, "2026-11-20T23:00:00Z", "open", "high"),        // 지연
                pointP("lab-w", 2, "2026-11-20T23:00:00Z", "open", "medium"),
                pointP("lab-w", 3, "2026-11-20T23:00:00Z", "investigating", "high"),
                pointP("lab-w", 4, "2026-11-20T23:00:00Z", "closed", null),        // 종결은 세지 않는다
                pointP("imp-w", 5, "2026-11-19T00:00:00Z", "open", "high"));       // 가져온 데이터: 지연 아님
        Mockito.when(assignments.assigneesFor(Mockito.anyCollection())).thenReturn(Map.of(
                "lab-w|1", new AssignmentDtos.Assignee("a1", "분석1", true),
                "lab-w|3", new AssignmentDtos.Assignee("a1", "분석1", true),
                "imp-w|5", new AssignmentDtos.Assignee("a2", "분석2", false)));
        Workload w = service.workload(pts, ANCHOR);
        assertThat(w.unclosed()).isEqualTo(4);
        assertThat(w.assigned()).isEqualTo(3);
        assertThat(w.unassigned()).isEqualTo(1);
        assertThat(w.unclosed()).isEqualTo(w.assigned() + w.unassigned());
        assertThat(w.byAssignee().stream().mapToLong(l -> l.open() + l.investigating()).sum()).isEqualTo(w.assigned());
        assertThat(w.ackOverdue()).isEqualTo(1);
        assertThat(w.byAssignee().get(0).username()).isEqualTo("a1");
        assertThat(w.byAssignee().get(0).open()).isEqualTo(1);
        assertThat(w.byAssignee().get(0).investigating()).isEqualTo(1);
        assertThat(w.byAssignee().get(1).enabled()).isFalse();
    }

    /* ───────────── 설정 ───────────── */

    @Test
    void ackTargetConfigValidation() {
        AckTargetService.validate(Duration.ofMinutes(30), Duration.ofHours(4), Duration.ofHours(24));
        AckTargetService.validate(Duration.ofHours(1), Duration.ofHours(1), Duration.ofHours(1));
        assertThatThrownBy(() -> AckTargetService.validate(Duration.ZERO, Duration.ofHours(4), Duration.ofHours(24)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AckTargetService.validate(Duration.ofMinutes(-1), Duration.ofHours(4), Duration.ofHours(24)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AckTargetService.validate(Duration.ofHours(5), Duration.ofHours(4), Duration.ofHours(24)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AckTargetService.validate(Duration.ofMinutes(30), Duration.ofHours(25), Duration.ofHours(24)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AckTargetService.validate(null, Duration.ofHours(4), Duration.ofHours(24)))
                .isInstanceOf(IllegalStateException.class);

        // 앱 시작: 잘못된 설정이면 빈 생성 실패, 기본값은 30분·4시간·24시간
        ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Cfg.class);
        runner.run(ctx -> {
            AckTargetService s = ctx.getBean(AckTargetService.class);
            assertThat(s.high()).isEqualTo(Duration.ofMinutes(30));
            assertThat(s.medium()).isEqualTo(Duration.ofHours(4));
            assertThat(s.low()).isEqualTo(Duration.ofHours(24));
        });
        runner.withPropertyValues("dashboard.sla.ack.high=5h").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.sla.ack.low=0s").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.sla.ack.medium=nonsense").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.sla.ack.high=10m", "dashboard.sla.ack.medium=1h", "dashboard.sla.ack.low=8h")
                .run(ctx -> assertThat(ctx.getBean(AckTargetService.class).medium()).isEqualTo(Duration.ofHours(1)));
    }

    @Configuration
    @EnableConfigurationProperties(DashboardProperties.class)
    static class Cfg {
        @Bean
        TimeContextService timeContextService(DashboardProperties p) {
            return new TimeContextService(p, null, Clock.fixed(Instant.parse("2026-11-21T00:00:00Z"), ZoneOffset.UTC));
        }

        @Bean
        AckTargetService ackTargetService(DashboardProperties p, TimeContextService t) {
            return new AckTargetService(p, t);
        }
    }

    /* ───────────── 도우미 ───────────── */

    private static List<Long> seq(int n) {
        List<Long> out = new ArrayList<>();
        for (long i = 1; i <= n; i++) out.add(i);
        return out;
    }

    private static HandlingPoint point(String capture, int n, String eventStart, String detected, String ack,
                                       String statusUpdated, String status, String resolution) {
        HandlingPoint p = new HandlingPoint();
        p.setIncidentId(capture + "|" + n);
        p.setCaptureId(capture);
        p.setEventStart(eventStart == null ? null : OffsetDateTime.parse(eventStart));
        p.setDetectedAt(detected == null ? null : OffsetDateTime.parse(detected));
        p.setAckAt(ack == null ? null : OffsetDateTime.parse(ack));
        p.setStatusUpdatedAt(statusUpdated == null ? null : OffsetDateTime.parse(statusUpdated));
        p.setStatusNorm(status);
        p.setZeekadResolution(resolution);
        return p;
    }

    private static HandlingPoint pointP(String capture, int n, String detected, String status, String priority) {
        HandlingPoint p = point(capture, n, null, detected, null, null, status, null);
        p.setPriority(priority);
        return p;
    }
}
