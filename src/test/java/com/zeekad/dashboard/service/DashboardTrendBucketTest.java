package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.DashboardOverviewResponse.Bucket;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Trend;
import com.zeekad.dashboard.model.zeekad.IncidentPoint;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T24 탐지 추이 구간(KST 시계, (start, end], 일부 구간)과 센서·캡처 상태 규칙(경계값) 단위 시험.
 */
class DashboardTrendBucketTest {

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    private static OffsetDateTime t(String iso) {
        return OffsetDateTime.parse(iso);
    }

    private static IncidentPoint p(String detectedIso, String priority) {
        IncidentPoint p = new IncidentPoint();
        p.setCaptureId("c");
        p.setDetectedAt(detectedIso == null ? null : t(detectedIso));
        p.setPriority(priority);
        return p;
    }

    private static void assertContiguous(List<Bucket> buckets, Duration width) {
        for (int i = 0; i < buckets.size(); i++) {
            Bucket b = buckets.get(i);
            if (width != null) {
                assertThat(Duration.between(b.start(), b.end())).isEqualTo(width);
            }
            if (i > 0) {
                assertThat(b.start()).isEqualTo(buckets.get(i - 1).end());
            }
        }
    }

    @Test
    void oneHourUsesFiveMinuteBucketsAndMarksPartialEnds() {
        Trend tr = DashboardOverviewService.buildTrend("1h", t("2026-11-21T00:02:30Z"), List.of());
        assertThat(tr.bucket()).isEqualTo("5m");
        assertThat(tr.buckets()).hasSize(13);
        assertContiguous(tr.buckets(), Duration.ofMinutes(5));
        assertThat(tr.buckets().get(0).start()).isEqualTo(t("2026-11-20T23:00:00Z"));
        assertThat(tr.buckets().get(0).partial()).isTrue();
        assertThat(tr.buckets().get(12).end()).isEqualTo(t("2026-11-21T00:05:00Z"));
        assertThat(tr.buckets().get(12).partial()).isTrue();
        assertThat(tr.buckets().subList(1, 12)).allSatisfy(b -> assertThat(b.partial()).isFalse());

        // 기준 시각이 경계와 같으면 12개이고 일부 구간이 없다
        Trend aligned = DashboardOverviewService.buildTrend("1h", t("2026-11-21T00:05:00Z"), List.of());
        assertThat(aligned.buckets()).hasSize(12);
        assertThat(aligned.buckets()).allSatisfy(b -> assertThat(b.partial()).isFalse());
    }

    @Test
    void twentyFourHoursUsesHourlyBucketsAtMostTwentyFive() {
        Trend tr = DashboardOverviewService.buildTrend("24h", t("2026-11-21T00:30:00Z"), List.of());
        assertThat(tr.bucket()).isEqualTo("1h");
        assertThat(tr.buckets()).hasSize(25);
        assertContiguous(tr.buckets(), Duration.ofHours(1));
        assertThat(tr.buckets().get(0).partial()).isTrue();
        assertThat(tr.buckets().get(24).partial()).isTrue();
        assertThat(DashboardOverviewService.buildTrend("24h", t("2026-11-21T00:00:00Z"), List.of()).buckets()).hasSize(24);
    }

    @Test
    void sevenDaysUsesSixHourBucketsStartingAtKstZeroSixTwelveEighteen() {
        // 기준 시각 2026-11-21 09:00 KST
        Trend tr = DashboardOverviewService.buildTrend("7d", t("2026-11-21T00:00:00Z"), List.of());
        assertThat(tr.bucket()).isEqualTo("6h");
        assertThat(tr.buckets()).hasSize(29);
        assertContiguous(tr.buckets(), Duration.ofHours(6));
        for (Bucket b : tr.buckets()) {
            ZonedDateTime start = b.start().atZoneSameInstant(KST);
            assertThat(start.getHour() % 6).isZero();
            assertThat(start.getMinute()).isZero();
        }
        // 첫 구간 06:00~12:00 KST(기간 시작 09:00 KST가 안에 있어 일부), 마지막 06:00~12:00 KST(기준 시각 뒤가 있어 일부)
        assertThat(tr.buckets().get(0).start()).isEqualTo(t("2026-11-13T21:00:00Z"));
        assertThat(tr.buckets().get(0).partial()).isTrue();
        assertThat(tr.buckets().get(28).end()).isEqualTo(t("2026-11-21T03:00:00Z"));
        assertThat(tr.buckets().get(28).partial()).isTrue();
    }

    @Test
    void thirtyDaysUsesDailyBucketsAtKstMidnightWhichIsUtcFifteen() {
        Trend tr = DashboardOverviewService.buildTrend("30d", t("2026-11-21T00:00:00Z"), List.of());
        assertThat(tr.bucket()).isEqualTo("1d");
        assertThat(tr.buckets()).hasSize(31);
        assertContiguous(tr.buckets(), Duration.ofDays(1));
        assertThat(tr.buckets()).allSatisfy(b -> {
            assertThat(b.start().withOffsetSameInstant(ZoneOffset.UTC).getHour()).isEqualTo(15);
            assertThat(b.start().atZoneSameInstant(KST).getHour()).isZero();
        });
        // 기준 시각이 KST 0시 정각이면 30개이고 일부 구간이 없다
        Trend aligned = DashboardOverviewService.buildTrend("30d", t("2026-11-20T15:00:00Z"), List.of());
        assertThat(aligned.buckets()).hasSize(30);
        assertThat(aligned.buckets()).allSatisfy(b -> assertThat(b.partial()).isFalse());
    }

    @Test
    void bucketsAreStartExclusiveEndInclusiveAndCountByPriority() {
        OffsetDateTime anchor = t("2026-11-21T00:00:00Z");
        List<IncidentPoint> points = List.of(
                p("2026-11-20T23:00:00Z", "high"),     // 정확히 경계: (22:00, 23:00] 구간
                p("2026-11-20T23:00:00.001Z", "low"),  // 다음 구간
                p("2026-11-21T00:00:00Z", "medium"),   // 기준 시각 = 마지막 구간 끝(포함)
                p("2026-11-20T23:30:00Z", null));      // 종결
        Trend tr = DashboardOverviewService.buildTrend("24h", anchor, points);
        Bucket at23 = tr.buckets().stream().filter(b -> b.end().isEqual(t("2026-11-20T23:00:00Z"))).findFirst().orElseThrow();
        assertThat(at23.high()).isEqualTo(1);
        assertThat(at23.total()).isEqualTo(1);
        Bucket last = tr.buckets().get(tr.buckets().size() - 1);
        assertThat(last.end()).isEqualTo(anchor);
        assertThat(last.low()).isEqualTo(1);
        assertThat(last.medium()).isEqualTo(1);
        assertThat(last.none()).isEqualTo(1);
        assertThat(last.total()).isEqualTo(3);
        assertThat(tr.buckets().stream().mapToLong(Bucket::total).sum()).isEqualTo(4);
    }

    @Test
    void allPeriodCountsUnbucketedRowsSeparatelyAndStartsAtFirstDetectionDay() {
        OffsetDateTime anchor = t("2026-11-21T00:00:00Z");
        List<IncidentPoint> points = List.of(
                p("2026-11-12T03:00:00Z", "low"),
                p("2026-11-19T04:00:00Z", "high"),
                p(null, "low"),
                p("2026-11-21T02:00:00Z", "low"));
        Trend tr = DashboardOverviewService.buildTrend("all", anchor, points);
        assertThat(tr.bucket()).isEqualTo("1d");
        assertThat(tr.unbucketed().noDetectedAt()).isEqualTo(1);
        assertThat(tr.unbucketed().afterAnchor()).isEqualTo(1);
        // 11-12 12:00 KST 날부터 11-21 09:00 KST 날까지 10일
        assertThat(tr.buckets()).hasSize(10);
        assertThat(tr.buckets().get(0).start().atZoneSameInstant(KST).toLocalDate().toString()).isEqualTo("2026-11-12");
        assertThat(tr.buckets().get(0).partial()).isFalse();
        assertThat(tr.buckets().get(9).partial()).isTrue();
        assertThat(tr.buckets().stream().mapToLong(Bucket::total).sum()).isEqualTo(2);

        assertThat(DashboardOverviewService.buildTrend("all", anchor, List.of()).buckets()).isEmpty();
        assertThat(DashboardOverviewService.buildTrend("all", anchor, List.of(p(null, "low"))).buckets()).isEmpty();
    }

    @Test
    void allPeriodOverNinetyTwoDaysUsesWeeklyBucketsFromKstMonday() {
        OffsetDateTime anchor = t("2026-11-21T00:00:00Z");
        List<IncidentPoint> points = new ArrayList<>();
        points.add(p("2026-08-01T00:00:00Z", "low"));
        points.add(p("2026-11-20T00:00:00Z", "high"));
        Trend tr = DashboardOverviewService.buildTrend("all", anchor, points);
        assertThat(tr.bucket()).isEqualTo("1w");
        assertContiguous(tr.buckets(), Duration.ofDays(7));
        assertThat(tr.buckets()).allSatisfy(b -> {
            ZonedDateTime s = b.start().atZoneSameInstant(KST);
            assertThat(s.getDayOfWeek()).isEqualTo(DayOfWeek.MONDAY);
            assertThat(s.getHour()).isZero();
        });
        assertThat(tr.buckets().stream().mapToLong(Bucket::total).sum()).isEqualTo(2);
        // 92일 이하면 일 단위
        Trend daily = DashboardOverviewService.buildTrend("all", anchor, List.of(p("2026-08-22T00:00:00Z", "low")));
        assertThat(daily.bucket()).isEqualTo("1d");
        assertThat(daily.buckets().size()).isLessThanOrEqualTo(92);
    }

    /* ───── 센서·캡처 상태 규칙 ───── */

    private static ScoringJob job(long id, String status, String finished) {
        ScoringJob j = new ScoringJob();
        j.setJobId(id);
        j.setCaptureId("lab-x");
        j.setStatus(status);
        j.setFinishedAt(finished == null ? null : t(finished));
        return j;
    }

    @Test
    void sensorHealthBoundariesAtExactlyFifteenMinutesAndOneHour() {
        Duration stale = Duration.ofMinutes(15);
        Duration down = Duration.ofHours(1);
        ScoringJob ok = job(1, "succeeded", "2026-11-21T00:00:00Z");
        assertThat(DashboardOverviewService.sensorHealth(ok, ok, t("2026-11-21T00:15:00Z"), stale, down)).isEqualTo("ok");
        assertThat(DashboardOverviewService.sensorHealth(ok, ok, t("2026-11-21T00:15:01Z"), stale, down)).isEqualTo("stale");
        assertThat(DashboardOverviewService.sensorHealth(ok, ok, t("2026-11-21T01:00:00Z"), stale, down)).isEqualTo("stale");
        assertThat(DashboardOverviewService.sensorHealth(ok, ok, t("2026-11-21T01:00:01Z"), stale, down)).isEqualTo("down");
        // 최신 끝난 작업이 실패면 신선해도 실패가 먼저다
        ScoringJob failed = job(2, "failed", "2026-11-21T00:01:00Z");
        assertThat(DashboardOverviewService.sensorHealth(failed, ok, t("2026-11-21T00:02:00Z"), stale, down)).isEqualTo("failed");
        // 성공 작업이 없으면 기록 없음
        assertThat(DashboardOverviewService.sensorHealth(null, null, t("2026-11-21T00:02:00Z"), stale, down)).isEqualTo("none");
        // 기준 시각보다 늦은 완료(now 모드 시계 차)는 정상
        assertThat(DashboardOverviewService.sensorHealth(ok, ok, t("2026-11-20T23:59:00Z"), stale, down)).isEqualTo("ok");
    }

    @Test
    void captureStateRules() {
        ScoringJob ok = job(5, "succeeded", "2026-11-21T00:00:00Z");
        ScoringJob failed = job(6, "failed", "2026-11-21T00:01:00Z");
        assertThat(DashboardOverviewService.captureState(failed, ok, true, 5L)).isEqualTo("failed");
        assertThat(DashboardOverviewService.captureState(failed, ok, false, null)).isEqualTo("failed");
        assertThat(DashboardOverviewService.captureState(null, null, true, 9L)).isEqualTo("none");
        assertThat(DashboardOverviewService.captureState(ok, ok, true, 5L)).isEqualTo("active");
        assertThat(DashboardOverviewService.captureState(ok, ok, true, 9L)).isEqualTo("ended");
        assertThat(DashboardOverviewService.captureState(ok, ok, false, null)).isEqualTo("imported");
    }

    /** 표시 시간대 서버 상수 = 프론트엔드 DISPLAY_TIME_ZONE */
    @Test
    void displayTimeZoneMatchesFrontendConstant() throws Exception {
        Path format = Path.of("frontend", "src", "utils", "format.ts");
        String src = Files.readString(format);
        Matcher m = Pattern.compile("export const DISPLAY_TIME_ZONE = '([^']+)'").matcher(src);
        assertThat(m.find()).as("format.ts DISPLAY_TIME_ZONE").isTrue();
        assertThat(m.group(1)).isEqualTo(DashboardOverviewService.DISPLAY_TIME_ZONE);
        assertThat(DashboardOverviewService.DISPLAY_ZONE).isEqualTo(ZoneId.of("Asia/Seoul"));
        assertThat(Instant.EPOCH).isNotNull();
    }
}
