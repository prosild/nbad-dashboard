package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.DashboardOverviewResponse.Bucket;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.Trend;
import com.zeekad.dashboard.model.zeekad.IncidentPoint;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T34 지정 기간 탐지 추이 구간: 폭(6시간·3일·14일·92일 바로 위아래), 첫·마지막 구간, 끝이 기준 시각 뒤, 시작이 기준 시각 뒤,
 * 프리셋 결과가 기간 경계를 받는 새 함수와 같음, 입력 검사(경계값).
 */
class T34CustomTrendBucketTest {

    private static final OffsetDateTime ANCHOR = OffsetDateTime.parse("2026-11-21T00:00:00Z"); // 09:00 KST

    private static OffsetDateTime t(String iso) {
        return OffsetDateTime.parse(iso);
    }

    private static IncidentPoint p(String iso) {
        IncidentPoint p = new IncidentPoint();
        p.setCaptureId("c");
        p.setDetectedAt(t(iso));
        p.setPriority("low");
        return p;
    }

    private static Trend custom(OffsetDateTime start, OffsetDateTime end, List<IncidentPoint> points) {
        return DashboardOverviewService.buildTrend("custom", ANCHOR, start, end, points);
    }

    @Test
    void bucketWidthFollowsLengthAtEachBoundary() {
        OffsetDateTime end = ANCHOR.minusDays(1);
        Object[][] cases = {
                {Duration.ofHours(6), "5m"},
                {Duration.ofHours(6).plusSeconds(1), "1h"},
                {Duration.ofDays(3), "1h"},
                {Duration.ofDays(3).plusSeconds(1), "6h"},
                {Duration.ofDays(14), "6h"},
                {Duration.ofDays(14).plusSeconds(1), "1d"},
                {Duration.ofDays(92), "1d"},
                {Duration.ofDays(92).plusSeconds(1), "1w"},
                {Duration.ofDays(366), "1w"},
                {Duration.ofMinutes(1), "5m"},
        };
        for (Object[] c : cases) {
            Duration len = (Duration) c[0];
            Trend tr = custom(end.minus(len), end, List.of());
            assertThat(tr.bucket()).as(len.toString()).isEqualTo(c[1]);
            // 구간은 이어져 있고 기간 전체를 덮는다
            List<Bucket> b = tr.buckets();
            assertThat(b).as(len.toString()).isNotEmpty();
            assertThat(b.get(0).start()).isBeforeOrEqualTo(end.minus(len));
            assertThat(b.get(0).end()).isAfter(end.minus(len));
            assertThat(b.get(b.size() - 1).end()).isAfterOrEqualTo(end);
            assertThat(b.get(b.size() - 1).start()).isBefore(end);
            for (int i = 1; i < b.size(); i++) {
                assertThat(b.get(i).start()).isEqualTo(b.get(i - 1).end());
            }
        }
    }

    @Test
    void unalignedRangeMarksFirstAndLastBucketsPartialAndCountsInside() {
        // 11-19 09:07 ~ 11:52 KST(00:07Z ~ 02:52Z), 5분 구간: 09:05~09:10 … 11:50~11:55
        OffsetDateTime s = t("2026-11-19T00:07:00Z");
        OffsetDateTime e = t("2026-11-19T02:52:00Z");
        Trend tr = custom(s, e, List.of(p("2026-11-19T00:08:00Z"), p("2026-11-19T02:52:00Z"), p("2026-11-19T01:00:00Z")));
        List<Bucket> b = tr.buckets();
        assertThat(tr.bucket()).isEqualTo("5m");
        assertThat(b.get(0).start()).isEqualTo(t("2026-11-19T00:05:00Z"));
        assertThat(b.get(0).partial()).isTrue();
        assertThat(b.get(b.size() - 1).end()).isEqualTo(t("2026-11-19T02:55:00Z"));
        assertThat(b.get(b.size() - 1).partial()).isTrue();
        assertThat(b.subList(1, b.size() - 1)).allMatch(x -> !x.partial());
        assertThat(b.stream().mapToLong(Bucket::total).sum()).isEqualTo(3);
        assertThat(b.get(0).total()).isEqualTo(1);
        assertThat(b.get(b.size() - 1).total()).isEqualTo(1);
        assertThat(tr.unbucketed().afterAnchor()).isZero();
    }

    @Test
    void endAfterAnchorStopsAtAnchorBucketAndCountsLaterRowsAsAfterAnchor() {
        // 11-20 15:00Z ~ 11-21 06:30Z(기준 시각 00:00Z 뒤), 15.5시간 → 1시간 구간, 마지막 구간 = 기준 시각을 담는 구간
        OffsetDateTime s = t("2026-11-20T15:00:00Z");
        OffsetDateTime e = t("2026-11-21T06:30:00Z");
        Trend tr = custom(s, e, List.of(p("2026-11-20T23:59:59Z"), p("2026-11-21T00:00:00Z"), p("2026-11-21T03:00:00Z")));
        assertThat(tr.bucket()).isEqualTo("1h");
        List<Bucket> b = tr.buckets();
        assertThat(b).hasSize(9);
        assertThat(b.get(b.size() - 1).end()).isEqualTo(ANCHOR);
        assertThat(b.get(b.size() - 1).partial()).isFalse();
        assertThat(b.stream().mapToLong(Bucket::total).sum()).isEqualTo(2);
        assertThat(tr.unbucketed().afterAnchor()).isEqualTo(1);

        // 기준 시각이 구간 중간이면 그 구간은 partial이다
        OffsetDateTime anchor = t("2026-11-21T00:30:00Z");
        Trend mid = DashboardOverviewService.buildTrend("custom", anchor, s, e, List.of());
        assertThat(mid.buckets().get(mid.buckets().size() - 1).end()).isEqualTo(t("2026-11-21T01:00:00Z"));
        assertThat(mid.buckets().get(mid.buckets().size() - 1).partial()).isTrue();
    }

    @Test
    void startAtOrAfterAnchorHasNoBuckets() {
        Trend at = custom(ANCHOR, ANCHOR.plusHours(3), List.of(p("2026-11-21T01:00:00Z")));
        assertThat(at.buckets()).isEmpty();
        assertThat(at.bucket()).isEqualTo("5m");
        assertThat(at.unbucketed().afterAnchor()).isEqualTo(1);
        Trend after = custom(ANCHOR.plusDays(1), ANCHOR.plusDays(5), List.of());
        assertThat(after.buckets()).isEmpty();
        assertThat(after.bucket()).isEqualTo("6h");
        // 1초 앞이면 구간이 있다
        assertThat(custom(ANCHOR.minusSeconds(1), ANCHOR.plusHours(3), List.of()).buckets()).hasSize(1);
    }

    @Test
    void presetResultsAreUnchangedByTheBoundedFunction() {
        List<IncidentPoint> pts = List.of(p("2026-11-20T23:30:00Z"), p("2026-11-20T03:00:00Z"), p("2026-11-15T00:00:00Z"));
        for (String period : List.of("1h", "24h", "7d", "30d")) {
            Duration len = IncidentQueueService.periodLength(period);
            Trend a = DashboardOverviewService.buildTrend(period, ANCHOR, pts);
            Trend b = DashboardOverviewService.buildTrend(period, ANCHOR, ANCHOR.minus(len), ANCHOR, pts);
            assertThat(b).as(period).isEqualTo(a);
        }
        assertThat(DashboardOverviewService.buildTrend("all", ANCHOR, null, null, pts))
                .isEqualTo(DashboardOverviewService.buildTrend("all", ANCHOR, pts));
        assertThat(IncidentQueueService.periodLength("custom")).isNull();
    }

    @Test
    void customRangeValidationBoundaries() {
        // 정확히 366일, 2000-01-01 00:00 KST 시작은 통과
        assertThat(IncidentQueueService.resolveCustomRange("custom", "2025-11-19T00:00:00Z", "2026-11-20T00:00:00Z")).hasSize(2);
        OffsetDateTime[] r = IncidentQueueService.resolveCustomRange("custom", "2000-01-01T00:00+09:00", "2000-01-02T00:00+09:00");
        assertThat(r[0]).isEqualTo(t("1999-12-31T15:00:00Z"));
        assertThat(r[0].getOffset().getTotalSeconds()).isZero();
        // 1초 넘김은 거부
        assertThatThrownBy(() -> IncidentQueueService.resolveCustomRange("custom", "2025-11-19T00:00:00Z", "2026-11-20T00:00:01Z"))
                .isInstanceOf(QueueQueryException.class).hasMessageContaining("366일");
        assertThatThrownBy(() -> IncidentQueueService.resolveCustomRange("custom", "1999-12-31T14:59:59Z", "2000-01-02T00:00:00Z"))
                .isInstanceOf(QueueQueryException.class).hasMessageContaining("2000-01-01");
        // 프리셋·전체에 start·end가 오면 거부, 없으면 null
        assertThatThrownBy(() -> IncidentQueueService.resolveCustomRange("24h", "2026-11-19T00:00:00Z", null))
                .isInstanceOf(QueueQueryException.class);
        assertThat(IncidentQueueService.resolveCustomRange("24h", null, " ")).isNull();
    }
}
