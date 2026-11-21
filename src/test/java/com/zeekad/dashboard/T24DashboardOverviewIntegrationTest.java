package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.DashboardOverviewResponse;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.CaptureRow;
import com.zeekad.dashboard.dto.DashboardOverviewResponse.SensorRow;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.OperationsApiResponse;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.CaptureAccessService;
import com.zeekad.dashboard.service.DashboardOverviewService;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.MaskingService;
import com.zeekad.dashboard.service.TimeContextService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T24 현황판 overview·운영 현황: 불변식(구간 합 + unbucketed = 큐 summary.total = 캡처 행 합, 센서 = 그 캡처 합),
 * 기간 경계, 센서·캡처 상태(지난 날짜·실행 중·숨긴 캡처·고정 스냅샷), 설정 검증, 권한·감사, VIEWER 작업 오류 마스킹,
 * /api/operations period·source(거르기·500건 상한·latestJobs·번들·교집합·period 없음 호환).
 * 시험용 행(job 94000~94999, 95000~95600)은 시험마다 넣고 지운다(공유 H2).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T24DashboardOverviewIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final List<String> PERIODS = List.of("1h", "24h", "7d", "30d", "all");
    private static final Pattern FULL_IPV4 = Pattern.compile("(?<![0-9.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![0-9.])");

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(FIXED_NOW);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private ZeekadReadMapper zeekadReadMapper;
    @Autowired private DashboardOverviewService overviewService;
    @Autowired private CaptureAccessService captureAccessService;
    @Autowired private MaskingService maskingService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        JdbcTemplate jdbc = jdbc();
        String range = "job_id BETWEEN 94000 AND 95999";
        jdbc.update("DELETE FROM dashboard.raw_send_decisions WHERE " + range);
        jdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE " + range);
        jdbc.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        jdbc.update("DELETE FROM dashboard.raw_slack_summaries WHERE " + range);
        jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        jdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    /* ───────────── 불변식 ───────────── */

    @Test
    void invariantsHoldForEveryPeriodAndSourceCondition() throws Exception {
        insertInvariantData();
        MockHttpSession s = login("t24_inv", UserRole.ANALYST, "*");
        List<String> conditions = List.of("", "&source=live", "&source=imported", "&captureId=lab-20261120",
                "&captureId=t24imp-old", "&source=live&captureId=t24imp-old");
        Map<String, Long> totals = new HashMap<>();
        for (String period : PERIODS) {
            for (String cond : conditions) {
                String q = "period=" + period + cond;
                JsonNode ov = getJson(s, "/api/dashboard/overview?" + q);
                JsonNode queue = getJson(s, "/api/incidents/queue?size=25&" + q);
                long queueTotal = queue.get("summary").get("total").asLong();
                long bucketSum = 0;
                for (JsonNode b : ov.get("trend").get("buckets")) {
                    long parts = b.get("high").asLong() + b.get("medium").asLong() + b.get("low").asLong() + b.get("none").asLong();
                    assertThat(b.get("total").asLong()).isEqualTo(parts);
                    bucketSum += parts;
                }
                JsonNode unb = ov.get("trend").get("unbucketed");
                long unbucketed = unb.get("noDetectedAt").asLong() + unb.get("afterAnchor").asLong();
                assertThat(bucketSum + unbucketed).as("구간 합 + unbucketed = 큐 total: %s", q).isEqualTo(queueTotal);
                long captureSum = 0;
                long captureHigh = 0;
                long captureAlerted = 0;
                Map<String, Long> bySensor = new HashMap<>();
                for (JsonNode c : ov.get("captures")) {
                    captureSum += c.get("total").asLong();
                    captureHigh += c.get("high").asLong();
                    captureAlerted += c.get("alerted").asLong();
                    if (!c.get("sensorKey").isNull()) bySensor.merge(c.get("sensorKey").asText(), c.get("total").asLong(), Long::sum);
                }
                assertThat(captureSum).as("캡처 행 합 = 큐 total: %s", q).isEqualTo(queueTotal);
                assertThat(captureHigh).as("캡처 행 high 합 = 큐 high: %s", q).isEqualTo(queue.get("summary").get("high").asLong());
                assertThat(captureAlerted).as("캡처 행 경보 합 = 큐 경보: %s", q).isEqualTo(queue.get("summary").get("alerted").asLong());
                for (JsonNode sensor : ov.get("sensors")) {
                    assertThat(sensor.get("total").asLong()).as("센서 = 캡처 합: %s", q)
                            .isEqualTo(bySensor.getOrDefault(sensor.get("sensorKey").asText(), 0L));
                }
                // 조건에 맞는 수집원만 나온다
                for (JsonNode c : ov.get("captures")) {
                    if (cond.contains("source=live")) assertThat(c.get("sourceType").asText()).isEqualTo("live");
                    if (cond.contains("source=imported")) assertThat(c.get("sourceType").asText()).isEqualTo("imported");
                    if (cond.contains("captureId=")) assertThat(cond).contains("captureId=" + c.get("captureId").asText());
                }
                if (cond.contains("source=imported") || cond.contains("captureId=t24imp")) {
                    assertThat(ov.get("sensors")).isEmpty();
                }
                assertThat(ov.get("period").asText()).isEqualTo(period);
                assertThat(ov.get("timeZone").asText()).isEqualTo("Asia/Seoul");
                totals.put(q, queueTotal);
            }
        }
        // 자료가 실제로 기간마다 다르게 나뉜다(시험 자료가 빈 집합만 비교하지 않는다)
        assertThat(totals.get("period=1h")).isEqualTo(3);   // lab-20261120 B·C(−10분), lab-20261121 E(−40분)
        assertThat(totals.get("period=24h")).isEqualTo(4);  // + A(첫 탐지 −3시간)
        assertThat(totals.get("period=all")).isGreaterThan(totals.get("period=30d"));
        // all의 unbucketed: 탐지 시각 없음 1(t24imp-nofin), 기준 시각 뒤 1(t24imp-future)
        JsonNode all = getJson(s, "/api/dashboard/overview?period=all&source=imported");
        assertThat(all.get("trend").get("unbucketed").get("noDetectedAt").asLong()).isEqualTo(1);
        assertThat(all.get("trend").get("unbucketed").get("afterAnchor").asLong()).isEqualTo(1);
        // 기간 안 실패 작업 수(finished_at 없으면 started_at 기준)
        JsonNode day = getJson(s, "/api/dashboard/overview?period=24h&captureId=t24imp-old");
        assertThat(day.get("captures").get(0).get("failedJobs").asLong()).isEqualTo(1);
        JsonNode week = getJson(s, "/api/dashboard/overview?period=all&captureId=t24imp-old");
        assertThat(week.get("captures").get(0).get("failedJobs").asLong()).isEqualTo(2);
        assertThat(week.get("captures").get(0).get("state").asText()).isEqualTo("imported");
    }

    @Test
    void periodBoundaryMatchesQueueStartExclusiveEndInclusive() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, List.of("lab-fusion-v2"));
        // 10.40.0.20·.30 탐지 = 2026-11-19 02:05. 기준 시각이 정확히 24시간 뒤면 빠진다(시작 불포함)
        clock.set(Instant.parse("2026-11-20T02:05:00Z"));
        assertThat(trendSum(overviewService.overview(analyst, "24h", null, null, "127.0.0.1"))).isZero();
        clock.set(Instant.parse("2026-11-20T02:04:59Z"));
        assertThat(trendSum(overviewService.overview(analyst, "24h", null, null, "127.0.0.1"))).isEqualTo(2);
        // 기준 시각 = 탐지 시각이면 들어오고 마지막 구간(끝 = 기준 시각, 5분 경계)에 든다
        clock.set(Instant.parse("2026-11-19T02:05:00Z"));
        DashboardOverviewResponse at = overviewService.overview(analyst, "1h", null, null, "127.0.0.1");
        assertThat(at.trend().buckets()).hasSize(12);
        DashboardOverviewResponse.Bucket last = at.trend().buckets().get(11);
        assertThat(last.end().toInstant()).isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        assertThat(last.total()).isEqualTo(2);
        assertThat(last.partial()).isFalse();
    }

    /* ───────────── 센서·캡처 상태 ───────────── */

    @Test
    void sensorHealthUsesWholeBundleAndEndedDayCapturesDoNotMakeItDown() {
        // lab-* 묶음: 시드 lab-20261118(11-18)·lab-fusion-v2(11-19) + 새 lab-20261120(오늘)
        job(94101, "lab-20261120", "succeeded", "2026-11-20T23:50:00Z", "2026-11-20T23:55:00Z", null);
        incident(94101, "lab-20261120", 1, "10.60.0.1", "2026-11-20T23:50:00Z", "low");
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, List.of("lab-*"));

        clock.set(Instant.parse("2026-11-21T00:10:00Z")); // 정확히 15분
        DashboardOverviewResponse ok = overviewService.overview(analyst, "24h", null, null, "127.0.0.1");
        SensorRow sensor = ok.sensors().get(0);
        assertThat(sensor.sensorKey()).isEqualTo("lab-*");
        assertThat(sensor.label()).isEqualTo("실습망 센서");
        assertThat(sensor.health()).isEqualTo("ok");
        assertThat(sensor.activeCaptureId()).isEqualTo("lab-20261120");
        assertThat(sensor.captureCount()).isEqualTo(3);
        assertThat(sensor.lastScoredAt().toInstant()).isEqualTo(Instant.parse("2026-11-20T23:55:00Z"));
        assertThat(sensor.lastActivityAt().toInstant()).isEqualTo(Instant.parse("2026-11-20T23:50:00Z"));
        Map<String, CaptureRow> caps = byCapture(ok);
        assertThat(caps.get("lab-20261120").state()).isEqualTo("active");
        assertThat(caps.get("lab-20261118").state()).isEqualTo("ended");
        assertThat(caps.get("lab-fusion-v2").state()).isEqualTo("ended");
        assertThat(caps.get("lab-20261118").lastScoredAt().toInstant()).isEqualTo(Instant.parse("2026-11-18T00:11:00Z"));

        clock.set(Instant.parse("2026-11-21T00:10:01Z"));
        assertThat(overviewService.overview(analyst, "24h", null, null, "127.0.0.1").sensors().get(0).health()).isEqualTo("stale");
        clock.set(Instant.parse("2026-11-21T00:55:00Z")); // 정확히 1시간
        assertThat(overviewService.overview(analyst, "24h", null, null, "127.0.0.1").sensors().get(0).health()).isEqualTo("stale");
        clock.set(Instant.parse("2026-11-21T00:55:01Z"));
        assertThat(overviewService.overview(analyst, "24h", null, null, "127.0.0.1").sensors().get(0).health()).isEqualTo("down");

        // 실행 중 작업은 건너뛴다(끝난 작업이 아님)
        clock.set(Instant.parse("2026-11-21T00:05:00Z"));
        job(94102, "lab-20261120", "running", "2026-11-21T00:00:00Z", null, null);
        DashboardOverviewResponse running = overviewService.overview(analyst, "24h", null, null, "127.0.0.1");
        assertThat(running.sensors().get(0).health()).isEqualTo("ok");
        assertThat(running.sensors().get(0).latestJob().jobId()).isEqualTo(94101L);

        // 최신 끝난 작업이 실패면 신선해도 실패가 먼저다. 캡처도 실패
        job(94103, "lab-20261120", "failed", "2026-11-21T00:00:00Z", "2026-11-21T00:01:00Z", "disk full");
        DashboardOverviewResponse failed = overviewService.overview(analyst, "24h", null, null, "127.0.0.1");
        assertThat(failed.sensors().get(0).health()).isEqualTo("failed");
        assertThat(failed.sensors().get(0).latestJob().error()).isEqualTo("disk full");
        assertThat(failed.sensors().get(0).failedJobs()).isEqualTo(1);
        assertThat(byCapture(failed).get("lab-20261120").state()).isEqualTo("failed");
        // 캡처 하나만 골라도 센서 상태는 묶음 전체 기준이고 수는 고른 캡처만
        DashboardOverviewResponse one = overviewService.overview(analyst, "24h", null, "lab-20261118", "127.0.0.1");
        assertThat(one.captures()).extracting(CaptureRow::captureId).containsExactly("lab-20261118");
        assertThat(one.sensors().get(0).health()).isEqualTo("failed");
        assertThat(one.sensors().get(0).failedJobs()).isZero();
        assertThat(one.sensors().get(0).captureCount()).isEqualTo(3);
    }

    @Test
    void hiddenNewerCaptureDoesNotAffectSensorHealthOrAppearAnywhere() throws Exception {
        // 허용: lab-20261118·lab-fusion-v2. 숨김 lab-20261120에 더 최근 실패 작업
        job(94201, "lab-20261120", "failed", "2026-11-19T02:06:00Z", "2026-11-19T02:09:00Z", "hidden failure 10.9.9.9");
        incident(94201, "lab-20261120", 1, "10.60.0.9", "2026-11-19T02:00:00Z", "low");
        clock.set(Instant.parse("2026-11-19T02:10:00Z"));
        DashboardOverviewResponse ov = overviewService.overview(
                principal(UserRole.ANALYST, List.of("lab-20261118", "lab-fusion-v2")), "all", null, null, "127.0.0.1");
        assertThat(ov.sensors().get(0).health()).isEqualTo("ok");
        assertThat(ov.sensors().get(0).captureCount()).isEqualTo(2);
        assertThat(ov.sensors().get(0).latestJob().jobId()).isEqualTo(602L);
        assertThat(objectMapper.writeValueAsString(ov)).doesNotContain("lab-20261120", "hidden failure", "94201");
    }

    @Test
    void noneHealthAndSnapshotAnchorUseAllowedCapturesOnly() {
        // 실행 중 작업만 있는 센서 캡처: 상태 기록 없음
        job(94301, "lab-20261130", "running", "2026-11-20T00:00:00Z", null, null);
        DashboardOverviewResponse none = overviewService.overview(
                principal(UserRole.ANALYST, List.of("lab-20261130")), "24h", null, null, "127.0.0.1");
        assertThat(none.sensors().get(0).health()).isEqualTo("none");
        assertThat(none.captures().get(0).state()).isEqualTo("none");
        assertThat(none.captures().get(0).lastScoredAt()).isNull();

        // 고정 스냅샷: 기준 시각 = 허용 캡처 최신 성공 완료(11-19 02:05). 시계가 며칠 뒤여도 정상
        clock.set(Instant.parse("2026-11-25T00:00:00Z"));
        DashboardOverviewService snapshot = snapshotService();
        DashboardOverviewResponse ov = snapshot.overview(
                principal(UserRole.ANALYST, List.of("lab-20261118", "lab-fusion-v2")), "24h", null, null, "127.0.0.1");
        assertThat(ov.snapshot()).isTrue();
        assertThat(ov.anchorMode()).isEqualTo("latest-data");
        assertThat(ov.anchor().toInstant()).isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        assertThat(ov.sensors().get(0).health()).isEqualTo("ok");
        assertThat(byCapture(ov).get("lab-fusion-v2").state()).isEqualTo("active");
        // 같은 때 now 모드면 중단
        assertThat(overviewService.overview(principal(UserRole.ANALYST, List.of("lab-20261118", "lab-fusion-v2")),
                "24h", null, null, "127.0.0.1").sensors().get(0).health()).isEqualTo("down");
    }

    @Test
    void importedCaptureFailureIsReported() {
        job(94401, "syn1-tue", "failed", "2026-11-20T00:00:00Z", "2026-11-20T00:01:00Z", "re-scoring aborted");
        DashboardOverviewResponse ov = overviewService.overview(
                principal(UserRole.ANALYST, List.of("syn1-*", "cic17-*")), "all", null, null, "127.0.0.1");
        Map<String, CaptureRow> caps = byCapture(ov);
        assertThat(caps.get("syn1-tue").state()).isEqualTo("failed");
        assertThat(caps.get("syn1-tue").latestJob().error()).isEqualTo("re-scoring aborted");
        assertThat(caps.get("syn1-tue").sensorKey()).isNull();
        // 실패해도 마지막 성공 채점 결과는 그대로 센다
        assertThat(caps.get("syn1-tue").total()).isEqualTo(1);
        assertThat(caps.get("syn1-wed").state()).isEqualTo("imported");
        // 최근 끝난 작업이 성공이면 이전 실패(cic17-wed 100)는 상태를 바꾸지 않는다
        assertThat(caps.get("cic17-wed").state()).isEqualTo("imported");
        assertThat(caps.get("cic17-wed").failedJobs()).isEqualTo(1);
        assertThat(ov.sensors()).isEmpty();
    }

    /* ───────────── 설정 ───────────── */

    @Test
    void invalidHealthThresholdSettingsFailStartup() {
        ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(TimeContextOnlyConfig.class);
        runner.withPropertyValues("dashboard.capture-sources.stale-after=bogus").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.stale-after=1h", "dashboard.capture-sources.down-after=1h")
                .run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.stale-after=2h", "dashboard.capture-sources.down-after=1h")
                .run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.stale-after=0s").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.down-after=-5m").run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.stale-after=PT10M", "dashboard.capture-sources.down-after=30m")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx.getBean(TimeContextService.class).staleAfter().toMinutes()).isEqualTo(10);
                    assertThat(ctx.getBean(TimeContextService.class).downAfter().toMinutes()).isEqualTo(30);
                });
        runner.run(ctx -> {
            assertThat(ctx.getBean(TimeContextService.class).staleAfter().toMinutes()).isEqualTo(15);
            assertThat(ctx.getBean(TimeContextService.class).downAfter().toHours()).isEqualTo(1);
        });
    }

    @EnableConfigurationProperties(DashboardProperties.class)
    static class TimeContextOnlyConfig {
        @Bean
        ZeekadReadMapper zeekadReadMapper() {
            return Mockito.mock(ZeekadReadMapper.class);
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        TimeContextService timeContextService(DashboardProperties p, ZeekadReadMapper m, Clock c) {
            return new TimeContextService(p, m, c);
        }
    }

    /* ───────────── 권한·마스킹 ───────────── */

    @Test
    void deniedCaptureIs403WithAuditAndHiddenCapturesLeaveNoTrace() throws Exception {
        MockHttpSession viewer = login("t24_viewer_scope", UserRole.VIEWER, "cic17-*");
        mockMvc.perform(get("/api/dashboard/overview").param("captureId", "syn1-tue").session(viewer))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/operations").param("period", "7d").param("captureId", "lab-20261118").session(viewer))
                .andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), "t24_viewer_scope", 20)).hasSize(2);
        mockMvc.perform(get("/api/dashboard/overview").param("period", "2d").session(viewer)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/dashboard/overview").param("source", "cloud").session(viewer)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/operations").param("period", "2d").session(viewer)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/dashboard/overview")).andExpect(status().isUnauthorized());

        for (String period : PERIODS) {
            JsonNode ov = getJson(viewer, "/api/dashboard/overview?period=" + period);
            assertThat(ov.toString()).doesNotContain("syn1-", "lab-");
            assertThat(ov.get("sensors")).isEmpty();
            assertThat(ov.get("captures")).hasSize(1);
            JsonNode ops = getJson(viewer, "/api/operations?period=" + period);
            assertThat(ops.toString()).doesNotContain("syn1-", "lab-", "zeekad-fusion/2", "zeekad-fusion/3");
            assertNoFullIpv4(ov);
            assertNoFullIpv4(ops);
        }
        // 기준 시각(now 모드는 현재 시각)과 기간 '전체'의 구간도 허용 캡처 안에서만 정한다
        JsonNode all = getJson(viewer, "/api/dashboard/overview?period=all");
        JsonNode buckets = all.get("trend").get("buckets");
        assertThat(OffsetDateTime.parse(buckets.get(0).get("end").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-16T15:00:00Z")); // cic17-wed 11-16 03:08 탐지 → KST 11-16 날
    }

    @Test
    void viewerJobErrorIsMaskedInOverviewAndOperations() throws Exception {
        job(94501, "cic17-wed", "failed", "2026-11-20T23:00:00Z", "2026-11-20T23:01:00Z",
                "connect to 192.168.10.50:5432 refused");
        MockHttpSession viewer = login("t24_viewer_mask", UserRole.VIEWER, "cic17-*");
        JsonNode ov = getJson(viewer, "/api/dashboard/overview?period=24h");
        assertThat(ov.get("captures").get(0).get("latestJob").get("error").asText()).isEqualTo("connect to 192.168.*.*:5432 refused");
        JsonNode ops = getJson(viewer, "/api/operations?period=24h");
        assertThat(ops.get("jobs").get(0).get("error").asText()).isEqualTo("connect to 192.168.*.*:5432 refused");
        assertThat(ops.get("latestJobs").get(0).get("latestEnded").get("error").asText()).isEqualTo("connect to 192.168.*.*:5432 refused");
        JsonNode legacy = getJson(viewer, "/api/operations");
        assertThat(legacy.toString()).doesNotContain("192.168.10.50");
        assertNoFullIpv4(ov);
        assertNoFullIpv4(ops);
        assertNoFullIpv4(legacy);

        MockHttpSession analyst = login("t24_analyst_mask", UserRole.ANALYST, "cic17-*");
        assertThat(getJson(analyst, "/api/operations?period=24h").get("jobs").get(0).get("error").asText())
                .isEqualTo("connect to 192.168.10.50:5432 refused");
    }

    /* ───────────── /api/operations period·source ───────────── */

    @Test
    void operationsFiltersJobsAndSlackByPeriodWithLatestJobsAndCumulativeSummariesUnchanged() throws Exception {
        MockHttpSession s = login("t24_ops", UserRole.ANALYST, "*");
        job(94601, "lab-20261120", "succeeded", "2026-11-20T23:00:00Z", "2026-11-20T23:05:00Z", null);
        job(94602, "lab-20261120", "failed", "2026-11-20T23:30:00Z", null, "worker lost"); // finished 없음 → started 기준
        slack(94601, "lab-20261120", "2026-11-20T23:06:00Z");

        JsonNode h1 = getJson(s, "/api/operations?period=1h");
        assertThat(ids(h1.get("jobs"), "jobId")).containsExactly(94602L, 94601L);
        assertThat(h1.get("jobsTruncated").asBoolean()).isFalse();
        assertThat(h1.get("jobsTotal").asLong()).isEqualTo(2);
        assertThat(h1.get("slackSummaries")).hasSize(1);
        assertThat(h1.get("period").asText()).isEqualTo("1h");

        JsonNode all = getJson(s, "/api/operations?period=all");
        assertThat(all.get("jobs").size()).isGreaterThan(2);
        assertThat(all.get("slackSummaries").size()).isEqualTo(3);
        // 누적 판정 집계·latestJobs는 기간과 무관하다
        assertThat(h1.get("feedbackSummaries")).isEqualTo(all.get("feedbackSummaries"));
        assertThat(h1.get("latestJobs")).isEqualTo(all.get("latestJobs"));
        JsonNode lab = null;
        for (JsonNode l : h1.get("latestJobs")) if ("lab-20261120".equals(l.get("captureId").asText())) lab = l;
        assertThat(lab).isNotNull();
        assertThat(lab.get("latestEnded").get("jobId").asLong()).isEqualTo(94602L);
        assertThat(lab.get("latestSucceeded").get("jobId").asLong()).isEqualTo(94601L);
        JsonNode cic = h1.get("latestJobs").get(0);
        assertThat(cic.get("captureId").asText()).isEqualTo("cic17-wed");
        assertThat(cic.get("latestSucceeded").get("jobId").asLong()).isEqualTo(101L);

        // source + captureId 교집합
        JsonNode cross = getJson(s, "/api/operations?period=all&source=live&captureId=cic17-wed");
        assertThat(cross.get("jobs")).isEmpty();
        assertThat(cross.get("slackSummaries")).isEmpty();
        assertThat(cross.get("feedbackSummaries")).isEmpty();
        assertThat(cross.get("latestJobs")).isEmpty();
        JsonNode live = getJson(s, "/api/operations?period=all&source=live");
        for (JsonNode j : live.get("jobs")) assertThat(j.get("captureId").asText()).startsWith("lab-");
        for (JsonNode f : live.get("feedbackSummaries")) assertThat(f.get("captureId").asText()).startsWith("lab-");
    }

    @Test
    void operationsCapsJobsAtFiveHundredWithTotal() throws Exception {
        JdbcTemplate jdbc = jdbc();
        List<Object[]> rows = new ArrayList<>();
        for (int i = 0; i < 520; i++) {
            OffsetDateTime fin = OffsetDateTime.of(2026, 11, 20, 1, 0, 0, 0, ZoneOffset.UTC).plusMinutes(i);
            rows.add(new Object[]{95000L + i, fin.minusMinutes(1), fin});
        }
        jdbc.batchUpdate("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, 't24bulk', 'zeekad-fusion/1', 'succeeded', ?, ?, NULL, 0)", rows);
        MockHttpSession s = login("t24_bulk", UserRole.ANALYST, "t24bulk");
        JsonNode body = getJson(s, "/api/operations?period=7d");
        assertThat(body.get("jobs")).hasSize(500);
        assertThat(body.get("jobsTruncated").asBoolean()).isTrue();
        assertThat(body.get("jobsTotal").asLong()).isEqualTo(520);
        assertThat(body.get("jobs").get(0).get("jobId").asLong()).isEqualTo(95519L);
        // period가 없으면 지금처럼 전체(상한 없음)
        JsonNode legacy = getJson(s, "/api/operations");
        assertThat(legacy.get("jobs")).hasSize(520);
        assertThat(legacy.get("jobsTruncated").asBoolean()).isFalse();
        assertThat(legacy.get("period").isNull()).isTrue();
    }

    @Test
    void operationsWithoutPeriodMatchesPreviousResponseAndBundlesFollowAllowedJobs() throws Exception {
        MockHttpSession analyst = login("t24_legacy", UserRole.ANALYST, "*");
        JsonNode body = getJson(analyst, "/api/operations");
        // 지금(main)과 같은 범위: 허용 캡처의 작업 전체(job_id 내림), Slack 요약 전체, 모델 버전(전부 쓰임)
        List<Long> expectedJobs = zeekadReadMapper.findScoringJobs(null).stream().map(ScoringJob::getJobId).toList();
        assertThat(ids(body.get("jobs"), "jobId")).containsExactlyElementsOf(expectedJobs);
        assertThat(body.get("slackSummaries")).hasSize(zeekadReadMapper.findSlackSummaries(null).size());
        assertThat(body.get("bundles")).hasSize(zeekadReadMapper.findAllModelBundles().size());
        assertThat(body.get("feedbackSummaries")).hasSize(zeekadReadMapper.findRawFeedbackSummaries(null).size());
        assertThat(body.get("selectedCaptureId").isNull()).isTrue();
        assertThat(body.get("allowedCaptures")).hasSize(zeekadReadMapper.findDistinctCaptureIds().size());
        // 캡처 하나(옛 링크)
        JsonNode one = getJson(analyst, "/api/operations?captureId=cic17-wed");
        assertThat(ids(one.get("jobs"), "jobId")).containsExactly(101L, 100L);
        assertThat(one.get("selectedCaptureId").asText()).isEqualTo("cic17-wed");

        // 번들: 숨긴 캡처만 쓴 모델 버전은 나오지 않는다(cic17-*는 zeekad-fusion/1만 씀)
        MockHttpSession viewer = login("t24_bundle", UserRole.VIEWER, "cic17-*");
        JsonNode v = getJson(viewer, "/api/operations");
        assertThat(v.get("bundles")).hasSize(1);
        assertThat(v.get("bundles").get(0).get("bundleId").asText()).isEqualTo("zeekad-fusion/1");
        // 조건 줄 선택지: 허용 캡처와 수집원 종류만
        assertThat(v.get("sources")).hasSize(1);
        assertThat(v.get("sources").get(0).get("captureId").asText()).isEqualTo("cic17-wed");
        assertThat(v.get("sources").get(0).get("sourceType").asText()).isEqualTo("imported");
    }

    /* ───────────── 도우미 ───────────── */

    private DashboardOverviewService snapshotService() {
        DashboardProperties props = new DashboardProperties();
        props.setTimeAnchor("latest-data");
        TimeContextService tcs = new TimeContextService(props, zeekadReadMapper, clock);
        IncidentQueueService qs = new IncidentQueueService(zeekadReadMapper, captureAccessService, maskingService, tcs);
        return new DashboardOverviewService(zeekadReadMapper, qs, tcs, maskingService);
    }

    private static long trendSum(DashboardOverviewResponse ov) {
        return ov.trend().buckets().stream().mapToLong(DashboardOverviewResponse.Bucket::total).sum()
                + ov.trend().unbucketed().noDetectedAt() + ov.trend().unbucketed().afterAnchor();
    }

    private static Map<String, CaptureRow> byCapture(DashboardOverviewResponse ov) {
        Map<String, CaptureRow> m = new HashMap<>();
        for (CaptureRow r : ov.captures()) m.put(r.captureId(), r);
        return m;
    }

    private static List<Long> ids(JsonNode arr, String field) {
        List<Long> out = new ArrayList<>();
        for (JsonNode n : arr) out.add(n.get(field).asLong());
        return out;
    }

    /**
     * 불변식 자료(기준 시각 2026-11-21 00:00Z, now 모드).
     * lab-20261120: 94000(−3h) A·D → 94001(−10분) A(high)·B(low)·C(종결). A 탐지 = −3h, D는 최신 큐에 없음.
     * lab-20261121: 94002(−40분) E(medium). t24imp-old: 실패 94008(−2h, finished 없음·started 기준)·94009(−21일)·성공 94012(−20일) F·G.
     * t24imp-nofin: 성공인데 finished 없음 H(탐지 시각 없음). t24imp-future: 기준 시각 뒤 완료 I. t24imp-edge: J(−6일), K(정확히 −24h: 24h에서 빠지고 7d에 든다).
     */
    private void insertInvariantData() {
        job(94000, "lab-20261120", "succeeded", "2026-11-20T20:55:00Z", "2026-11-20T21:00:00Z", null);
        incident(94000, "lab-20261120", 1, "10.61.0.1", "2026-11-20T20:50:00Z", "low");
        incident(94000, "lab-20261120", 2, "10.61.0.4", "2026-11-20T20:50:00Z", "low");
        job(94001, "lab-20261120", "succeeded", "2026-11-20T23:45:00Z", "2026-11-20T23:50:00Z", null);
        incident(94001, "lab-20261120", 1, "10.61.0.1", "2026-11-20T20:50:00Z", "high");
        incident(94001, "lab-20261120", 2, "10.61.0.2", "2026-11-20T23:40:00Z", "low");
        incident(94001, "lab-20261120", 3, "10.61.0.3", "2026-11-20T23:40:00Z", "closed");
        job(94002, "lab-20261121", "succeeded", "2026-11-20T23:15:00Z", "2026-11-20T23:20:00Z", null);
        incident(94002, "lab-20261121", 1, "10.62.0.1", "2026-11-20T23:10:00Z", "medium");
        job(94008, "t24imp-old", "failed", "2026-11-20T22:00:00Z", null, "worker lost");
        job(94009, "t24imp-old", "failed", "2026-10-31T00:00:00Z", "2026-10-31T00:01:00Z", "old");
        // 재채점 성공(가장 최근 끝난 작업)이라 상태는 imported. 실패 작업은 기간 안 수에만 든다
        job(94012, "t24imp-old", "succeeded", "2026-11-01T00:00:00Z", "2026-11-01T00:10:00Z", null);
        incident(94012, "t24imp-old", 1, "10.63.0.1", "2026-10-30T00:00:00Z", "low");
        incident(94012, "t24imp-old", 2, "10.63.0.2", "2026-10-30T00:00:00Z", "medium");
        job(94004, "t24imp-nofin", "succeeded", "2026-11-20T10:00:00Z", null, null);
        incident(94004, "t24imp-nofin", 1, "10.64.0.1", "2026-11-20T09:00:00Z", "low");
        job(94005, "t24imp-future", "succeeded", "2026-11-21T01:00:00Z", "2026-11-21T02:00:00Z", null);
        incident(94005, "t24imp-future", 1, "10.65.0.1", "2026-11-21T00:30:00Z", "low");
        job(94006, "t24imp-edge", "succeeded", "2026-11-14T23:00:00Z", "2026-11-15T00:00:00Z", null);
        incident(94006, "t24imp-edge", 1, "10.66.0.2", "2026-11-14T22:00:00Z", "low");
        job(94007, "t24imp-edge", "succeeded", "2026-11-19T23:00:00Z", "2026-11-20T00:00:00Z", null);
        incident(94007, "t24imp-edge", 1, "10.66.0.2", "2026-11-14T22:00:00Z", "low");
        incident(94007, "t24imp-edge", 2, "10.66.0.1", "2026-11-19T22:00:00Z", "low");
    }

    private void job(long id, String capture, String status, String started, String finished, String error) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, CAST(? AS TIMESTAMP WITH TIME ZONE), CAST(? AS TIMESTAMP WITH TIME ZONE), ?, 0)",
                id, capture, status, started, finished, error);
    }

    /** kind: low / medium(교차 탐지) / high(리포트 + 발송) / closed */
    private void incident(long jobId, String capture, int rank, String ip, String eventEnd, String kind) {
        String id = capture + "|" + ip + "|originator|" + rank;
        String also = "medium".equals(kind) ? "ARRAY['autoencoder']" : "NULL";
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', CAST(? AS TIMESTAMP WITH TIME ZONE) - INTERVAL '5' MINUTE, "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), 'hbos', " + also + ", 10, NULL)",
                jobId, capture, rank, id, ip, eventEnd, eventEnd);
        if ("high".equals(kind)) {
            jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                    + "zeekad_report, created_at) VALUES (?, ?, 'template', 'template.v1', '{}' FORMAT JSON, CAST(? AS TIMESTAMP WITH TIME ZONE))",
                    jobId, id, eventEnd);
            jdbc().update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                    + "VALUES (?, ?, TRUE, 'policy', CAST(? AS TIMESTAMP WITH TIME ZONE))", jobId, id, eventEnd);
        }
        if ("closed".equals(kind)) {
            jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                    + "VALUES (?, ?, 'closed', 'benign', CAST(? AS TIMESTAMP WITH TIME ZONE), 't24')", jobId, id, eventEnd);
        }
    }

    private void slack(long jobId, String capture, String created) {
        jdbc().update("INSERT INTO dashboard.raw_slack_summaries (job_id, capture_id, zeekad_message_version, zeekad_delivery_mode, "
                        + "zeekad_delivery_status, slack_payload, slack_ts, delivered_at, created_at) VALUES (?, ?, 'daily-summary.v1', 'dry_run', "
                        + "'recorded', '{\"text\": \"t24\"}' FORMAT JSON, NULL, NULL, CAST(? AS TIMESTAMP WITH TIME ZONE))",
                jobId, capture, created);
    }

    private static DashboardUserPrincipal principal(UserRole role, List<String> patterns) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t24-principal");
        u.setDisplayName("t24");
        u.setRole(role);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, patterns, FIXED_NOW);
    }

    private void assertNoFullIpv4(JsonNode node) {
        var m = FULL_IPV4.matcher(node.toString());
        while (m.find()) {
            boolean valid = true;
            for (int g = 1; g <= 4; g++) {
                if (Integer.parseInt(m.group(g)) > 255) valid = false;
            }
            assertThat(valid).as("가려지지 않은 IPv4: %s", m.group()).isFalse();
        }
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private MockHttpSession login(String username, UserRole role, String patterns) throws Exception {
        userAdminService.createUser(username, username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
