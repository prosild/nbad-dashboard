package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
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
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T29 기간 밖 수(outsidePeriod = 같은 조건 기간 전체 total − total), newestOutsidePeriod(기간 시작 이하 최대 탐지 시각),
 * 수집원 lastDetectedAt. 띠 축·수집원·자산 검색·통신 방향 조건, 탐지 시각 없음·기준 시각 뒤 행, 기간 경계, 허용 캡처 밖.
 *
 * 시험 데이터(기준 시각 = 2026-11-21 00:00Z, now 모드):
 *  t29a-cap 작업 9101(11-10 00:10 완료): A3·A4 / 작업 9102(11-20 12:00, 최신): A1·A2·A3·A4 → A1·A2 탐지 11-20 12:00, A3·A4 11-10 00:10
 *  t29n-cap 작업 9103(성공, 완료 시각 없음): N1 → 탐지 시각 없음
 *  t29f-cap 작업 9104(11-22 00:00): F1 → 기준 시각 뒤
 *  t29h-cap 작업 9105(11-01): H1 → 허용 밖(ANALYST 시험 주체는 t29a·t29n·t29f만 허용)
 *  A1·A3 교차 탐지(Medium), 나머지 Low. A2·A4 responder, 나머지 originator.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T29OutsidePeriodIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final long[] JOBS = {9101L, 9102L, 9103L, 9104L, 9105L, 9106L};
    private static final List<String> PATTERNS = List.of("t29a-*", "t29n-*", "t29f-*");
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
    @Autowired private IncidentQueueService queueService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    @BeforeEach
    void seed() {
        deleteRows();
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        job(jdbc, 9101L, "t29a-cap", "2026-11-10 00:00:00Z", "'2026-11-10 00:10:00Z'");
        job(jdbc, 9102L, "t29a-cap", "2026-11-20 11:00:00Z", "'2026-11-20 12:00:00Z'");
        job(jdbc, 9103L, "t29n-cap", "2026-11-20 11:00:00Z", null);
        job(jdbc, 9104L, "t29f-cap", "2026-11-21 23:00:00Z", "'2026-11-22 00:00:00Z'");
        job(jdbc, 9105L, "t29h-cap", "2026-11-01 00:00:00Z", "'2026-11-01 00:10:00Z'");
        row(jdbc, 9101L, "t29a-cap", 1, "A3", "10.91.0.3", "originator", true);
        row(jdbc, 9101L, "t29a-cap", 2, "A4", "10.91.0.4", "responder", false);
        row(jdbc, 9102L, "t29a-cap", 1, "A1", "10.91.0.1", "originator", true);
        row(jdbc, 9102L, "t29a-cap", 2, "A2", "10.91.0.2", "responder", false);
        row(jdbc, 9102L, "t29a-cap", 3, "A3", "10.91.0.3", "originator", true);
        row(jdbc, 9102L, "t29a-cap", 4, "A4", "10.91.0.4", "responder", false);
        row(jdbc, 9103L, "t29n-cap", 1, "N1", "10.92.0.1", "originator", false);
        row(jdbc, 9104L, "t29f-cap", 1, "F1", "10.93.0.1", "originator", false);
        row(jdbc, 9105L, "t29h-cap", 1, "H1", "10.94.0.1", "originator", false);
    }

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        deleteRows();
    }

    @Test
    void outsidePeriodIsAllPeriodTotalMinusTotalIncludingNullAndAfterAnchorRows() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST);
        UnifiedQueueResponse day = queueService.loadQueue(analyst, p("24h", null, null, null, null, null), "127.0.0.1");
        assertThat(day.total()).isEqualTo(2);                        // A1·A2
        assertThat(day.outsidePeriod()).isEqualTo(4L);               // A3·A4 + 탐지 시각 없음 N1 + 기준 뒤 F1 (허용 밖 H1 없음)
        assertThat(day.newestOutsidePeriod().toInstant()).isEqualTo(Instant.parse("2026-11-10T00:10:00Z"));
        assertThat(day.latestDetectedAt().toInstant()).isEqualTo(Instant.parse("2026-11-20T12:00:00Z"));

        UnifiedQueueResponse all = queueService.loadQueue(analyst, p("all", null, null, null, null, null), "127.0.0.1");
        assertThat(all.total()).isEqualTo(6);
        assertThat(all.outsidePeriod()).isZero();
        assertThat(all.newestOutsidePeriod()).isNull();
        assertThat(day.total() + day.outsidePeriod()).isEqualTo(all.total());
    }

    @Test
    void outsidePeriodFollowsEveryOtherConditionOnBothSqlAndAssetPaths() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST);
        // {source, captureId, priority(띠), role, asset}
        List<String[]> conds = List.of(
                new String[]{null, null, null, null, null},
                new String[]{null, null, "medium", null, null},
                new String[]{null, null, "low", null, null},
                new String[]{null, "t29a-cap", null, null, null},
                new String[]{null, "t29n-cap", null, null, null},
                new String[]{"imported", null, null, null, null},
                new String[]{null, null, null, "responder", null},
                new String[]{null, null, null, null, "10.91.0"},
                new String[]{null, null, "medium", null, "10.91.0"},
                new String[]{null, null, null, "originator", "."},
                new String[]{null, null, null, null, "."});
        for (String period : List.of("1h", "24h", "7d", "30d")) {
            for (String[] c : conds) {
                UnifiedQueueResponse r = queueService.loadQueue(analyst, p(period, c[0], c[1], c[2], c[3], c[4]), "127.0.0.1");
                UnifiedQueueResponse a = queueService.loadQueue(analyst, p("all", c[0], c[1], c[2], c[3], c[4]), "127.0.0.1");
                String label = period + " " + String.join(",", java.util.Arrays.stream(c).map(String::valueOf).toList());
                assertThat(r.outsidePeriod()).as(label).isEqualTo(a.total() - r.total());
                // 자산 검색 "."는 모든 행에 맞으므로 SQL 경로와 같은 값이다
                if (".".equals(c[4])) {
                    UnifiedQueueResponse sql = queueService.loadQueue(analyst, p(period, c[0], c[1], c[2], c[3], null), "127.0.0.1");
                    assertThat(r.outsidePeriod()).as(label).isEqualTo(sql.outsidePeriod());
                    assertThat(r.newestOutsidePeriod()).as(label).isEqualTo(sql.newestOutsidePeriod());
                    assertThat(r.latestDetectedAt()).as(label).isEqualTo(sql.latestDetectedAt());
                    assertThat(r.total()).as(label).isEqualTo(sql.total());
                    assertThat(r.summary()).as(label).isEqualTo(sql.summary());
                }
            }
        }
        // 띠 필터(Medium) 24시간: A1 안, A3 밖
        UnifiedQueueResponse medium = queueService.loadQueue(analyst, p("24h", null, null, "medium", null, null), "127.0.0.1");
        assertThat(medium.total()).isEqualTo(1);
        assertThat(medium.outsidePeriod()).isEqualTo(1L);
        // 요약(띠 축 뺀 집합)은 기간 밖 수와 상관없다
        assertThat(medium.summary().total()).isEqualTo(2);
        // 자산 검색 경로 24시간(10.91.0 = t29a): A1·A2 안, A3·A4 밖
        UnifiedQueueResponse asset = queueService.loadQueue(analyst, p("24h", null, null, null, null, "10.91.0"), "127.0.0.1");
        assertThat(asset.total()).isEqualTo(2);
        assertThat(asset.outsidePeriod()).isEqualTo(2L);
        assertThat(asset.newestOutsidePeriod().toInstant()).isEqualTo(Instant.parse("2026-11-10T00:10:00Z"));
    }

    @Test
    void periodBoundaryStartIsOutsideAndNewestOutsideIsAtOrBeforeStart() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST);
        // 기준 11-17 00:10, 7일 시작 = 11-10 00:10 = A3·A4 탐지 시각 → 시작 불포함이라 기간 밖. A1·A2·F1은 기준 뒤, N1은 시각 없음.
        clock.set(Instant.parse("2026-11-17T00:10:00Z"));
        UnifiedQueueResponse atStart = queueService.loadQueue(analyst, p("7d", null, null, null, null, null), "127.0.0.1");
        assertThat(atStart.total()).isZero();
        assertThat(atStart.outsidePeriod()).isEqualTo(6L);
        assertThat(atStart.newestOutsidePeriod().toInstant()).isEqualTo(Instant.parse("2026-11-10T00:10:00Z"));
        UnifiedQueueResponse atStartAsset = queueService.loadQueue(analyst, p("7d", null, null, null, null, "."), "127.0.0.1");
        assertThat(atStartAsset.outsidePeriod()).isEqualTo(6L);
        assertThat(atStartAsset.newestOutsidePeriod()).isEqualTo(atStart.newestOutsidePeriod());

        // 1초 앞이면 A3·A4가 기간 안, 시작 이하에 탐지된 행이 없어 newestOutsidePeriod는 null(시각 없음·기준 뒤는 넣지 않는다)
        clock.set(Instant.parse("2026-11-17T00:09:59Z"));
        UnifiedQueueResponse inside = queueService.loadQueue(analyst, p("7d", null, null, null, null, null), "127.0.0.1");
        assertThat(inside.total()).isEqualTo(2);
        assertThat(inside.outsidePeriod()).isEqualTo(4L);
        assertThat(inside.newestOutsidePeriod()).isNull();
        UnifiedQueueResponse insideAsset = queueService.loadQueue(analyst, p("7d", null, null, null, null, "."), "127.0.0.1");
        assertThat(insideAsset.outsidePeriod()).isEqualTo(4L);
        assertThat(insideAsset.newestOutsidePeriod()).isNull();
    }

    @Test
    void viewerApiHasOutsidePeriodAndSourceLastDetectedOnlyForAllowedCapturesWithoutFullIpv4() throws Exception {
        MockHttpSession viewer = login("t29_viewer_out", UserRole.VIEWER, String.join(",", PATTERNS));
        JsonNode body = getJson(viewer, "/api/incidents/queue?period=24h");
        assertThat(body.get("total").asLong()).isEqualTo(2);
        assertThat(body.get("outsidePeriod").asLong()).isEqualTo(4);
        assertThat(OffsetDateTime.parse(body.get("newestOutsidePeriod").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-10T00:10:00Z"));
        Map<String, JsonNode> sources = new HashMap<>();
        for (JsonNode s : body.get("sources")) sources.put(s.get("captureId").asText(), s);
        assertThat(sources).containsOnlyKeys("t29a-cap", "t29n-cap", "t29f-cap");
        assertThat(OffsetDateTime.parse(sources.get("t29a-cap").get("lastDetectedAt").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-20T12:00:00Z"));
        assertThat(sources.get("t29n-cap").get("lastDetectedAt").isNull()).isTrue();
        assertThat(OffsetDateTime.parse(sources.get("t29f-cap").get("lastDetectedAt").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-22T00:00:00Z"));
        assertThat(body.toString()).doesNotContain("t29h-cap", "10.94.0.1");
        assertNoFullIpv4(body);

        JsonNode all = getJson(viewer, "/api/incidents/queue?period=all");
        assertThat(all.get("outsidePeriod").asLong()).isZero();
        assertThat(all.get("newestOutsidePeriod").isNull()).isTrue();
        // 자산 검색(가려진 값) 경로도 같은 수
        JsonNode asset = getJson(viewer, "/api/incidents/queue?period=24h&asset=10.91");
        assertThat(asset.get("total").asLong()).isEqualTo(2);
        assertThat(asset.get("outsidePeriod").asLong()).isEqualTo(2);
        assertNoFullIpv4(asset);
    }

    @Test
    void lastDetectedFollowsNewSucceededJobOfTheCapture() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST);
        assertThat(last(queueService.loadQueue(analyst, p("24h", null, null, null, null, null), "127.0.0.1"), "t29a-cap"))
                .isEqualTo(Instant.parse("2026-11-20T12:00:00Z"));
        // 같은 캡처에 새 성공 작업(최신 작업 ID가 바뀜)이 생기면 다시 센다
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        job(jdbc, 9106L, "t29a-cap", "2026-11-20 17:00:00Z", "'2026-11-20 18:00:00Z'");
        row(jdbc, 9106L, "t29a-cap", 1, "A5", "10.91.0.5", "originator", false);
        row(jdbc, 9106L, "t29a-cap", 2, "A1", "10.91.0.1", "originator", true);
        assertThat(last(queueService.loadQueue(analyst, p("24h", null, null, null, null, null), "127.0.0.1"), "t29a-cap"))
                .isEqualTo(Instant.parse("2026-11-20T18:00:00Z"));
    }

    private static Instant last(UnifiedQueueResponse r, String capture) {
        return r.sources().stream().filter(s -> s.captureId().equals(capture)).findFirst()
                .map(s -> s.lastDetectedAt() == null ? null : s.lastDetectedAt().toInstant()).orElse(null);
    }

    /* ───────────── 도우미 ───────────── */

    private static QueueParams p(String period, String source, String captureId, String priority, String role, String asset) {
        return new QueueParams(period, source, captureId, priority, null, null, null, null, role, null, null, asset,
                null, null, null, "100");
    }

    private static DashboardUserPrincipal principal(UserRole role) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t29-principal");
        u.setDisplayName("t29");
        u.setRole(role);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, PATTERNS, FIXED_NOW);
    }

    private static void job(JdbcTemplate jdbc, long jobId, String capture, String started, String finishedLiteral) {
        String finished = finishedLiteral == null ? "NULL" : "TIMESTAMP WITH TIME ZONE " + finishedLiteral;
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', CAST(? AS TIMESTAMP WITH TIME ZONE), " + finished + ", NULL, 1)",
                jobId, capture, started);
    }

    private static void row(JdbcTemplate jdbc, long jobId, String capture, int rank, String name, String ip, String role, boolean also) {
        String id = capture + "|" + ip + "|" + role + "|t29-" + name;
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-01 00:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-01 00:05:00Z', 'hbos', " + (also ? "ARRAY['autoencoder']" : "NULL")
                + ", 3, NULL)", jobId, capture, rank, id, ip, role);
    }

    private void deleteRows() {
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        for (long job : JOBS) {
            jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", job);
        }
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
}
