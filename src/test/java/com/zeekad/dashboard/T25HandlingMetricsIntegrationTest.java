package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.OperationsApiResponse.HandlingTimes;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.HandlingPoint;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.HandlingMetricsService;
import com.zeekad.dashboard.service.IncidentQueueService;
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
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T25 /api/operations handlingTimes·workload를 실제 질의(H2)로: 착수 = 첫 investigating 이력, 종결 = status_updated_at
 * (이력 changed_at과 다른 자료로 확인), 가져온 데이터 탐지 지연 제외, period 없으면 블록 없음, SQL 기간 하한 거르기가 결과를 바꾸지 않음,
 * workload 불변식과 ackOverdue = 큐 overdue=true total. 시험용 행은 job 96100~96199.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T25HandlingMetricsIntegrationTest {

    static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    static final String LIVE = "lab-t25m";
    static final String IMP = "t25mimp";

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
    @Autowired private ZeekadReadMapper zeekadReadMapper;
    @Autowired private IncidentQueueService queueService;
    @Autowired private HandlingMetricsService metricsService;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    private static int seq = 0;

    @BeforeEach
    void seed() {
        job(96100, LIVE, "2026-11-20T12:00:00Z");
        // m1: MTTD 1시간, 착수 10분 뒤, 종결 status_updated_at 13:00(이력 changed_at은 13:00:30 → 쓰지 않는다)
        incident(96100, LIVE, 1, "2026-11-20T11:00:00Z");
        history(96100, LIVE, 1, "open", "investigating", null, "2026-11-20T12:10:00Z");
        history(96100, LIVE, 1, "investigating", "closed", "true_positive", "2026-11-20T13:00:30Z");
        setStatus(96100, LIVE, 1, "closed", "true_positive", "2026-11-20T13:00:00Z");
        // m2: 착수 30분 뒤, 조사 중(두 번째 investigating 기록은 쓰지 않는다)
        incident(96100, LIVE, 2, "2026-11-20T11:30:00Z");
        history(96100, LIVE, 2, "open", "investigating", null, "2026-11-20T12:30:00Z");
        history(96100, LIVE, 2, "open", "investigating", null, "2026-11-20T15:00:00Z");
        setStatus(96100, LIVE, 2, "investigating", null, "2026-11-20T12:30:00Z");
        // m3: 신규, 탐지 지연 음수
        incident(96100, LIVE, 3, "2026-11-20T12:30:00Z");
        // m4: 조사 중 기록 없이 종결(판정 없음), 처리 2시간
        incident(96100, LIVE, 4, "2026-11-20T11:00:00Z");
        setStatus(96100, LIVE, 4, "closed", null, "2026-11-20T14:00:00Z");
        // 가져온 데이터: 탐지 지연 제외, 착수 20분, 처리 40분(정상)
        job(96110, IMP, "2026-11-20T12:00:00Z");
        incident(96110, IMP, 1, "2017-07-05T10:00:00Z");
        history(96110, IMP, 1, "open", "investigating", null, "2026-11-20T12:20:00Z");
        setStatus(96110, IMP, 1, "closed", "benign", "2026-11-20T12:40:00Z");
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 96100 AND 96199";
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    @Test
    void handlingTimesFromRealQuery() throws Exception {
        MockHttpSession s = login(UserRole.VIEWER, LIVE + "," + IMP);
        JsonNode ops = getJson(s, "/api/operations?period=24h");
        JsonNode h = ops.get("handlingTimes");
        assertThat(h.at("/detection/n").asLong()).isEqualTo(3);          // m1 3600, m2 1800, m4 3600 (m3 음수 제외)
        assertThat(h.at("/acknowledge/n").asLong()).isEqualTo(3);        // 600, 1800, 1200
        assertThat(h.at("/acknowledge/medianSeconds").asLong()).isEqualTo(1200);
        assertThat(h.at("/acknowledge/p90Seconds").asLong()).isEqualTo(1800);
        assertThat(h.at("/acknowledge/excluded").asLong()).isEqualTo(1);  // m4
        assertThat(h.at("/resolve/all/n").asLong()).isEqualTo(3);        // 3600, 7200, 2400
        assertThat(h.at("/resolve/all/medianSeconds").asLong()).isEqualTo(3600); // status_updated_at 기준(이력이면 3630)
        assertThat(h.at("/resolve/all/p90Seconds").asLong()).isEqualTo(7200);
        assertThat(h.at("/resolve/all/smallSample").asBoolean()).isTrue();
        assertThat(h.at("/resolve/byResolution/0/resolution").asText()).isEqualTo("true_positive");
        assertThat(h.at("/resolve/byResolution/0/stat/medianSeconds").asLong()).isEqualTo(3600);
        assertThat(h.at("/resolve/byResolution/3/resolution").asText()).isEqualTo("none");
        assertThat(h.at("/resolve/byResolution/3/stat/medianSeconds").asLong()).isEqualTo(7200);
        // 가져온 데이터는 탐지 지연에서 빠진다: 실습망만 보면 같은 수
        JsonNode liveOnly = getJson(s, "/api/operations?period=24h&source=live").get("handlingTimes");
        assertThat(liveOnly.get("detection")).isEqualTo(h.get("detection"));
        JsonNode impOnly = getJson(s, "/api/operations?period=24h&source=imported").get("handlingTimes");
        assertThat(impOnly.at("/detection/n").asLong()).isZero();
        assertThat(impOnly.at("/detection/excluded").asLong()).isZero();
        assertThat(impOnly.at("/acknowledge/n").asLong()).isEqualTo(1);
        // period가 없으면 블록이 없다(workload는 있다)
        JsonNode legacy = getJson(s, "/api/operations");
        assertThat(legacy.has("handlingTimes")).isFalse();
        assertThat(legacy.has("workload")).isTrue();
    }

    @Test
    void detectionValuesAndSqlLowerBoundDoesNotChangeResult() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, LIVE + "," + IMP);
        JsonNode h = getJson(s, "/api/operations?period=24h").get("handlingTimes");
        // m1 3600, m2 1800, m4 3600 / m3 음수 제외
        assertThat(h.at("/detection/n").asLong()).isEqualTo(3);
        assertThat(h.at("/detection/excluded").asLong()).isEqualTo(1);
        assertThat(h.at("/detection/medianSeconds").asLong()).isEqualTo(3600);

        DashboardUserPrincipal p = principal(LIVE + "," + IMP);
        for (String period : List.of("1h", "24h", "7d", "30d")) {
            IncidentQueueService.Condition cond = queueService.resolveCondition(p, period, null, null, "127.0.0.1");
            HandlingTimes withBound = metricsService.compute(cond, true).handlingTimes();
            List<HandlingPoint> all = zeekadReadMapper.findHandlingPoints(cond.criteria(), null);
            HandlingTimes noBound = invokeHandlingTimes(all, cond.after(), cond.anchor());
            assertThat(withBound).as(period).isEqualTo(noBound);
        }
        // 1시간: 기간 밖
        JsonNode oneHour = getJson(s, "/api/operations?period=1h").get("handlingTimes");
        assertThat(oneHour.at("/resolve/all/n").asLong()).isZero();
        assertThat(oneHour.at("/resolve/all/medianSeconds").isNull()).isTrue();
    }

    @Test
    void workloadMatchesQueueOverdueAndInvariants() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, LIVE + "," + IMP);
        for (String src : List.of("", "&source=live", "&source=imported")) {
            JsonNode w = getJson(s, "/api/operations?period=7d" + src).get("workload");
            assertThat(w.get("unclosed").asLong()).isEqualTo(w.get("assigned").asLong() + w.get("unassigned").asLong());
            long sum = 0;
            for (JsonNode l : w.get("byAssignee")) sum += l.get("open").asLong() + l.get("investigating").asLong();
            assertThat(sum).isEqualTo(w.get("assigned").asLong());
            JsonNode q = getJson(s, "/api/incidents/queue?period=all&overdue=true" + src);
            assertThat(w.get("ackOverdue").asLong()).as(src).isEqualTo(q.get("total").asLong());
            JsonNode unclosedQ = getJson(s, "/api/incidents/queue?period=all&status=open" + src);
            JsonNode invQ = getJson(s, "/api/incidents/queue?period=all&status=investigating" + src);
            assertThat(w.get("unclosed").asLong()).isEqualTo(unclosedQ.get("total").asLong() + invQ.get("total").asLong());
        }
        // m3(High 아님, 낮음 24시간 → 12:00+24h > 기준 시각): 지연 0. 실습망 신규 = m3 하나
        assertThat(getJson(s, "/api/operations?period=7d").at("/workload/ackOverdue").asLong()).isZero();
        assertThat(getJson(s, "/api/operations?period=7d").at("/workload/unclosed").asLong()).isEqualTo(2);
    }

    /* ───────────── 도우미 ───────────── */

    private HandlingTimes invokeHandlingTimes(List<HandlingPoint> pts, OffsetDateTime after, OffsetDateTime until) throws Exception {
        Method m = HandlingMetricsService.class.getDeclaredMethod("handlingTimes", List.class, OffsetDateTime.class, OffsetDateTime.class);
        m.setAccessible(true);
        return (HandlingTimes) m.invoke(metricsService, pts, after, until);
    }

    private DashboardUserPrincipal principal(String patterns) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t25-principal");
        u.setDisplayName("t25");
        u.setRole(UserRole.ANALYST);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, List.of(patterns.split(",")), FIXED_NOW);
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t25m_u" + (++seq) + "_" + System.nanoTime() % 100000;
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

    private static String id(String capture, int n) {
        return capture + "|10.81.0." + n + "|originator|t25m";
    }

    private void job(long id, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', CAST(? AS TIMESTAMP WITH TIME ZONE) - INTERVAL '5' MINUTE, "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                id, capture, finished, finished);
    }

    private void incident(long jobId, String capture, int n, String eventStart) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', CAST(? AS TIMESTAMP WITH TIME ZONE), "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE) + INTERVAL '1' MINUTE, 'hbos', NULL, 10, NULL)",
                jobId, capture, n, id(capture, n), "10.81.0." + n, eventStart, eventStart);
    }

    private void setStatus(long jobId, String capture, int n, String st, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), 't25')", jobId, id(capture, n), st, resolution, at);
    }

    private void history(long jobId, String capture, int n, String from, String to, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution, "
                + "actor, reason, changed_at) VALUES (?, ?, ?, ?, ?, 'analyst1', 't25', CAST(? AS TIMESTAMP WITH TIME ZONE))",
                jobId, id(capture, n), from, to, resolution, at);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
