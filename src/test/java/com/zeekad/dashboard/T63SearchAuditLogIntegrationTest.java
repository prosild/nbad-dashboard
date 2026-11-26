package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T63 검색·감사 로그·서버 로그(모의 환경: H2 + MockMvc).
 * <ul>
 *   <li>큐 asset(목록·옛 목록·새 건수·이웃)과 호스트 위험도 q: 숨은 문자·전각 글자를 낀 이름이 보이는 글자로 찾힌다(분석가·조회자),
 *       asset 101 UTF-16 단위는 400, 숨은 문자만인 검색어는 조건 없음.</li>
 *   <li>감사 로그 actorUsername: %·_·\가 글자 그대로 찾히고 101은 400. 서러게이트 쌍이 열 상한에 걸치는 값을 저장해도 반쪽이 남지 않는다.</li>
 *   <li>서버 로그: 검토 결정의 요청 incidentId와 상태 전이의 사용자 이름이 줄바꿈으로 로그 줄을 만들지 못한다(표지로 찍힌다).</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(OutputCaptureExtension.class)
class T63SearchAuditLogIntegrationTest {

    static final String CAP = "t63-srch";
    static final long JOB = 64001L;
    static final String PASSWORD = "Pass1234!";
    static final String ADMIN_SECRET = "JBSWY3DPEHPK3PXP";
    /** 숨은 문자(U+200B)와 전각 글자를 낀 이름 */
    static final String TRICKY_NAME = "web​-ｓｅｒｖｅｒ-63";
    static final String LOG_ACTOR = "t63_log\nFAKE-ACTOR-LINE";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserAdminService userAdminService;
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private TotpService totpService;
    @Autowired
    private Clock clock;
    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;
    @Autowired
    @Qualifier("appDataSource")
    private DataSource appDataSource;

    private JdbcTemplate zeekadJdbc;
    private JdbcTemplate appJdbc;
    private MockHttpSession analyst;
    private MockHttpSession viewer;
    private MockHttpSession admin;

    static String incidentId(int i) {
        return CAP + "|" + hostIp(i) + "|originator|" + (1700000100 + i);
    }

    /** 조회자 묶음이 갈리게 /16을 다르게 둔다 */
    static String hostIp(int i) {
        return "10." + (63 + i) + ".0.1";
    }

    @BeforeAll
    void seed() throws Exception {
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        appJdbc = new JdbcTemplate(appDataSource);
        cleanup();
        createUserOnce("t63s_analyst", UserRole.ANALYST, "t63-*");
        createUserOnce("t63s_viewer", UserRole.VIEWER, "t63-*");
        DashboardUser adminUser = createUserOnce("t63s_admin", UserRole.ADMIN, "*");
        userMapper.updateTotpState(adminUser.getId(), ADMIN_SECRET, true, OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        if (userMapper.findByUsername(LOG_ACTOR) == null) {
            DashboardUser logActor = createUserOnce("t63_logactor", UserRole.ANALYST, "t63-*");
            appJdbc.update("UPDATE users SET username = ? WHERE id = ?", LOG_ACTOR, logActor.getId());
        }

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-21 02:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-21 02:05:00Z', NULL, 2)
                """, JOB, CAP);
        insertQueueRow(1, TRICKY_NAME);
        insertQueueRow(2, "plain-host");
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
                VALUES (?, ?, 'investigating', NULL, TIMESTAMP WITH TIME ZONE '2026-11-21 02:10:00Z', 't63s_analyst')
                """, JOB, incidentId(1));

        analyst = login("t63s_analyst");
        viewer = login("t63s_viewer");
        admin = loginAdmin("t63s_admin");
    }

    @AfterAll
    void cleanup() {
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE capture_id = ?", CAP);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", JOB);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_status WHERE incident_id LIKE ?", CAP + "|%");
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_status_history WHERE incident_id LIKE ?", CAP + "|%");
    }

    private void insertQueueRow(int i, String hostName) {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip,
                    zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-21 01:30:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-21 01:45:00Z', 'iforest', NULL, 5, ?)
                """, JOB, CAP, i, incidentId(i), hostIp(i), new String[]{hostName});
    }

    /* ───────────────────────── 검색 ───────────────────────── */

    /** 네 경로의 "찾은 수": 큐 total, 옛 목록 incidents 수, 새 건수 count, 이웃 total */
    private List<Long> assetCounts(MockHttpSession session, String asset) throws Exception {
        List<Long> out = new ArrayList<>();
        out.add(json(session, withAsset(get("/api/incidents/queue").param("captureId", CAP).param("period", "all"), asset))
                .get("total").asLong());
        out.add((long) json(session, withAsset(get("/api/incidents").param("captureId", CAP), asset)).get("incidents").size());
        out.add(json(session, withAsset(get("/api/incidents/queue/new-count").param("captureId", CAP)
                .param("since", "2000-01-01T00:00:00Z"), asset)).get("count").asLong());
        out.add(json(session, withAsset(get("/api/incidents/queue/neighbors").param("jobId", String.valueOf(JOB))
                .param("queueRank", "1").param("captureId", CAP).param("period", "all"), asset)).get("total").asLong());
        return out;
    }

    private static MockHttpServletRequestBuilder withAsset(MockHttpServletRequestBuilder b, String asset) {
        return asset == null ? b : b.param("asset", asset);
    }

    @Test
    void assetSearchMatchesVisibleTextThroughHiddenAndFullwidthCharactersOnAllFourPaths() throws Exception {
        for (MockHttpSession session : List.of(analyst, viewer)) {
            assertThat(assetCounts(session, null)).as("조건 없음").containsExactly(2L, 2L, 2L, 2L);
            assertThat(assetCounts(session, "web-server-63")).as("보이는 글자로").containsExactly(1L, 1L, 1L, 1L);
            assertThat(assetCounts(session, "WEB-SERVER")).as("대문자").containsExactly(1L, 1L, 1L, 1L);
            assertThat(assetCounts(session, "ｗｅｂ-ｓｅｒｖｅｒ")).as("전각 검색어").containsExactly(1L, 1L, 1L, 1L);
            assertThat(assetCounts(session, "web​‮-server")).as("검색어의 숨은 문자").containsExactly(1L, 1L, 1L, 1L);
            assertThat(assetCounts(session, "​⁠ㅤ")).as("숨은 문자만 = 조건 없음").containsExactly(2L, 2L, 2L, 2L);
        }
    }

    @Test
    void assetLongerThan100Utf16UnitsIsRejectedOnAllFourPaths() throws Exception {
        String ok = "😀".repeat(50);          // 100 UTF-16 단위
        String tooLong = "😀".repeat(50) + "x"; // 101
        List<Function<String, MockHttpServletRequestBuilder>> paths = List.of(
                a -> get("/api/incidents/queue").param("captureId", CAP).param("period", "all").param("asset", a),
                a -> get("/api/incidents").param("captureId", CAP).param("asset", a),
                a -> get("/api/incidents/queue/new-count").param("captureId", CAP).param("since", "2000-01-01T00:00:00Z").param("asset", a),
                a -> get("/api/incidents/queue/neighbors").param("jobId", String.valueOf(JOB)).param("queueRank", "1")
                        .param("captureId", CAP).param("period", "all").param("asset", a));
        for (Function<String, MockHttpServletRequestBuilder> path : paths) {
            mockMvc.perform(path.apply(ok).session(analyst)).andExpect(status().isOk());
            mockMvc.perform(path.apply(tooLong).session(analyst))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        }
    }

    @Test
    void hostRiskQueryUsesTheSameNormalization() throws Exception {
        for (MockHttpSession session : List.of(analyst, viewer)) {
            assertThat(json(session, get("/api/hosts").param("captureId", CAP).param("period", "all")
                    .param("q", "ＷＥＢ-server")).get("total").asLong()).isEqualTo(1L);
            assertThat(json(session, get("/api/hosts").param("captureId", CAP).param("period", "all")
                    .param("q", "​​")).get("total").asLong()).isEqualTo(2L);
        }
    }

    /* ───────────────────────── 감사 로그 ───────────────────────── */

    @Test
    void auditActorSearchTreatsWildcardsAndBackslashLiterallyAndRejectsLongQueries() throws Exception {
        for (String name : List.of("t63pct%x", "t63pctAx", "t63und_x", "t63undYx", "t63bs\\x", "t63bsx")) {
            loginFails(name);
        }
        assertThat(actors("pct%x")).containsOnly("t63pct%x");
        assertThat(actors("und_x")).containsOnly("t63und_x");
        assertThat(actors("bs\\x")).containsOnly("t63bs\\x");
        mockMvc.perform(get("/api/admin/audit-logs").param("actorUsername", "a".repeat(100)).session(admin))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/audit-logs").param("actorUsername", "a".repeat(101)).session(admin))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    private List<String> actors(String query) throws Exception {
        JsonNode logs = json(admin, get("/api/admin/audit-logs").param("actorUsername", query).param("limit", "500")).get("logs");
        List<String> out = new ArrayList<>();
        logs.forEach(l -> out.add(l.get("actorUsername").asText()));
        return out;
    }

    @Test
    void auditColumnTruncationNeverLeavesHalfASurrogatePair() throws Exception {
        String actor = "q".repeat(99) + "😀tail"; // 쌍이 100번째 자리에 걸친다
        loginFails(actor);
        String capture = "zz" + "c".repeat(125) + "😀"; // 쌍이 128번째 자리에 걸친다
        mockMvc.perform(get("/api/incidents/queue").param("captureId", capture).session(viewer)).andExpect(status().isForbidden());

        List<String> actors = appJdbc.queryForList(
                "SELECT actor_username FROM audit_logs WHERE actor_username LIKE ?", String.class, "q".repeat(99) + "%");
        assertThat(actors).isNotEmpty().allSatisfy(a -> {
            assertThat(a.length()).isLessThanOrEqualTo(100);
            assertThat(hasLoneSurrogate(a)).as("반쪽 서러게이트").isFalse();
        });
        List<String> captures = appJdbc.queryForList(
                "SELECT target_capture_id FROM audit_logs WHERE target_capture_id LIKE ?", String.class, "zzccc%");
        assertThat(captures).isNotEmpty().allSatisfy(c -> {
            assertThat(c.length()).isLessThanOrEqualTo(128);
            assertThat(hasLoneSurrogate(c)).as("반쪽 서러게이트").isFalse();
        });
    }

    private static boolean hasLoneSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    return true;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return true;
            }
        }
        return false;
    }

    /* ───────────────────────── 서버 로그 ───────────────────────── */

    @Test
    void reviewDecisionAndTransitionLogsCannotForgeLogLines(CapturedOutput output) throws Exception {
        // 검토 결정: 요청 본문의 incidentId(없는 대상 → SQLSTATE 02000 경로가 찍는다)
        Cookie csrf = csrf();
        mockMvc.perform(post("/api/reviews/decide").session(analyst).cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("jobId", JOB,
                                "incidentId", "t63-missing\nFAKE-REVIEW-LINE ‮", "action", "confirm"))))
                .andExpect(status().isNotFound());
        // 상태 전이: 이미 분석 중인 건을 다시 분석 중으로(SQLSTATE 22023 경로가 사용자 이름을 찍는다)
        MockHttpSession logActor = login(LOG_ACTOR);
        Cookie csrf2 = csrf();
        mockMvc.perform(post("/api/incidents/" + JOB + "/rank/1/transition").session(logActor).cookie(csrf2)
                        .header("X-XSRF-TOKEN", csrf2.getValue()).contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("toStatus", "investigating", "reason", "t63"))))
                .andExpect(status().isConflict());

        String all = output.getAll();
        assertThat(all).contains("t63-missing[U+000A]FAKE-REVIEW-LINE [U+202E]");
        assertThat(all).contains("t63_log[U+000A]FAKE-ACTOR-LINE");
        assertThat(all.lines()).noneMatch(line -> line.startsWith("FAKE-REVIEW-LINE") || line.startsWith("FAKE-ACTOR-LINE"));
    }

    /* ───────────────────────── 요청 ───────────────────────── */

    private JsonNode json(MockHttpSession session, MockHttpServletRequestBuilder request) throws Exception {
        MvcResult res = mockMvc.perform(request.session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(res.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private Cookie csrf() throws Exception {
        return mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn()
                .getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession login(String username) throws Exception {
        Cookie csrf = csrf();
        MvcResult result = mockMvc.perform(post("/api/auth/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private MockHttpSession loginAdmin(String username) throws Exception {
        Cookie csrf = csrf();
        MockHttpSession session = login(username);
        String code = totpService.generateCode(ADMIN_SECRET, clock.instant());
        mockMvc.perform(post("/api/auth/totp/verify").session(session).cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());
        return session;
    }

    private void loginFails(String username) throws Exception {
        Cookie csrf = csrf();
        mockMvc.perform(post("/api/auth/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, "wrong-password"))));
    }

    private DashboardUser createUserOnce(String username, UserRole role, String patterns) {
        DashboardUser existing = userMapper.findByUsername(username);
        if (existing != null) {
            return existing;
        }
        return userAdminService.createUser(username, username, PASSWORD, role, patterns, "seed", "ADMIN", "127.0.0.1");
    }
}
