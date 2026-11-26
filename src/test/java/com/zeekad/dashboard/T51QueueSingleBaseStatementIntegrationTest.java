package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import com.zeekad.dashboard.testsupport.SqlCaptureInterceptor;
import com.zeekad.dashboard.testsupport.T51QueueSeed;
import jakarta.servlet.http.Cookie;
import org.apache.ibatis.session.SqlSessionFactory;
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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T51 인시던트 목록 요청 하나에 통합 큐 기반 SQL(표지 {@code /* unifiedQueueBase *}{@code /})이 든 문장이 한 번만 실행된다.
 * 읽기 DB의 SqlSessionFactory에 가로채기를 붙여 실행한 SQL 글의 표지를 센다(H2. 문장 수만 증명한다.
 * PostgreSQL이 그 한 문장 안에서 기반을 한 번만 계산한다는 것은 실제 스냅샷의 EXPLAIN으로 본다).
 * 자산 검색(asset) 경로와 새 건수(new-count)는 이 단언의 대상이 아니다.
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t51a_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t51a_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t51a_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T51QueueSingleBaseStatementIntegrationTest {

    static final String MARKER = "/* unifiedQueueBase */";

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(T51QueueSeed.NOW);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadSqlSessionFactory") private SqlSessionFactory readFactory;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    private static int seq = 0;
    private SqlCaptureInterceptor capture;

    @BeforeEach
    void setUp() {
        clock.set(T51QueueSeed.NOW);
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        T51QueueSeed.delete(jdbc);
        T51QueueSeed.insert(jdbc);
        capture = SqlCaptureInterceptor.attach(readFactory);
    }

    @AfterEach
    void cleanup() {
        capture.stop();
        T51QueueSeed.delete(new JdbcTemplate(zeekadReadDataSource));
    }

    @Test
    void listRequestRunsTheBaseSqlInExactlyOneStatement() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST);
        MockHttpSession viewer = login(UserRole.VIEWER);
        String q = "/api/incidents/queue?";
        List<String> urls = List.of(
                // 전체 기간
                q + "period=all",
                q + "period=all&size=25&page=3&sort=detected&dir=asc",
                // 기간이 있을 때(프리셋·지정 구간)
                q + "period=24h",
                q + "period=1h",
                q + "period=7d&size=25&page=2",
                q + "period=30d&sort=connections",
                q + "period=custom&start=2026-11-15T00:00:00Z&end=2026-11-20T13:00:00Z",
                q + "period=custom&start=2026-08-01T00:00:00Z&end=2026-08-02T00:00:00Z",
                // 띠 축 조건
                q + "period=all&priority=high",
                q + "period=24h&priority=low",
                q + "period=all&reviewPending=true",
                q + "period=all&alerted=true",
                q + "period=30d&overdue=true",
                q + "period=7d&priority=medium&alerted=true&reviewPending=true",
                // 일반 조건
                q + "period=all&status=closed",
                q + "period=all&pickedBy=iforest&role=originator&hasReport=true&wouldSend=false",
                // 가려진 대역(조회자도 걸린다. 조회자가 원문 주소를 주면 범위가 비어 기반을 부르지 않는다)
                q + "period=all&hostIp=10.51.*.*",
                q + "period=all&attack=T1059",
                q + "period=all&source=imported",
                q + "period=all&captureId=" + T51QueueSeed.LIVE,
                q + "period=all&assignee=none",
                // 범위 밖·잘못된 쪽
                q + "period=all&page=999",
                q + "period=all&page=2147483647&size=100",
                q + "period=all&page=0",
                q + "period=all&page=-3",
                q + "period=all&page=abc&size=25",
                q + "period=24h&page=999&size=7");
        Map<String, Long> counts = new LinkedHashMap<>();
        for (MockHttpSession session : List.of(analyst, viewer)) {
            for (String url : urls) {
                capture.start();
                String body = getBody(session, url);
                List<String> sqls = capture.stop();
                assertThat(objectMapper.readTree(body).has("total")).as(url).isTrue();
                assertThat(sqls).as("가로채기가 읽기 DB 문장을 본다: %s", url).isNotEmpty();
                counts.put((session == analyst ? "ANALYST " : "VIEWER ") + url, SqlCaptureInterceptor.countContaining(sqls, MARKER));
            }
        }
        assertThat(counts).as("목록 요청 하나에 기반 SQL이 든 문장 수").allSatisfy((url, n) -> assertThat(n).as(url).isEqualTo(1L));

        // 자료가 실제로 걸린다(0건만 세는 시험이 아니다)
        JsonNode all = getJson(analyst, q + "period=all");
        assertThat(all.get("total").asLong())
                .isEqualTo(T51QueueSeed.COMBINATIONS + T51QueueSeed.IMPORTED_ROWS + T51QueueSeed.NO_DETECT_ROWS);
        assertThat(getJson(analyst, q + "period=all&page=999").get("items")).isNotEmpty();
    }

    @Test
    void emptyScopeRunsNoBaseStatementAndTheCounterSeesStatementsOutsideTheListPath() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST);
        // 내 담당이 하나도 없으면 범위가 비어 기반 SQL을 부르지 않는다
        capture.start();
        JsonNode mine = getJson(analyst, "/api/incidents/queue?period=all&assignee=me");
        List<String> none = capture.stop();
        assertThat(mine.get("total").asLong()).isZero();
        assertThat(SqlCaptureInterceptor.countContaining(none, MARKER)).isZero();

        // 세는 도구 확인: 목록 밖 경로(새 건수 = 건수 + 최댓값)는 기반 문장이 둘로 잡힌다(이 단언의 대상이 아닌 경로)
        capture.start();
        JsonNode fresh = getJson(analyst, "/api/incidents/queue/new-count?since=2026-01-01T00:00:00Z");
        List<String> two = capture.stop();
        assertThat(fresh.get("count").asLong()).isPositive();
        assertThat(SqlCaptureInterceptor.countContaining(two, MARKER)).isEqualTo(2L);
    }

    private MockHttpSession login(UserRole role) throws Exception {
        String username = "t51a_u" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, T51QueueSeed.PATTERNS, "seed", "ADMIN", "127.0.0.1");
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

    private String getBody(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(URI.create(url)).session(session)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        return objectMapper.readTree(getBody(session, url));
    }
}
