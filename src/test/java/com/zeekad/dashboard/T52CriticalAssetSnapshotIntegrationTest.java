package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.CriticalAssetMapper;
import com.zeekad.dashboard.model.CriticalAsset;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.CriticalAssetService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import com.zeekad.dashboard.testsupport.T51QueueSeed;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T52 중요 자산 스냅샷: 요청 하나에 앱 DB의 자산 목록을 한 번만 읽고, 우선순위 식(주소 배열)과 이름에 같은 것을 쓴다.
 * 읽는 사이에 관리자가 목록을 바꿔도(여기서는 첫 읽기 뒤 바로 지운다) 한 응답 안의 표지·우선순위·이름이 어긋나지 않는다.
 * 동시 추가가 UNIQUE에 걸린 경우(확인 뒤 넣기 전에 다른 요청이 넣음)는 500이 아니라 409다.
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t52s_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t52s_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t52s_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T52CriticalAssetSnapshotIntegrationTest {

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
    @Autowired private CriticalAssetService criticalAssetService;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;
    @MockitoSpyBean private CriticalAssetMapper criticalAssetMapper;

    private static int seq = 0;

    @BeforeEach
    void setUp() {
        clock.set(T51QueueSeed.NOW);
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        T52CriticalAssetPriorityIntegrationTest.deleteOwnRows(jdbc);
        T52CriticalAssetPriorityIntegrationTest.insertScreenRows(jdbc);
        app().update("DELETE FROM critical_assets");
        app().update("INSERT INTO critical_assets (host_ip, name, description, created_by, created_at, updated_by, updated_at) "
                + "VALUES (?, '결제 서버', '설명', 't52', TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z', 't52', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z')", T52CriticalAssetPriorityIntegrationTest.CRITICAL_HOST);
        Mockito.clearInvocations(criticalAssetMapper);
    }

    @AfterEach
    void cleanup() {
        Mockito.reset(criticalAssetMapper);
        app().update("DELETE FROM critical_assets");
        T52CriticalAssetPriorityIntegrationTest.deleteOwnRows(new JdbcTemplate(zeekadReadDataSource));
    }

    @Test
    void everyIncidentEndpointReadsTheAssetListOnce() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST);
        long job = T52CriticalAssetPriorityIntegrationTest.SCREEN_JOB;
        List<String> urls = List.of(
                "/api/incidents/queue?period=all",
                "/api/incidents/queue?period=24h&priority=high",
                "/api/incidents/queue?period=all&asset=10.52",
                "/api/incidents/queue/new-count?since=2026-01-01T00:00:00Z",
                "/api/incidents/queue/neighbors?period=all&jobId=" + job + "&queueRank=2",
                "/api/incidents/" + job + "/rank/1",
                "/api/incidents/" + job + "/rank/2/related-host-incidents",
                "/api/hosts?period=all",
                "/api/dashboard/overview?period=all",
                "/api/operations");
        for (String url : urls) {
            Mockito.clearInvocations(criticalAssetMapper);
            getBody(analyst, url);
            Mockito.verify(criticalAssetMapper, Mockito.times(1).description(url)).findHostNames();
            // 인시던트 응답 경로는 설명이 든 목록을 읽지 않는다
            Mockito.verify(criticalAssetMapper, Mockito.never().description(url)).findAll();
        }
    }

    @Test
    void aChangeDuringTheRequestDoesNotSplitOneResponse() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST);
        // 첫 읽기가 끝나면 곧바로 목록을 비운다(관리자가 그 사이 지운 경우). 같은 요청 안에서 다시 읽으면 이름이 빠지거나 표지가 어긋난다
        AtomicInteger reads = new AtomicInteger();
        Mockito.doAnswer(inv -> {
            List<CriticalAsset> rows = new ArrayList<>();
            for (java.util.Map<String, Object> r : app().queryForList("SELECT id, host_ip, name FROM critical_assets ORDER BY id")) {
                CriticalAsset asset = new CriticalAsset();
                asset.setId(((Number) r.get("id")).longValue());
                asset.setHostIp((String) r.get("host_ip"));
                asset.setName((String) r.get("name"));
                rows.add(asset);
            }
            if (reads.getAndIncrement() == 0) {
                app().update("DELETE FROM critical_assets");
            }
            return rows;
        }).when(criticalAssetMapper).findHostNames();

        JsonNode queue = objectMapper.readTree(getBody(analyst, "/api/incidents/queue?period=all&size=100"));
        JsonNode a = null;
        for (JsonNode it : queue.path("items")) {
            if (T52CriticalAssetPriorityIntegrationTest.A.equals(it.path("incidentId").asText())) a = it;
        }
        assertThat(a).isNotNull();
        assertThat(a.path("assetCritical").asBoolean()).isTrue();
        assertThat(a.path("priority").asText()).isEqualTo("high");
        assertThat(a.path("criticalAssetName").asText()).isEqualTo("결제 서버");
        assertThat(queue.path("summary").path("high").asLong()).isEqualTo(1L);
        assertThat(reads.get()).isEqualTo(1);
        // 다음 요청은 바뀐 목록(빈 목록)을 본다(캐시 없음)
        JsonNode next = objectMapper.readTree(getBody(analyst, "/api/incidents/queue?period=all&size=100"));
        assertThat(next.path("summary").path("high").asLong()).isZero();
    }

    @Test
    void uniqueViolationAfterTheCheckIs409NotA500() {
        // 확인(findByHostIp)이 비어 있다고 본 뒤 다른 요청이 같은 주소를 먼저 넣은 경우
        Mockito.doReturn(null).when(criticalAssetMapper).findByHostIp(T52CriticalAssetPriorityIntegrationTest.CRITICAL_HOST);
        assertThatThrownBy(() -> criticalAssetService.create(T52CriticalAssetPriorityIntegrationTest.CRITICAL_HOST, "다른 이름",
                null, "t52", "ADMIN", "127.0.0.1"))
                .isInstanceOfSatisfying(com.zeekad.dashboard.service.CriticalAssetException.class, e -> {
                    assertThat(e.getStatus()).isEqualTo(409);
                    assertThat(e.getCode()).isEqualTo("CRITICAL_ASSET_EXISTS");
                });
        assertThat(app().queryForObject("SELECT name FROM critical_assets WHERE host_ip = ?", String.class,
                T52CriticalAssetPriorityIntegrationTest.CRITICAL_HOST)).isEqualTo("결제 서버");
        assertThat(app().queryForObject("SELECT COUNT(*) FROM audit_logs WHERE action_type = 'CRITICAL_ASSET_CHANGE' "
                + "AND actor_username = 't52'", Long.class)).isZero();
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private MockHttpSession login(UserRole role) throws Exception {
        String username = "t52s_u" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role,
                T52CriticalAssetPriorityIntegrationTest.SCREEN, "seed", "ADMIN", "127.0.0.1");
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
}
