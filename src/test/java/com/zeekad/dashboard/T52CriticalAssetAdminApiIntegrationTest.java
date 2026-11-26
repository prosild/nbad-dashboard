package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T52 중요 자산 관리자 API(H2 + MockMvc): 목록·추가·고치기·지우기(POST …/{id}/delete), 감사 CRITICAL_ASSET_CHANGE(같은 트랜잭션),
 * 주소 검증(IPv4 하나의 정확한 꼴만), 같은 주소 409, 200개 상한, 분석가·조회자 403, CSRF, 화면 경로.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T52CriticalAssetAdminApiIntegrationTest {

    private static final String BASE = "/api/admin/critical-assets";
    private static final String TOTP_SECRET = "JBSWY3DPEHPK3PXP";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private UserMapper userMapper;
    @Autowired private TotpService totpService;
    @Autowired private Clock clock;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;
    @MockitoSpyBean private AuditService auditService;

    private static int seq = 0;
    private Cookie csrf;

    @BeforeEach
    void setUp() throws Exception {
        app().update("DELETE FROM critical_assets");
        csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
    }

    @AfterEach
    void cleanup() {
        app().update("DELETE FROM critical_assets");
        Mockito.reset(auditService);
    }

    @Test
    void adminListsCreatesUpdatesAndDeletesWithAuditRows() throws Exception {
        Session admin = adminSession();

        JsonNode empty = json(mockMvc.perform(get(BASE).session(admin.session())).andExpect(status().isOk()).andReturn());
        assertThat(empty.path("items")).isEmpty();
        assertThat(empty.path("limit").asInt()).isEqualTo(200);

        // 추가: 201, 이름·설명의 앞뒤 공백은 지운다
        JsonNode created = json(mockMvc.perform(write(post(BASE), admin, Map.of(
                        "hostIp", "10.10.0.20", "name", "  실습망 대상 서버 ", "description", " SSH·HTTP ")))
                .andExpect(status().isCreated()).andReturn());
        JsonNode item = created.path("item");
        long id = item.path("id").asLong();
        assertThat(item.path("hostIp").asText()).isEqualTo("10.10.0.20");
        assertThat(item.path("name").asText()).isEqualTo("실습망 대상 서버");
        assertThat(item.path("description").asText()).isEqualTo("SSH·HTTP");
        assertThat(item.path("createdBy").asText()).isEqualTo(admin.username());
        assertThat(item.path("updatedBy").asText()).isEqualTo(admin.username());
        assertThat(created.path("message").asText()).isNotBlank();

        // 설명 없이 하나 더
        mockMvc.perform(write(post(BASE), admin, mapOf("hostIp", "192.168.10.3", "name", "도메인 서버", "description", null)))
                .andExpect(status().isCreated());
        JsonNode list = json(mockMvc.perform(get(BASE).session(admin.session())).andExpect(status().isOk()).andReturn());
        assertThat(list.path("items")).hasSize(2);

        // 고치기: 이름·설명만(본문의 주소는 무시한다. 주소를 바꾸려면 지우고 새로 만든다)
        JsonNode updated = json(mockMvc.perform(write(put(BASE + "/" + id), admin, Map.of(
                        "hostIp", "10.10.0.99", "name", "대상 서버(별칭 포함)", "description", "")))
                .andExpect(status().isOk()).andReturn());
        assertThat(updated.path("item").path("hostIp").asText()).isEqualTo("10.10.0.20");
        assertThat(updated.path("item").path("name").asText()).isEqualTo("대상 서버(별칭 포함)");
        assertThat(updated.path("item").path("description").isNull()).isTrue();
        assertThat(app().queryForObject("SELECT COUNT(*) FROM critical_assets WHERE host_ip = '10.10.0.99'", Long.class)).isZero();

        // 지우기: POST …/{id}/delete(본문 없음)
        mockMvc.perform(write(post(BASE + "/" + id + "/delete"), admin, null)).andExpect(status().isOk());
        assertThat(app().queryForObject("SELECT COUNT(*) FROM critical_assets WHERE id = ?", Long.class, id)).isZero();
        // 없는 ID는 404
        mockMvc.perform(write(post(BASE + "/" + id + "/delete"), admin, null)).andExpect(status().isNotFound());
        mockMvc.perform(write(put(BASE + "/" + id), admin, Map.of("name", "x"))).andExpect(status().isNotFound());

        // 감사: 변경마다 한 행, detail {operation, hostIp, name}
        List<Map<String, Object>> audits = app().queryForList(
                "SELECT actor_username, actor_role, detail_json FROM audit_logs WHERE action_type = 'CRITICAL_ASSET_CHANGE' "
                        + "AND actor_username = ? ORDER BY id", admin.username());
        assertThat(audits).hasSize(4);
        assertAudit(audits.get(0), admin.username(), "CREATE", "10.10.0.20", "실습망 대상 서버");
        assertAudit(audits.get(1), admin.username(), "CREATE", "192.168.10.3", "도메인 서버");
        assertAudit(audits.get(2), admin.username(), "UPDATE", "10.10.0.20", "대상 서버(별칭 포함)");
        assertAudit(audits.get(3), admin.username(), "DELETE", "10.10.0.20", "대상 서버(별칭 포함)");

        // 감사 로그 화면의 유형 목록에 새 유형이 있다
        JsonNode logs = json(mockMvc.perform(get("/api/admin/audit-logs").param("actionType", "CRITICAL_ASSET_CHANGE")
                .session(admin.session())).andExpect(status().isOk()).andReturn());
        assertThat(logs.path("actionTypes").toString()).contains("CRITICAL_ASSET_CHANGE");
    }

    @Test
    void addressMustBeOneExactIpv4AndFieldsAreBounded() throws Exception {
        Session admin = adminSession();
        List<String> badAddresses = List.of(
                "10.0.0.0/24",        // 대역
                "10.0.0.1-10.0.0.9",  // 범위
                "10.0.0.*",           // 가린 꼴
                "::1",                // IPv6
                "fe80::1",
                "256.1.1.1",          // 범위 밖 옥텟
                "10.0.0.300",
                "010.1.1.1",          // 앞자리 0
                "10.01.1.1",
                "10.0.0.1\n",         // 줄바꿈
                "10.0.0.1\r",
                " 10.0.0.1",          // 앞뒤 공백
                "10.0.0.1 ",
                "١٠.0.0.1", // ASCII가 아닌 숫자
                "１０.0.0.1",
                "server.local",       // 호스트 이름(이름을 풀어 보지 않는다)
                "localhost",
                "10.0.0",
                "10.0.0.1.5",
                "");
        for (String bad : badAddresses) {
            MvcResult r = mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", bad, "name", "x")))
                    .andExpect(status().isBadRequest()).andReturn();
            assertThat(json(r).path("code").asText()).as("주소 [%s]", bad).isEqualTo("INVALID_REQUEST");
        }
        mockMvc.perform(write(post(BASE), admin, mapOf("hostIp", null, "name", "x"))).andExpect(status().isBadRequest());
        // 이름: 필수, 100자(코드 포인트) 이하, 제어 문자 없음. 설명: 300자 이하
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.0.0.1", "name", "   "))).andExpect(status().isBadRequest());
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.0.0.1", "name", "가".repeat(101))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.0.0.1", "name", "줄\n바꿈")))
                .andExpect(status().isBadRequest());
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.0.0.1", "name", "x", "description", "나".repeat(301))))
                .andExpect(status().isBadRequest());
        assertThat(count()).isZero();
        assertThat(app().queryForObject("SELECT COUNT(*) FROM audit_logs WHERE action_type = 'CRITICAL_ASSET_CHANGE' "
                + "AND actor_username = ?", Long.class, admin.username())).isZero();

        // 경계 값은 받는다: 0, 255, 100자 이름(보조 평면 글자 포함), 300자 설명
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "0.0.0.0", "name", "가".repeat(100))))
                .andExpect(status().isCreated());
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "255.255.255.255", "name", "😀".repeat(100),
                        "description", "나".repeat(300))))
                .andExpect(status().isCreated());
        assertThat(count()).isEqualTo(2L);
    }

    @Test
    void duplicateAddressIs409AndListIsCappedAt200() throws Exception {
        Session admin = adminSession();
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.10.0.10", "name", "배포 서버")))
                .andExpect(status().isCreated());
        MvcResult dup = mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.10.0.10", "name", "다른 이름")))
                .andExpect(status().isConflict()).andReturn();
        assertThat(json(dup).path("code").asText()).isEqualTo("CRITICAL_ASSET_EXISTS");
        assertThat(app().queryForObject("SELECT name FROM critical_assets WHERE host_ip = '10.10.0.10'", String.class))
                .isEqualTo("배포 서버");

        // 200개까지 받는다(199개를 더 채우고 마지막 하나는 API로)
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        for (int i = 1; i <= 198; i++) {
            app().update("INSERT INTO critical_assets (host_ip, name, description, created_by, created_at, updated_by, updated_at) "
                    + "VALUES (?, ?, NULL, 't52', ?, 't52', ?)", "10.200." + (i / 250) + "." + (i % 250), "n" + i, now, now);
        }
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.201.0.1", "name", "200번째")))
                .andExpect(status().isCreated());
        assertThat(count()).isEqualTo(200L);
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.201.0.2", "name", "201번째")))
                .andExpect(status().isBadRequest());
        assertThat(count()).isEqualTo(200L);
        JsonNode list = json(mockMvc.perform(get(BASE).session(admin.session())).andExpect(status().isOk()).andReturn());
        assertThat(list.path("items")).hasSize(200);
    }

    @Test
    void auditFailureRollsBackTheChange() throws Exception {
        Session admin = adminSession();
        Mockito.doThrow(new IllegalStateException("감사 기록 실패(시험)"))
                .when(auditService).record(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(),
                        ArgumentMatchers.eq(AuditActionType.valueOf("CRITICAL_ASSET_CHANGE")),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.10.0.21", "name", "별칭")))
                .andExpect(status().isInternalServerError());
        assertThat(count()).isZero();
    }

    @Test
    void analystAndViewerAreForbiddenAndNothingChanges() throws Exception {
        Session admin = adminSession();
        mockMvc.perform(write(post(BASE), admin, Map.of("hostIp", "10.10.0.20", "name", "대상 서버")))
                .andExpect(status().isCreated());
        long id = app().queryForObject("SELECT id FROM critical_assets WHERE host_ip = '10.10.0.20'", Long.class);
        String before = snapshot();

        for (UserRole role : new UserRole[]{UserRole.ANALYST, UserRole.VIEWER}) {
            Session user = userSession(role);
            mockMvc.perform(get(BASE).session(user.session())).andExpect(status().isForbidden());
            mockMvc.perform(write(post(BASE), user, Map.of("hostIp", "10.10.0.30", "name", "x"))).andExpect(status().isForbidden());
            mockMvc.perform(write(put(BASE + "/" + id), user, Map.of("name", "바뀜"))).andExpect(status().isForbidden());
            mockMvc.perform(write(post(BASE + "/" + id + "/delete"), user, null)).andExpect(status().isForbidden());
            // 화면 경로도 사용자 관리와 같게 막힌다
            int usersPage = mockMvc.perform(get("/admin/users").session(user.session())).andReturn().getResponse().getStatus();
            int assetsPage = mockMvc.perform(get("/admin/critical-assets").session(user.session())).andReturn().getResponse().getStatus();
            assertThat(assetsPage).as("%s 화면 경로", role).isEqualTo(usersPage).isEqualTo(403);
        }
        assertThat(snapshot()).isEqualTo(before);

        // 쓰기는 CSRF가 필요하다(관리자라도)
        mockMvc.perform(post(BASE).session(admin.session()).contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("hostIp", "10.10.0.31", "name", "x"))))
                .andExpect(status().isForbidden());
        mockMvc.perform(post(BASE + "/" + id + "/delete").session(admin.session())).andExpect(status().isForbidden());
        assertThat(snapshot()).isEqualTo(before);

        // 관리자는 화면 경로를 셸로 받는다
        mockMvc.perform(get("/admin/critical-assets").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));
    }

    /* ───────────── 도우미 ───────────── */

    private record Session(MockHttpSession session, String username) {
    }

    private void assertAudit(Map<String, Object> row, String actor, String operation, String hostIp, String name) throws Exception {
        assertThat(row.get("actor_username")).isEqualTo(actor);
        assertThat(row.get("actor_role")).isEqualTo("ADMIN");
        JsonNode detail = objectMapper.readTree(String.valueOf(row.get("detail_json")));
        assertThat(detail.path("operation").asText()).isEqualTo(operation);
        assertThat(detail.path("hostIp").asText()).isEqualTo(hostIp);
        assertThat(detail.path("name").asText()).isEqualTo(name);
    }

    private String snapshot() {
        return app().queryForList("SELECT id, host_ip, name, description, updated_by FROM critical_assets ORDER BY id").toString();
    }

    private long count() {
        return app().queryForObject("SELECT COUNT(*) FROM critical_assets", Long.class);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private MockHttpServletRequestBuilder write(MockHttpServletRequestBuilder b, Session s, Object body) throws Exception {
        b.session(s.session()).cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        if (body != null) {
            b.contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        }
        return b;
    }

    private JsonNode json(MvcResult r) throws Exception {
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private Session adminSession() throws Exception {
        String username = "t52adm_" + (++seq) + "_" + System.nanoTime() % 100000;
        DashboardUser admin = userAdminService.createUser(username, "자산 관리자", "AdminPass!88", UserRole.ADMIN, "*",
                "seed", "ADMIN", "127.0.0.1");
        userMapper.updateTotpState(admin.getId(), TOTP_SECRET, true, OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        MockHttpSession session = login(username, "AdminPass!88");
        String code = totpService.generateCode(TOTP_SECRET, clock.instant());
        mockMvc.perform(post("/api/auth/totp/verify")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());
        return new Session(session, username);
    }

    private Session userSession(UserRole role) throws Exception {
        String username = "t52usr_" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "사용자", "Pass1234!", role, "*", "seed", "ADMIN", "127.0.0.1");
        return new Session(login(username, "Pass1234!"), username);
    }

    private MockHttpSession login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
