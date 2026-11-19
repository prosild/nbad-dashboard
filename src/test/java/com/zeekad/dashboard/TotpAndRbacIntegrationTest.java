package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TotpAndRbacIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Test
    void adminMustSetupAndVerifyTotpBeforeAccessingAdminOrProtectedRoutes() throws Exception {
        String adminUsername = "totp_admin_1";
        userAdminService.createUser(adminUsername, "TOTP관리자", "AdminPass!88", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");

        DashboardUser adminBefore = userMapper.findByUsername(adminUsername);
        assertThat(adminBefore.isTotpEnabled()).isFalse();
        assertThat(adminBefore.getTotpSecret()).isNotBlank();

        // ensureSecret DB 저장 검증을 위해 totp_secret 을 null 로 초기화 후 /api/auth/totp/setup 조회
        userMapper.updateTotpState(adminBefore.getId(), null, false,
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        // 1차 로그인 -> 미등록이므로 nextRoute=/login/totp/setup 반환
        Cookie loginCsrf = fetchCsrfCookie();
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .cookie(loginCsrf)
                        .header("X-XSRF-TOKEN", loginCsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(adminUsername, "AdminPass!88"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.nextRoute").value("/login/totp/setup"))
                .andExpect(jsonPath("$.user.totpRequired").value(true))
                .andExpect(jsonPath("$.user.totpVerified").value(false))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // TOTP 미검증 상태에서 API는 403 JSON(TOTP_SETUP_REQUIRED), 비-API는 리다이렉트
        mockMvc.perform(get("/api/admin/users").session(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.code").value("TOTP_SETUP_REQUIRED"));
        mockMvc.perform(get("/api/incidents").session(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("TOTP_SETUP_REQUIRED"));
        mockMvc.perform(get("/admin/users").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp/setup"));

        // GET /api/auth/totp/setup 조회 시 새 시크릿 생성 및 DB 저장 확인
        mockMvc.perform(get("/api/auth/totp/setup").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpauthUri").value(startsWith("otpauth://totp/")))
                .andExpect(jsonPath("$.accountName").value(adminUsername));

        DashboardUser ensuredUser = userMapper.findByUsername(adminUsername);
        assertThat(ensuredUser.getTotpSecret()).isNotBlank();

        // 잘못된 6자리 코드 입력 시 400 Bad Request
        Cookie csrf = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest("000000"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));

        // 유효한 6자리 코드 입력 시 활성화 완료 및 TOTP_VERIFIED 로그 기록
        String validCode = totpService.generateCode(ensuredUser.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(validCode))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andExpect(jsonPath("$.user.totpEnabled").value(true))
                .andExpect(jsonPath("$.user.totpVerified").value(true));

        DashboardUser adminAfter = userMapper.findByUsername(adminUsername);
        assertThat(adminAfter.isTotpEnabled()).isTrue();

        // 이미 등록된 상태에서 GET /api/auth/totp/setup 재호출 시 409 Conflict
        mockMvc.perform(get("/api/auth/totp/setup").session(session))
                .andExpect(status().isConflict());

        // 이제 /api/admin/users 접근 가능
        mockMvc.perform(get("/api/admin/users").session(session))
                .andExpect(status().isOk());

        // 재로그인 시 이제 nextRoute=/login/totp 반환
        Cookie secondCsrf = fetchCsrfCookie();
        MvcResult secondLogin = mockMvc.perform(post("/api/auth/login")
                        .cookie(secondCsrf)
                        .header("X-XSRF-TOKEN", secondCsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(adminUsername, "AdminPass!88"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nextRoute").value("/login/totp"))
                .andReturn();

        MockHttpSession secondSession = (MockHttpSession) secondLogin.getRequest().getSession(false);
        mockMvc.perform(get("/api/admin/audit-logs").session(secondSession))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("TOTP_VERIFICATION_REQUIRED"));
        mockMvc.perform(get("/admin/audit-logs").session(secondSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp"));

        String secondCode = totpService.generateCode(adminAfter.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/api/auth/totp/verify")
                        .session(secondSession)
                        .cookie(secondCsrf)
                        .header("X-XSRF-TOKEN", secondCsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(secondCode))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andExpect(jsonPath("$.user.totpVerified").value(true));

        mockMvc.perform(get("/api/admin/audit-logs").session(secondSession))
                .andExpect(status().isOk());

        List<AuditLog> totpLogs = auditLogMapper.findFiltered(AuditActionType.TOTP_VERIFIED.name(), adminUsername, 10);
        assertThat(totpLogs).hasSize(2);
    }

    @Test
    void viewerAndAnalystReceive403ForbiddenOnAdminRoutes() throws Exception {
        String viewer = "rbac_viewer_1";
        String analyst = "rbac_analyst_1";
        userAdminService.createUser(viewer, "권한조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(analyst, "권한분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");
        mockMvc.perform(get("/api/admin/users").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/audit-logs").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/users").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/auth/totp/setup").session(viewerSession))
                .andExpect(status().isForbidden());

        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");
        mockMvc.perform(get("/api/admin/users").session(analystSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/audit-logs").session(analystSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/audit-logs").session(analystSession))
                .andExpect(status().isForbidden());
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        Cookie csrfCookie = fetchCsrfCookie();
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
