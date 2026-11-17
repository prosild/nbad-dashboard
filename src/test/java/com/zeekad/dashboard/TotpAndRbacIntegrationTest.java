package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TotpAndRbacIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

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

        // 1차 로그인 -> 미등록이므로 /login/totp/setup 리다이렉트
        MvcResult loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", adminUsername)
                        .param("password", "AdminPass!88"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp/setup"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // TOTP 미검증 상태에서 /admin/users 및 / 접근 차단
        mockMvc.perform(get("/admin/users").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp/setup"));
        mockMvc.perform(get("/").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp/setup"));

        // 설정 페이지에 시크릿 및 otpauth URI 표시
        mockMvc.perform(get("/login/totp/setup").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(adminBefore.getTotpSecret())))
                .andExpect(content().string(containsString("otpauth://totp/")));

        // 잘못된 6자리 코드 입력 시 실패
        mockMvc.perform(post("/login/totp/setup")
                        .session(session)
                        .with(csrf())
                        .param("code", "000000"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("인증 코드가 올바르지 않습니다")));

        // 유효한 6자리 코드 입력 시 활성화 완료 및 TOTP_VERIFIED 로그 기록
        String validCode = totpService.generateCode(adminBefore.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/login/totp/setup")
                        .session(session)
                        .with(csrf())
                        .param("code", validCode))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));

        DashboardUser adminAfter = userMapper.findByUsername(adminUsername);
        assertThat(adminAfter.isTotpEnabled()).isTrue();

        // 이제 /admin/users 접근 가능
        mockMvc.perform(get("/admin/users").session(session))
                .andExpect(status().isOk());

        // 재로그인 시 이제 /login/totp 로 이동
        MvcResult secondLogin = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", adminUsername)
                        .param("password", "AdminPass!88"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp"))
                .andReturn();

        MockHttpSession secondSession = (MockHttpSession) secondLogin.getRequest().getSession(false);
        mockMvc.perform(get("/admin/audit-logs").session(secondSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp"));

        String secondCode = totpService.generateCode(adminAfter.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/login/totp")
                        .session(secondSession)
                        .with(csrf())
                        .param("code", secondCode))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));

        mockMvc.perform(get("/admin/audit-logs").session(secondSession))
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
        mockMvc.perform(get("/admin/users").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/audit-logs").session(viewerSession))
                .andExpect(status().isForbidden());

        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");
        mockMvc.perform(get("/admin/users").session(analystSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/audit-logs").session(analystSession))
                .andExpect(status().isForbidden());
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
