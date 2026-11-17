package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.SessionAttributes;
import com.zeekad.dashboard.service.UserAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityAuthSessionTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private ServerProperties serverProperties;

    @Test
    void loginRegeneratesSessionIdStoresBcryptAndEnforcesTimeoutsAndCsrf() throws Exception {
        String username = "auth_viewer_1";
        userAdminService.createUser(username, "인증조회자", "ValidPass!99", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        DashboardUser created = userMapper.findByUsername(username);
        assertThat(created.getPasswordHash()).startsWith("$2");
        assertThat(created.getPasswordHash()).doesNotContain("ValidPass!99");

        // CSRF 누락 시 POST 차단
        mockMvc.perform(post("/login")
                        .param("username", username)
                        .param("password", "ValidPass!99"))
                .andExpect(status().isForbidden());

        // 로그인 전 세션 생성 후 로그인 시 세션 ID 재발급 검증
        MockHttpSession preLoginSession = new MockHttpSession();
        String sessionIdBefore = preLoginSession.getId();

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(preLoginSession)
                        .with(csrf())
                        .param("username", username)
                        .param("password", "ValidPass!99"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andReturn();

        MockHttpSession authedSession = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(authedSession).isNotNull();
        assertThat(authedSession.getId()).isNotEqualTo(sessionIdBefore);

        List<AuditLog> successLogs = auditLogMapper.findFiltered(AuditActionType.LOGIN_SUCCESS.name(), username, 10);
        assertThat(successLogs).isNotEmpty();

        // 정상 세션으로 홈 접근
        mockMvc.perform(get("/").session(authedSession))
                .andExpect(status().isOk());

        // 유휴 만료(30분 초과) 시 세션 무효화 및 로그인 리다이렉트
        authedSession.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT,
                Instant.now().minusSeconds(31 * 60L).toEpochMilli());
        mockMvc.perform(get("/").session(authedSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?expired"));
        assertThat(authedSession.isInvalid()).isTrue();

        // 재로그인 후 절대 만료(8시간 초과) 시 세션 무효화
        MvcResult reloginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", "ValidPass!99"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        MockHttpSession secondSession = (MockHttpSession) reloginResult.getRequest().getSession(false);
        assertThat(secondSession).isNotNull();
        secondSession.setAttribute(SessionAttributes.SESSION_CREATED_AT,
                Instant.now().minusSeconds(8 * 60 * 60L + 60L).toEpochMilli());
        mockMvc.perform(get("/").session(secondSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?expired"));
        assertThat(secondSession.isInvalid()).isTrue();

        // 세션 쿠키 보안 설정 확인
        assertThat(serverProperties.getServlet().getSession().getCookie().getHttpOnly()).isTrue();
        assertThat(serverProperties.getServlet().getSession().getCookie().getSameSite().name()).isEqualTo("LAX");
    }

    @Test
    void fiveConsecutiveFailuresLockAccountAndRecordAuditLogs() throws Exception {
        String username = "lock_analyst_1";
        userAdminService.createUser(username, "잠금분석가", "SecretPass!77", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        for (int i = 1; i <= 4; i++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .param("username", username)
                            .param("password", "WrongPass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }

        // 5번째 실패에서 계정 잠금
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", "WrongPass"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?locked"));

        DashboardUser locked = userMapper.findByUsername(username);
        assertThat(locked.getFailedAttempts()).isEqualTo(5);
        assertThat(locked.getLockedUntil()).isNotNull();

        List<AuditLog> lockLogs = auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), username, 10);
        assertThat(lockLogs).hasSize(1);
        List<AuditLog> failLogs = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), username, 10);
        assertThat(failLogs).hasSize(5);

        // 잠금 상태에서는 올바른 비밀번호로도 로그인 차단
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", "SecretPass!77"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?locked"));
    }
}
