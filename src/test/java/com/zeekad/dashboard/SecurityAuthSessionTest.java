package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.SessionAttributes;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityAuthSessionTest {

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
    private ServerProperties serverProperties;

    @Test
    void loginRegeneratesSessionIdRotatesCsrfEnforcesTimeoutsAndSupportsLogout() throws Exception {
        String username = "auth_viewer_1";
        userAdminService.createUser(username, "인증조회자", "ValidPass!99", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        DashboardUser created = userMapper.findByUsername(username);
        assertThat(created.getPasswordHash()).startsWith("$2");
        assertThat(created.getPasswordHash()).doesNotContain("ValidPass!99");

        // 비인증 /api/auth/me 는 200 OK { authenticated: false, user: null }
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.user").doesNotExist());

        // CSRF 발급 확인 (XSRF-TOKEN 쿠키 SameSite=Lax + JSON 토큰)
        MvcResult csrfResult = mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();

        Cookie preLoginXsrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
        assertThat(preLoginXsrfCookie).isNotNull();
        assertThat(preLoginXsrfCookie.isHttpOnly()).isFalse();
        assertThat(preLoginXsrfCookie.getAttribute("SameSite")).isEqualTo("Lax");
        String preLoginPlainToken = preLoginXsrfCookie.getValue();

        // CSRF 헤더 누락 시 403 JSON 차단
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "ValidPass!99"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        // 로그인 전 세션 생성 후 로그인 시 세션 ID 재발급 + CSRF 토큰 회전 검증 (평문 XSRF-TOKEN 헤더 사용)
        MockHttpSession preLoginSession = new MockHttpSession();
        String sessionIdBefore = preLoginSession.getId();

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .session(preLoginSession)
                        .cookie(preLoginXsrfCookie)
                        .header("X-XSRF-TOKEN", preLoginPlainToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "ValidPass!99"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.nextRoute").value("/"))
                .andExpect(jsonPath("$.user.username").value(username))
                .andExpect(jsonPath("$.user.role").value("VIEWER"))
                .andExpect(jsonPath("$.user.maskedView").value(true))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))))
                .andReturn();

        MockHttpSession authedSession = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(authedSession).isNotNull();
        assertThat(authedSession.getId()).isNotEqualTo(sessionIdBefore);

        // 로그인 응답에서 새 XSRF-TOKEN 쿠키가 회전 발급되었는지 확인
        Cookie rotatedXsrfCookie = extractLastCookie(loginResult.getResponse().getCookies(), "XSRF-TOKEN");
        assertThat(rotatedXsrfCookie).isNotNull();
        assertThat(rotatedXsrfCookie.getAttribute("SameSite")).isEqualTo("Lax");
        String rotatedXsrfValue = rotatedXsrfCookie.getValue();
        assertThat(rotatedXsrfValue).isNotBlank().isNotEqualTo(preLoginPlainToken);

        List<AuditLog> successLogs = auditLogMapper.findFiltered(AuditActionType.LOGIN_SUCCESS.name(), username, 10);
        assertThat(successLogs).isNotEmpty();

        // /api/auth/me 로 인증 사용자 정보 확인
        mockMvc.perform(get("/api/auth/me").session(authedSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.user.username").value(username))
                .andExpect(jsonPath("$.user.totpRequired").value(false))
                .andExpect(jsonPath("$.user.totpVerified").value(true));

        // 구 CSRF 토큰은 차단되고 회전된 새 XSRF-TOKEN 으로 상태 변경 요청이 통과해야 함
        mockMvc.perform(post("/api/auth/logout")
                        .session(authedSession)
                        .cookie(new Cookie("XSRF-TOKEN", rotatedXsrfValue))
                        .header("X-XSRF-TOKEN", preLoginPlainToken))
                .andExpect(status().isForbidden());

        // 유휴 만료(30분 초과) 시 /api/** 는 401 JSON SESSION_EXPIRED 직접 반환
        authedSession.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT,
                Instant.now().minusSeconds(31 * 60L).toEpochMilli());
        mockMvc.perform(get("/api/incidents").session(authedSession))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("SESSION_EXPIRED"));
        assertThat(authedSession.isInvalid()).isTrue();

        // 재로그인 시 XOR 토큰(GET /api/auth/csrf JSON 응답)으로도 통과 확인 + 절대 만료(8시간 초과) 검증
        MvcResult xorCsrfRes = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        JsonNode xorJson = objectMapper.readTree(xorCsrfRes.getResponse().getContentAsString());
        String xorToken = xorJson.get("token").asText();
        Cookie xorCookie = xorCsrfRes.getResponse().getCookie("XSRF-TOKEN");

        MvcResult reloginResult = mockMvc.perform(post("/api/auth/login")
                        .cookie(xorCookie)
                        .header("X-XSRF-TOKEN", xorToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "ValidPass!99"))))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession secondSession = (MockHttpSession) reloginResult.getRequest().getSession(false);
        assertThat(secondSession).isNotNull();

        secondSession.setAttribute(SessionAttributes.SESSION_CREATED_AT,
                Instant.now().minusSeconds(8 * 60 * 60L + 60L).toEpochMilli());
        mockMvc.perform(get("/api/incidents").session(secondSession))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SESSION_EXPIRED"));
        assertThat(secondSession.isInvalid()).isTrue();

        // 정상 로그아웃 시 세션 무효화 및 쿠키 만료 확인
        MvcResult thirdLogin = performLogin(username, "ValidPass!99");
        MockHttpSession thirdSession = (MockHttpSession) thirdLogin.getRequest().getSession(false);
        Cookie thirdXsrfCookie = extractLastCookie(thirdLogin.getResponse().getCookies(), "XSRF-TOKEN");
        assertThat(thirdXsrfCookie).isNotNull();
        String thirdXsrf = thirdXsrfCookie.getValue();

        MvcResult logoutRes = mockMvc.perform(post("/api/auth/logout")
                        .session(thirdSession)
                        .cookie(new Cookie("XSRF-TOKEN", thirdXsrf))
                        .header("X-XSRF-TOKEN", thirdXsrf))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andReturn();
        assertThat(thirdSession.isInvalid()).isTrue();
        assertThat(logoutRes.getResponse().getHeaders("Set-Cookie"))
                .anyMatch(h -> h.contains("ZEEKAD_SESSION=") && h.contains("Max-Age=0") && h.contains("SameSite=Lax"));

        // 비-API 유휴 만료 리다이렉트 확인
        MvcResult fourthLogin = performLogin(username, "ValidPass!99");
        MockHttpSession fourthSession = (MockHttpSession) fourthLogin.getRequest().getSession(false);
        fourthSession.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT,
                Instant.now().minusSeconds(31 * 60L).toEpochMilli());
        mockMvc.perform(get("/").session(fourthSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?expired"));

        // 세션 쿠키 보안 설정 확인
        assertThat(serverProperties.getServlet().getSession().getCookie().getHttpOnly()).isTrue();
        assertThat(serverProperties.getServlet().getSession().getCookie().getSameSite().name()).isEqualTo("LAX");
    }

    @Test
    void fiveConsecutiveFailuresLockAccountAndRecordAuditLogs() throws Exception {
        String username = "lock_analyst_1";
        userAdminService.createUser(username, "잠금분석가", "SecretPass!77", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        Cookie csrfCookie = fetchCsrfCookie();

        for (int i = 1; i <= 4; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .cookie(csrfCookie)
                            .header("X-XSRF-TOKEN", csrfCookie.getValue())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new LoginRequest(username, "WrongPass"))))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        }

        // 5번째 실패에서 423 Locked + ACCOUNT_LOCKED
        mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "WrongPass"))))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.status").value(423))
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));

        DashboardUser locked = userMapper.findByUsername(username);
        assertThat(locked.getFailedAttempts()).isEqualTo(5);
        assertThat(locked.getLockedUntil()).isNotNull();

        List<AuditLog> lockLogs = auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), username, 10);
        assertThat(lockLogs).hasSize(1);
        List<AuditLog> failLogs = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), username, 10);
        assertThat(failLogs).hasSize(5);

        // 잠금 상태에서는 올바른 비밀번호로도 423 차단
        mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "SecretPass!77"))))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }

    private MvcResult performLogin(String username, String password) throws Exception {
        Cookie csrfCookie = fetchCsrfCookie();
        return mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private Cookie extractLastCookie(Cookie[] cookies, String cookieName) {
        if (cookies == null) {
            return null;
        }
        Cookie last = null;
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isEmpty()) {
                last = cookie;
            }
        }
        return last;
    }
}
