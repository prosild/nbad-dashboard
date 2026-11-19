package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(SecurityHeadersAndErrorTest.BoomController.class)
class SecurityHeadersAndErrorTest {

    @TestConfiguration
    static class TestControllerConfig {
    }

    @RestController
    static class BoomController {
        @GetMapping("/api/test-internal-error")
        public String boom() {
            throw new IllegalStateException("java.lang.RuntimeException: internal SQL leak");
        }
    }

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

    @Test
    void responsesIncludeSecurityHeadersHideStackTracesAndDoNotExposeActuator() throws Exception {
        // SPA 로그인 경로 포워딩 및 보안 헤더 검증
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("style-src 'self'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"));

        mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<div id=\"root\"></div>")))
                .andExpect(content().string(not(containsString("<script"))))
                .andExpect(content().string(not(containsString("style="))));

        // 비인증 브라우저 SPA 경로는 /login 리다이렉트, 비인증 API는 401 JSON 반환
        mockMvc.perform(get("/incidents"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));

        mockMvc.perform(get("/api/incidents"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));

        // 인증된 관리자 세션 준비
        String adminUsername = "hdr_admin_1";
        DashboardUser admin = userAdminService.createUser(adminUsername, "헤더관리자", "HeaderPass!1", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        String secret = "JBSWY3DPEHPK3PXP";
        userMapper.updateTotpState(admin.getId(), secret, true,
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        Cookie csrfCookie = fetchCsrfCookie();
        MvcResult loginRes = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(adminUsername, "HeaderPass!1"))))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession session = (MockHttpSession) loginRes.getRequest().getSession(false);

        String code = totpService.generateCode(secret, clock.instant());
        Cookie totpCsrf = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/verify")
                        .session(session)
                        .cookie(totpCsrf)
                        .header("X-XSRF-TOKEN", totpCsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());

        // 인증된 SPA 경로 포워딩 확인
        mockMvc.perform(get("/incidents").session(session))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));

        // 존재하지 않는 /api/** 요청은 index.html 폴백 없이 404 JSON 반환
        mockMvc.perform(get("/api/unknown").session(session))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));

        // 내부 예외 발생 시 스택 트레이스·예외 클래스명 은닉 JSON 확인
        mockMvc.perform(get("/api/test-internal-error").session(session))
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
                .andExpect(content().string(not(containsString("java.lang."))))
                .andExpect(content().string(not(containsString("org.springframework."))))
                .andExpect(content().string(not(containsString("IllegalStateException"))))
                .andExpect(content().string(not(containsString("internal SQL leak"))));

        // Actuator 미노출 확인 (인증 상태에서도 404, 비인증 시 302 로그인 리다이렉트)
        mockMvc.perform(get("/actuator/health").session(session))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/actuator/env").session(session))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().is3xxRedirection());
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }
}
