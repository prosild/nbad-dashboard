package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(SecurityHeadersAndErrorTest.BoomController.class)
class SecurityHeadersAndErrorTest {

    @TestConfiguration
    static class TestControllerConfig {
    }

    @Controller
    static class BoomController {
        @GetMapping("/test-internal-error")
        public String boom() {
            throw new IllegalStateException("java.lang.RuntimeException: internal SQL leak");
        }
    }

    @Autowired
    private MockMvc mockMvc;

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
        // 로그인 페이지 보안 헤더 검증
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"));

        // 인증된 관리자 세션 준비
        String adminUsername = "hdr_admin_1";
        DashboardUser admin = userAdminService.createUser(adminUsername, "헤더관리자", "HeaderPass!1", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        String secret = "JBSWY3DPEHPK3PXP";
        userMapper.updateTotpState(admin.getId(), secret, true,
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        MvcResult loginRes = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", adminUsername)
                        .param("password", "HeaderPass!1"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        MockHttpSession session = (MockHttpSession) loginRes.getRequest().getSession(false);

        String code = totpService.generateCode(secret, clock.instant());
        mockMvc.perform(post("/login/totp")
                        .session(session)
                        .with(csrf())
                        .param("code", code))
                .andExpect(status().is3xxRedirection());

        // 내부 예외 발생 시 스택 트레이스·예외 클래스명 은닉 확인
        mockMvc.perform(get("/test-internal-error").session(session))
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
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
}
