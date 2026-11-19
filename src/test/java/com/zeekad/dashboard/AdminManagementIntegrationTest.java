package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.CreateUserRequest;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.dto.UpdateUserRequest;
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminManagementIntegrationTest {

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
    void adminCanManageUsersUnlockResetTotpAndQueryAuditLogsWithoutLeakingSecrets() throws Exception {
        String adminUsername = "mgmt_admin_1";
        DashboardUser admin = userAdminService.createUser(adminUsername, "운영관리자", "AdminMgmt!99", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        String fixedSecret = "JBSWY3DPEHPK3PXP";
        userMapper.updateTotpState(admin.getId(), fixedSecret, true,
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        Cookie csrf = fetchCsrfCookie();
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(adminUsername, "AdminMgmt!99"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nextRoute").value("/login/totp"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);

        String code = totpService.generateCode(fixedSecret, clock.instant());
        mockMvc.perform(post("/api/auth/totp/verify")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());

        // 0. 사용자 목록 조회 시 민감 필드 미포함 검증
        mockMvc.perform(get("/api/admin/users").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.users").isArray())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))))
                .andExpect(content().string(not(containsString(fixedSecret))))
                .andExpect(content().string(not(containsString("$2"))));

        // 빈 capturePatterns 배열은 400 Bad Request
        mockMvc.perform(post("/api/admin/users")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateUserRequest("bad_user", "실패", "TempPass!11", "VIEWER", List.of()))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        // 1. 사용자 생성 (201 Created)
        String targetUser = "managed_user_1";
        mockMvc.perform(post("/api/admin/users")
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new CreateUserRequest(targetUser, "신규분석가", "TempPass!11", "VIEWER",
                                        List.of("cic17-*")))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.username").value(targetUser))
                .andExpect(jsonPath("$.user.role").value("VIEWER"))
                .andExpect(jsonPath("$.user.capturePatterns[0]").value("cic17-*"))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))));

        DashboardUser created = userMapper.findByUsername(targetUser);
        assertThat(created).isNotNull();
        assertThat(created.getRole()).isEqualTo(UserRole.VIEWER);

        // 2. 역할·표시이름·캡처 패턴 수정
        mockMvc.perform(put("/api/admin/users/{id}", created.getId())
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new UpdateUserRequest("승격관리자", "ADMIN", List.of("cic17-*", "syn1-*")))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.role").value("ADMIN"))
                .andExpect(jsonPath("$.user.displayName").value("승격관리자"))
                .andExpect(jsonPath("$.user.capturePatterns[1]").value("syn1-*"))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))));

        DashboardUser updated = userMapper.findByUsername(targetUser);
        assertThat(updated.getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(updated.getDisplayName()).isEqualTo("승격관리자");
        assertThat(userMapper.findCapturePatternsByUserId(updated.getId()))
                .containsExactly("cic17-*", "syn1-*");

        // 3. 잠금 강제 후 해제 + 비활성화 토글 + TOTP 초기화
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.updateLoginFailure(updated.getId(), 5, now.plusMinutes(15), now);
        userMapper.updateTotpState(updated.getId(), fixedSecret, true, now);

        mockMvc.perform(post("/api/admin/users/{id}/unlock", updated.getId())
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.failedAttempts").value(0))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))));

        mockMvc.perform(post("/api/admin/users/{id}/toggle-enabled", updated.getId())
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.enabled").value(false))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))));

        mockMvc.perform(post("/api/admin/users/{id}/reset-totp", updated.getId())
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.totpEnabled").value(false))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("totpSecret"))));

        // 존재하지 않는 대상 수정 요청은 400 ApiErrorResponse
        mockMvc.perform(post("/api/admin/users/{id}/unlock", 999999L)
                        .session(session)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        DashboardUser finalTarget = userMapper.findByUsername(targetUser);
        assertThat(finalTarget.getFailedAttempts()).isZero();
        assertThat(finalTarget.getLockedUntil()).isNull();
        assertThat(finalTarget.isEnabled()).isFalse();
        assertThat(finalTarget.isTotpEnabled()).isFalse();
        assertThat(finalTarget.getTotpSecret()).isNotEqualTo(fixedSecret);

        // 4. USER_ADMIN_CHANGE 감사 로그 확인 및 /api/admin/audit-logs 필터 조회
        List<AuditLog> adminChangeLogs = auditLogMapper.findFiltered(
                AuditActionType.USER_ADMIN_CHANGE.name(), adminUsername, 20);
        assertThat(adminChangeLogs).hasSizeGreaterThanOrEqualTo(5);

        mockMvc.perform(get("/api/admin/audit-logs")
                        .session(session)
                        .param("actionType", AuditActionType.USER_ADMIN_CHANGE.name())
                        .param("actorUsername", adminUsername))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.logs").isArray())
                .andExpect(content().string(containsString(targetUser)))
                .andExpect(content().string(containsString("RESET_TOTP")));
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }
}
