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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
class AdminManagementIntegrationTest {

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
    void adminCanManageUsersUnlockResetTotpAndQueryAuditLogs() throws Exception {
        String adminUsername = "mgmt_admin_1";
        DashboardUser admin = userAdminService.createUser(adminUsername, "운영관리자", "AdminMgmt!99", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        String fixedSecret = "JBSWY3DPEHPK3PXP";
        userMapper.updateTotpState(admin.getId(), fixedSecret, true,
                OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", adminUsername)
                        .param("password", "AdminMgmt!99"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/totp"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);

        String code = totpService.generateCode(fixedSecret, clock.instant());
        mockMvc.perform(post("/login/totp")
                        .session(session)
                        .with(csrf())
                        .param("code", code))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));

        // 1. 사용자 생성
        String targetUser = "managed_user_1";
        mockMvc.perform(post("/admin/users")
                        .session(session)
                        .with(csrf())
                        .param("username", targetUser)
                        .param("displayName", "신규분석가")
                        .param("password", "TempPass!11")
                        .param("role", "VIEWER")
                        .param("capturePatterns", "cic17-*"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        DashboardUser created = userMapper.findByUsername(targetUser);
        assertThat(created).isNotNull();
        assertThat(created.getRole()).isEqualTo(UserRole.VIEWER);

        // 2. 역할·표시이름·캡처 패턴 수정
        mockMvc.perform(post("/admin/users/{id}/update", created.getId())
                        .session(session)
                        .with(csrf())
                        .param("displayName", "승격관리자")
                        .param("role", "ADMIN")
                        .param("capturePatterns", "cic17-*, syn1-*"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        DashboardUser updated = userMapper.findByUsername(targetUser);
        assertThat(updated.getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(updated.getDisplayName()).isEqualTo("승격관리자");
        assertThat(userMapper.findCapturePatternsByUserId(updated.getId()))
                .containsExactly("cic17-*", "syn1-*");

        // 3. 잠금 강제 후 해제 + 비활성화 토글 + TOTP 초기화
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.updateLoginFailure(updated.getId(), 5, now.plusMinutes(15), now);
        userMapper.updateTotpState(updated.getId(), fixedSecret, true, now);

        mockMvc.perform(post("/admin/users/{id}/unlock", updated.getId())
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        mockMvc.perform(post("/admin/users/{id}/toggle-enabled", updated.getId())
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        mockMvc.perform(post("/admin/users/{id}/reset-totp", updated.getId())
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        DashboardUser finalTarget = userMapper.findByUsername(targetUser);
        assertThat(finalTarget.getFailedAttempts()).isZero();
        assertThat(finalTarget.getLockedUntil()).isNull();
        assertThat(finalTarget.isEnabled()).isFalse();
        assertThat(finalTarget.isTotpEnabled()).isFalse();
        assertThat(finalTarget.getTotpSecret()).isNotEqualTo(fixedSecret);

        // 4. USER_ADMIN_CHANGE 감사 로그 확인 및 /admin/audit-logs 필터 조회
        List<AuditLog> adminChangeLogs = auditLogMapper.findFiltered(
                AuditActionType.USER_ADMIN_CHANGE.name(), adminUsername, 20);
        assertThat(adminChangeLogs).hasSizeGreaterThanOrEqualTo(5);

        mockMvc.perform(get("/admin/audit-logs")
                        .session(session)
                        .param("actionType", AuditActionType.USER_ADMIN_CHANGE.name())
                        .param("actorUsername", adminUsername))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(targetUser)))
                .andExpect(content().string(containsString("RESET_TOTP")));
    }
}
