package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.LockoutExemptionStartupCheck;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T29·T33 공유 계정 잠금 제외: 목록(대소문자·공백 무시, 빈 항목 버림)에 있고 DB 역할이 VIEWER 또는 ANALYST인 계정만 잠금에서 빠진다.
 * 목록의 ADMIN, 목록 밖 VIEWER·ANALYST는 지금처럼 잠긴다. 제외 계정도 실패 감사는 남고 비활성이면 거부된다.
 */
@SpringBootTest(properties = "dashboard.security.lockout-exempt-usernames= T29_Demo_V , ,t29_demo_analyst,"
        + "t29_DEMO_locked , t29_demo_disabled,t29_missing_user,t33_demo_admin")
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class T29LockoutExemptIntegrationTest {

    private static final String PASS = "SecretPass!29";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private UserMapper userMapper;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private LockoutExemptionStartupCheck startupCheck;

    @Test
    void exemptViewerSurvivesSixFailuresAndLogsInWithFailureAuditsButNoLock() throws Exception {
        // 목록 항목은 " T29_Demo_V "(대소문자·공백 다름), 저장 이름은 소문자
        create("t29_demo_v", UserRole.VIEWER);
        for (int i = 1; i <= 6; i++) {
            login("t29_demo_v", "WrongPass").andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        }
        DashboardUser after = userMapper.findByUsername("t29_demo_v");
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();

        login("t29_demo_v", PASS).andExpect(status().isOk());

        List<AuditLog> fails = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), "t29_demo_v", 20);
        assertThat(fails).hasSize(6);
        assertThat(fails).allSatisfy(l -> {
            assertThat(l.getDetailJson()).contains("\"lockoutExempt\":true").contains("invalid_credentials")
                    .doesNotContain("failedAttempts");
        });
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), "t29_demo_v", 20)).isEmpty();
        assertThat(auditLogMapper.findFiltered(AuditActionType.LOGIN_SUCCESS.name(), "t29_demo_v", 20)).hasSize(1);
    }

    @Test
    void enteredNameCaseDoesNotMatterBecauseStoredNameIsCompared() throws Exception {
        create("t29_case_viewer", UserRole.VIEWER);
        // 목록에 없는 이름은 입력 대소문자를 바꿔도 제외되지 않는다(저장 이름으로 비교)
        for (int i = 1; i <= 4; i++) {
            login("T29_CASE_VIEWER", "WrongPass").andExpect(status().isUnauthorized());
        }
        login("T29_CASE_VIEWER", "WrongPass").andExpect(status().isLocked());
        assertThat(userMapper.findByUsername("t29_case_viewer").getLockedUntil()).isNotNull();
    }

    @Test
    void listedAnalystIsExemptSinceT33() throws Exception {
        // T33: 체험용 분석가 공유 계정처럼 목록의 ANALYST도 잠금에서 빠진다(실패 감사는 남는다)
        create("t29_demo_analyst", UserRole.ANALYST);
        for (int i = 1; i <= 6; i++) {
            login("t29_demo_analyst", "WrongPass").andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        }
        DashboardUser after = userMapper.findByUsername("t29_demo_analyst");
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();
        login("t29_demo_analyst", PASS).andExpect(status().isOk());
        List<AuditLog> fails = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), "t29_demo_analyst", 20);
        assertThat(fails).hasSize(6).allSatisfy(l -> assertThat(l.getDetailJson()).contains("\"lockoutExempt\":true"));
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), "t29_demo_analyst", 20)).isEmpty();
    }

    @Test
    void listedAdminIsAlwaysLocked() throws Exception {
        // T33: ADMIN은 목록에 있어도 늘 잠긴다
        create("t33_demo_admin", UserRole.ADMIN);
        for (int i = 1; i <= 4; i++) {
            login("t33_demo_admin", "WrongPass").andExpect(status().isUnauthorized());
        }
        login("t33_demo_admin", "WrongPass").andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
        login("t33_demo_admin", PASS).andExpect(status().isLocked());
        assertThat(userMapper.findByUsername("t33_demo_admin").getLockedUntil()).isNotNull();
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), "t33_demo_admin", 20)).hasSize(1);
    }

    @Test
    void unlistedAnalystIsStillLocked() throws Exception {
        create("t33_other_analyst", UserRole.ANALYST);
        for (int i = 1; i <= 4; i++) {
            login("t33_other_analyst", "WrongPass").andExpect(status().isUnauthorized());
        }
        login("t33_other_analyst", "WrongPass").andExpect(status().isLocked());
        login("t33_other_analyst", PASS).andExpect(status().isLocked());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), "t33_other_analyst", 20)).hasSize(1);
    }

    @Test
    void unlistedViewerIsStillLocked() throws Exception {
        create("t29_other_viewer", UserRole.VIEWER);
        for (int i = 1; i <= 4; i++) {
            login("t29_other_viewer", "WrongPass").andExpect(status().isUnauthorized());
        }
        login("t29_other_viewer", "WrongPass").andExpect(status().isLocked());
        login("t29_other_viewer", PASS).andExpect(status().isLocked());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCOUNT_LOCKED.name(), "t29_other_viewer", 20)).hasSize(1);
    }

    @Test
    void exemptViewerWithLeftoverLockLogsInAndLockIsCleared() throws Exception {
        // 목록 항목 "t29_DEMO_locked " — 예전에 잠긴 채 남은 locked_until
        create("t29_demo_locked", UserRole.VIEWER);
        DashboardUser u = userMapper.findByUsername("t29_demo_locked");
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        userMapper.updateLoginFailure(u.getId(), 5, now.plusHours(1), now);

        login("t29_demo_locked", "WrongPass").andExpect(status().isUnauthorized());
        DashboardUser still = userMapper.findByUsername("t29_demo_locked");
        assertThat(still.getFailedAttempts()).isEqualTo(5);   // 틀려도 바꾸지 않는다
        assertThat(still.getLockedUntil()).isNotNull();

        login("t29_demo_locked", PASS).andExpect(status().isOk());
        DashboardUser cleared = userMapper.findByUsername("t29_demo_locked");
        assertThat(cleared.getFailedAttempts()).isZero();
        assertThat(cleared.getLockedUntil()).isNull();
    }

    @Test
    void disabledExemptViewerIsRejected() throws Exception {
        create("t29_demo_disabled", UserRole.VIEWER);
        DashboardUser u = userMapper.findByUsername("t29_demo_disabled");
        userMapper.updateEnabled(u.getId(), false, OffsetDateTime.now(ZoneOffset.UTC));
        login("t29_demo_disabled", PASS).andExpect(status().is4xxClientError());
        List<AuditLog> fails = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), "t29_demo_disabled", 20);
        assertThat(fails).hasSize(1);
        assertThat(fails.get(0).getDetailJson()).contains("disabled");
        assertThat(auditLogMapper.findFiltered(AuditActionType.LOGIN_SUCCESS.name(), "t29_demo_disabled", 20)).isEmpty();
    }

    @Test
    void startupCheckWarnsForMissingOrNonExemptRoleNamesOnly(CapturedOutput output) {
        create("t29_demo_analyst", UserRole.ANALYST);
        create("t29_demo_v", UserRole.VIEWER);
        create("t33_demo_admin", UserRole.ADMIN);
        List<String> warned = startupCheck.check();
        // 없는 계정과 ADMIN은 경고, 목록의 VIEWER·ANALYST는 경고 없음, 빈 항목은 버린다(정규화한 이름)
        assertThat(warned).contains("t29_missing_user", "t33_demo_admin")
                .doesNotContain("t29_demo_v", "t29_demo_analyst", "");
        String log = output.getOut() + output.getErr();
        assertThat(log).contains("t29_missing_user").contains("t33_demo_admin").contains("VIEWER·ANALYST가 아니라");
        // 비밀값은 로그에 없다
        assertThat(log).doesNotContain(PASS);
    }

    private void create(String username, UserRole role) {
        if (userMapper.findByUsername(username) == null) {
            userAdminService.createUser(username, username, PASS, role, "cic17-*", "seed", "ADMIN", "127.0.0.1");
        }
    }

    private ResultActions login(String username, String password) throws Exception {
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        return mockMvc.perform(post("/api/auth/login")
                .cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, password))));
    }
}
