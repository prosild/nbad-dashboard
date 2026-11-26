package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T60 관리자 TOTP 확인의 실패 제한. 틀린 코드는 감사(TOTP_FAILURE)에 남고 비밀번호 실패와 같은 횟수에 합쳐진다.
 * 한도(기본 5)에서 계정이 잠기고 요청한 세션이 끝난다. 잠긴 계정의 확인은 코드를 보지 않고 423이다(다른 세션 포함).
 * 관리자는 TOTP 확인(또는 등록 완료)까지 성공해야 횟수가 되돌아간다.
 *
 * 검증 환경: 모의 환경(H2, MockMvc). 계정·비밀번호·비밀키는 모두 이 시험이 만든 값이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T60TotpFailureLimitIntegrationTest {

    private static final Instant BASE_NOW = Instant.parse("2026-11-26T03:00:10Z");
    private static final String PASS = "T60-Pass!word";
    private static final String TOTP_FAILURE = "TOTP_FAILURE";
    private static final String TOTP_VERIFIED = "TOTP_VERIFIED";
    private static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    private static final String LOGIN_FAILURE = "LOGIN_FAILURE";

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(BASE_NOW);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private UserMapper userMapper;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private TotpService totpService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;
    @MockitoSpyBean private PasswordEncoder passwordEncoder;

    @BeforeEach
    @AfterEach
    void resetClock() {
        clock.set(BASE_NOW);
    }

    @Test
    void wrongCodeIs400AndLeavesTotpFailureAuditWithActorAndClientIp() throws Exception {
        String name = "t60_wrongcode";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);

        verify(session, wrongCode(secret)).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));
        verify(session, wrongCode(secret)).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));

        List<AuditLog> failures = audits(TOTP_FAILURE, name);
        assertThat(failures).hasSize(2).allSatisfy(log -> {
            assertThat(log.getActorUsername()).isEqualTo(name);
            assertThat(log.getActorRole()).isEqualTo("ADMIN");
            assertThat(log.getClientIp()).isEqualTo("127.0.0.1");
            assertThat(log.getDetailJson()).contains("invalid_code");
        });
        // 최신 행이 앞이다: 횟수는 갱신 뒤 다시 읽은 값
        assertThat(failures.get(0).getDetailJson()).contains("\"failedAttempts\":2");
        assertThat(failures.get(1).getDetailJson()).contains("\"failedAttempts\":1");
        // 감사 detail에 넣은 코드나 비밀키는 없다
        assertThat(failures).allSatisfy(log -> assertThat(log.getDetailJson()).doesNotContain(secret));

        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.getFailedAttempts()).isEqualTo(2);
        assertThat(after.getLockedUntil()).isNull();
        assertThat(audits(ACCOUNT_LOCKED, name)).isEmpty();
        // 한도 전에는 세션이 살아 있고 맞는 코드로 통과한다
        assertThat(session.isInvalid()).isFalse();
        verify(session, validCode(secret)).andExpect(status().isOk());
    }

    @Test
    void fifthWrongCodeLocksAccountEndsSessionAndCorrectPasswordIs423() throws Exception {
        String name = "t60_fifthlock";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);

        for (int i = 1; i <= 4; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        verify(session, wrongCode(secret)).andExpect(status().isLocked())
                .andExpect(jsonPath("$.status").value(423))
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));

        DashboardUser locked = userMapper.findByUsername(name);
        assertThat(locked.getFailedAttempts()).isEqualTo(5);
        assertThat(locked.getLockedUntil()).isNotNull();
        assertThat(locked.getLockedUntil().toInstant()).isEqualTo(BASE_NOW.plusSeconds(15 * 60L));

        // 5번째 실패에는 TOTP_FAILURE와 ACCOUNT_LOCKED가 둘 다 남는다
        assertThat(audits(TOTP_FAILURE, name)).hasSize(5);
        List<AuditLog> lockLogs = audits(ACCOUNT_LOCKED, name);
        assertThat(lockLogs).hasSize(1);
        assertThat(lockLogs.get(0).getDetailJson()).contains("\"failedAttempts\":5").contains("lockedUntil");
        assertThat(lockLogs.get(0).getClientIp()).isEqualTo("127.0.0.1");

        // 그 세션은 끝났다: 같은 세션으로 업무 API와 TOTP 확인을 다시 불러도 401
        assertThat(session.isInvalid()).isTrue();
        mockMvc.perform(get("/api/incidents").session(session)).andExpect(status().isUnauthorized());
        verify(session, validCode(secret)).andExpect(status().isUnauthorized());
        assertThat(audits(TOTP_VERIFIED, name)).isEmpty();

        // 잠긴 동안에는 비밀번호가 맞아도 423
        login(name, PASS).andExpect(status().isLocked()).andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
    }

    @Test
    void sessionOpenedBeforeLockGets423WithoutCodeBeingJudged() throws Exception {
        String name = "t60_othersession";
        String secret = createEnrolledAdmin(name);
        MockHttpSession first = loginSession(name);
        // 잠금 전에 비밀번호 로그인만 해 둔 둘째 세션
        MockHttpSession second = loginSession(name);

        for (int i = 1; i <= 4; i++) {
            verify(first, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        verify(first, wrongCode(secret)).andExpect(status().isLocked());

        // 잠긴 뒤에는 맞는 코드를 보내도 코드를 보지 않고 423이다
        verify(second, validCode(secret)).andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));

        assertThat(audits(TOTP_VERIFIED, name)).isEmpty();
        assertThat(second.isInvalid()).isTrue();
        mockMvc.perform(get("/api/admin/users").session(second)).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/incidents").session(second)).andExpect(status().isUnauthorized());

        List<AuditLog> failures = audits(TOTP_FAILURE, name);
        assertThat(failures).hasSize(6);
        assertThat(failures.get(0).getDetailJson()).contains("account_locked").doesNotContain("invalid_code");
        assertThat(audits(ACCOUNT_LOCKED, name)).hasSize(1);
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(5);
    }

    @Test
    void passwordReLoginDoesNotResetCountForAdmin() throws Exception {
        String name = "t60_relogin";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);
        for (int i = 1; i <= 4; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        }

        // 비밀번호 로그인을 다시 해도 관리자의 횟수는 되돌아가지 않는다
        MockHttpSession again = loginSession(name);
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(4);

        verify(again, wrongCode(secret)).andExpect(status().isLocked());
        assertThat(userMapper.findByUsername(name).getLockedUntil()).isNotNull();
        assertThat(audits(ACCOUNT_LOCKED, name)).hasSize(1);
    }

    @Test
    void passwordFailuresAndCodeFailuresShareOneCount() throws Exception {
        String name = "t60_combined";
        String secret = createEnrolledAdmin(name);
        login(name, "Wrong-Pass").andExpect(status().isUnauthorized());
        login(name, "Wrong-Pass").andExpect(status().isUnauthorized());

        MockHttpSession session = loginSession(name);
        verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        verify(session, wrongCode(secret)).andExpect(status().isLocked());

        DashboardUser locked = userMapper.findByUsername(name);
        assertThat(locked.getFailedAttempts()).isEqualTo(5);
        assertThat(locked.getLockedUntil()).isNotNull();
        assertThat(audits(LOGIN_FAILURE, name)).hasSize(2);
        assertThat(audits(TOTP_FAILURE, name)).hasSize(3);
        assertThat(audits(ACCOUNT_LOCKED, name)).hasSize(1);
    }

    @Test
    void correctCodeResetsCount() throws Exception {
        String name = "t60_resetok";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);
        for (int i = 1; i <= 4; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        verify(session, validCode(secret)).andExpect(status().isOk())
                .andExpect(jsonPath("$.user.totpVerified").value(true));
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isZero();
        mockMvc.perform(get("/api/admin/users").session(session)).andExpect(status().isOk());

        // 다시 로그인해 4번 틀려도 잠기지 않는다
        MockHttpSession again = loginSession(name);
        for (int i = 1; i <= 4; i++) {
            verify(again, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.getFailedAttempts()).isEqualTo(4);
        assertThat(after.getLockedUntil()).isNull();
        assertThat(audits(ACCOUNT_LOCKED, name)).isEmpty();
    }

    @Test
    void setupCompletionResetsCountAndWrongSetupCodeIsNotCounted() throws Exception {
        String name = "t60_setupreset";
        userAdminService.createUser(name, name, PASS, UserRole.ADMIN, "*", "seed", "ADMIN", "127.0.0.1");
        login(name, "Wrong-Pass").andExpect(status().isUnauthorized());
        login(name, "Wrong-Pass").andExpect(status().isUnauthorized());

        // 등록 전 관리자도 역할이 ADMIN이라 비밀번호가 맞는 것만으로는 되돌아가지 않는다
        MockHttpSession session = loginSession(name);
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(2);

        mockMvc.perform(get("/api/auth/totp/setup").session(session)).andExpect(status().isOk());
        String secret = userMapper.findByUsername(name).getTotpSecret();

        // 등록의 틀린 코드는 세지 않고 감사도 남기지 않는다
        setup(session, wrongCode(secret)).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(2);
        assertThat(audits(TOTP_FAILURE, name)).isEmpty();

        setup(session, validCode(secret)).andExpect(status().isOk());
        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.isTotpEnabled()).isTrue();
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();
    }

    @Test
    void afterLockExpiresFirstWrongCodeCountsFromOne() throws Exception {
        String name = "t60_expired";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);
        for (int i = 1; i <= 4; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        verify(session, wrongCode(secret)).andExpect(status().isLocked());

        // 잠금 시간(15분)이 지난 뒤: 비밀번호 로그인은 되고, 만료된 잠금과 횟수 5가 남아 있다
        clock.set(BASE_NOW.plusSeconds(16 * 60L));
        MockHttpSession afterExpiry = loginSession(name);
        DashboardUser leftover = userMapper.findByUsername(name);
        assertThat(leftover.getFailedAttempts()).isEqualTo(5);
        assertThat(leftover.getLockedUntil()).isNotNull();

        // 첫 틀린 코드는 1부터 센다(바로 다시 잠기지 않는다)
        verify(afterExpiry, wrongCode(secret)).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));
        DashboardUser recount = userMapper.findByUsername(name);
        assertThat(recount.getFailedAttempts()).isEqualTo(1);
        assertThat(recount.getLockedUntil()).isNull();
        assertThat(audits(ACCOUNT_LOCKED, name)).hasSize(1);

        verify(afterExpiry, validCode(secret)).andExpect(status().isOk());
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isZero();
    }

    @Test
    void alreadyVerifiedSessionWrongCodeIs400WithoutCountOrAudit() throws Exception {
        String name = "t60_verified";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);
        verify(session, validCode(secret)).andExpect(status().isOk());

        for (int i = 1; i <= 6; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_TOTP_CODE"));
        }
        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();
        assertThat(audits(TOTP_FAILURE, name)).isEmpty();
        assertThat(audits(ACCOUNT_LOCKED, name)).isEmpty();
        assertThat(session.isInvalid()).isFalse();
        mockMvc.perform(get("/api/admin/users").session(session)).andExpect(status().isOk());
    }

    @Test
    void twentyConcurrentWrongCodesAreJudgedAtMostFiveTimes() throws Exception {
        String name = "t60_concurrent";
        String secret = createEnrolledAdmin(name);
        String wrong = wrongCode(secret);
        int requests = 20;
        List<MockHttpSession> sessions = new ArrayList<>();
        List<Cookie> csrfCookies = new ArrayList<>();
        for (int i = 0; i < requests; i++) {
            sessions.add(loginSession(name));
            csrfCookies.add(fetchCsrfCookie());
        }
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isZero();

        ExecutorService pool = Executors.newFixedThreadPool(requests);
        CyclicBarrier barrier = new CyclicBarrier(requests);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < requests; i++) {
                MockHttpSession session = sessions.get(i);
                Cookie csrf = csrfCookies.get(i);
                futures.add(pool.submit(() -> {
                    barrier.await(20, TimeUnit.SECONDS);
                    return mockMvc.perform(post("/api/auth/totp/verify")
                                    .session(session)
                                    .cookie(csrf)
                                    .header("X-XSRF-TOKEN", csrf.getValue())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(new TotpCodeRequest(wrong))))
                            .andReturn().getResponse().getStatus();
                }));
            }
            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> future : futures) {
                statuses.add(future.get(60, TimeUnit.SECONDS));
            }

            // 판정받은 것(코드를 본 것)은 한도 5건 이하, 나머지는 코드를 보지 않고 423
            List<AuditLog> failures = audits(TOTP_FAILURE, name);
            long judged = failures.stream().filter(log -> log.getDetailJson().contains("invalid_code")).count();
            long refused = failures.stream().filter(log -> log.getDetailJson().contains("account_locked")).count();
            assertThat(judged).isLessThanOrEqualTo(5);
            assertThat(judged + refused).isEqualTo(requests);
            assertThat(statuses).allMatch(s -> s == 400 || s == 423);
            assertThat(statuses.stream().filter(s -> s == 400).count()).isLessThanOrEqualTo(4);
            assertThat(statuses.stream().filter(s -> s == 423).count()).isGreaterThanOrEqualTo(requests - 4);

            DashboardUser after = userMapper.findByUsername(name);
            assertThat(after.getFailedAttempts()).isEqualTo(5);
            assertThat(after.getLockedUntil()).isNotNull();
            assertThat(audits(ACCOUNT_LOCKED, name)).hasSize(1);
            assertThat(audits(TOTP_VERIFIED, name)).isEmpty();
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void passwordFailureDoesNotEraseTotpFailuresThatLandDuringPasswordCheck() throws Exception {
        String name = "t60_noerase";
        createEnrolledAdmin(name);
        Long id = userMapper.findByUsername(name).getId();
        JdbcTemplate jdbc = new JdbcTemplate(appDataSource);

        // 비밀번호 비교(BCrypt)가 도는 사이에 다른 요청의 TOTP 실패 두 건이 횟수를 올린 상황을 만든다
        doAnswer(invocation -> {
            jdbc.update("UPDATE users SET failed_attempts = failed_attempts + 2 WHERE id = ?", id);
            return invocation.callRealMethod();
        }).when(passwordEncoder).matches(any(), any());

        login(name, "Wrong-Pass").andExpect(status().isUnauthorized());

        // 읽은 값 + 1을 절대값으로 덮어쓰면 1이 된다(두 건이 지워진다). 원자 증가면 3이다
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(3);
        List<AuditLog> failures = audits(LOGIN_FAILURE, name);
        assertThat(failures).hasSize(1);
        assertThat(failures.get(0).getDetailJson()).contains("\"failedAttempts\":3");
    }

    @Test
    void nonAdminPasswordSuccessStillResetsCount() throws Exception {
        String name = "t60_analyst";
        userAdminService.createUser(name, name, PASS, UserRole.ANALYST, "cic17-*", "seed", "ADMIN", "127.0.0.1");
        for (int i = 1; i <= 3; i++) {
            login(name, "Wrong-Pass").andExpect(status().isUnauthorized());
        }
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isEqualTo(3);

        login(name, PASS).andExpect(status().isOk());
        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();

        // 관리자가 아닌 계정은 TOTP 확인 경로에 닿지 못한다(지금과 같다)
        MockHttpSession session = loginSession(name);
        verify(session, "123456").andExpect(status().isForbidden());
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isZero();
        assertThat(audits(TOTP_FAILURE, name)).isEmpty();
    }

    @Test
    void unauthenticatedAndUnenrolledCallsKeepTheirResponsesAndDoNotCount() throws Exception {
        // 로그인하지 않은 요청: 401
        Cookie csrf = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/verify")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest("123456"))))
                .andExpect(status().isUnauthorized());

        // 등록되지 않은 관리자: 409, 횟수와 감사는 그대로
        String name = "t60_unenrolled";
        userAdminService.createUser(name, name, PASS, UserRole.ADMIN, "*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginSession(name);
        for (int i = 1; i <= 6; i++) {
            verify(session, "123456").andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code").value("TOTP_NOT_ENABLED"));
        }
        DashboardUser after = userMapper.findByUsername(name);
        assertThat(after.getFailedAttempts()).isZero();
        assertThat(after.getLockedUntil()).isNull();
        assertThat(audits(TOTP_FAILURE, name)).isEmpty();
        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void adminUnlockLetsLockedAdminLogInAndVerifyAgain() throws Exception {
        String name = "t60_unlocked";
        String secret = createEnrolledAdmin(name);
        MockHttpSession session = loginSession(name);
        for (int i = 1; i <= 4; i++) {
            verify(session, wrongCode(secret)).andExpect(status().isBadRequest());
        }
        verify(session, wrongCode(secret)).andExpect(status().isLocked());
        login(name, PASS).andExpect(status().isLocked());

        // 다른 관리자가 잠금을 푼다
        String operator = "t60_operator";
        String operatorSecret = createEnrolledAdmin(operator);
        MockHttpSession operatorSession = loginSession(operator);
        verify(operatorSession, validCode(operatorSecret)).andExpect(status().isOk());
        Cookie csrf = fetchCsrfCookie();
        mockMvc.perform(post("/api/admin/users/{id}/unlock", userMapper.findByUsername(name).getId())
                        .session(operatorSession)
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.failedAttempts").value(0));

        MockHttpSession again = loginSession(name);
        verify(again, validCode(secret)).andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/users").session(again)).andExpect(status().isOk());
        assertThat(userMapper.findByUsername(name).getFailedAttempts()).isZero();
    }

    /** 관리자 계정을 만들고 TOTP를 등록된 상태로 둔다. 비밀키를 돌려준다. */
    private String createEnrolledAdmin(String username) {
        userAdminService.createUser(username, username, PASS, UserRole.ADMIN, "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser created = userMapper.findByUsername(username);
        String secret = created.getTotpSecret();
        userMapper.updateTotpState(created.getId(), secret, true, OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        return secret;
    }

    private String validCode(String secret) {
        return totpService.generateCode(secret, clock.instant());
    }

    /** 지금 허용 창(앞뒤 1창) 어디에도 맞지 않는 6자리 코드 */
    private String wrongCode(String secret) {
        for (int candidate = 0; candidate < 10; candidate++) {
            String code = String.format("%06d", candidate);
            if (!totpService.verifyCode(secret, code, clock.instant())) {
                return code;
            }
        }
        throw new IllegalStateException("틀린 코드를 찾지 못했다");
    }

    private List<AuditLog> audits(String actionType, String username) {
        return auditLogMapper.findFiltered(actionType, username, 200);
    }

    private Cookie fetchCsrfCookie() throws Exception {
        return mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn()
                .getResponse().getCookie("XSRF-TOKEN");
    }

    private ResultActions login(String username, String password) throws Exception {
        Cookie csrf = fetchCsrfCookie();
        return mockMvc.perform(post("/api/auth/login")
                .cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, password))));
    }

    private MockHttpSession loginSession(String username) throws Exception {
        MvcResult result = login(username, PASS).andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private ResultActions verify(MockHttpSession session, String code) throws Exception {
        return postCode("/api/auth/totp/verify", session, code);
    }

    private ResultActions setup(MockHttpSession session, String code) throws Exception {
        return postCode("/api/auth/totp/setup", session, code);
    }

    private ResultActions postCode(String path, MockHttpSession session, String code) throws Exception {
        Cookie csrf = fetchCsrfCookie();
        return mockMvc.perform(post(path)
                .session(session)
                .cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))));
    }
}
