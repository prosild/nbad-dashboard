package com.zeekad.dashboard.security;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/**
 * BCrypt 비밀번호 검증, 연속 실패 계정 잠금 및 로그인 감사 로그를 처리하는 인증 공급자.
 */
@Component
public class DashboardAuthenticationProvider implements AuthenticationProvider {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final DashboardProperties properties;
    private final ClientIpResolver clientIpResolver;
    private final FailedAttemptService failedAttemptService;
    private final Clock clock;

    public DashboardAuthenticationProvider(UserMapper userMapper,
                                           PasswordEncoder passwordEncoder,
                                           AuditService auditService,
                                           DashboardProperties properties,
                                           ClientIpResolver clientIpResolver,
                                           FailedAttemptService failedAttemptService,
                                           Clock clock) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.properties = properties;
        this.clientIpResolver = clientIpResolver;
        this.failedAttemptService = failedAttemptService;
        this.clock = clock;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName() == null ? "" : authentication.getName().trim();
        String rawPassword = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();
        String clientIp = resolveCurrentClientIp();
        Instant now = clock.instant();
        OffsetDateTime nowUtc = OffsetDateTime.ofInstant(now, ZoneOffset.UTC);

        DashboardUser user = userMapper.findByUsername(username);
        if (user == null) {
            auditService.recordAuthEvent(username, null, AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "invalid_credentials"), clientIp);
            throw new BadCredentialsException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        if (!user.isEnabled()) {
            auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "disabled"), clientIp);
            throw new DisabledException("비활성화된 계정입니다.");
        }

        // T29·T33 공유 계정 잠금 제외: 잠금 검사 앞에서 DB 저장 이름과 지금 DB 역할로 판정한다(VIEWER·ANALYST만, ADMIN은 늘 잠금).
        // 제외 계정은 남아 있는 locked_until에 막히지 않고, 틀려도 실패 수·잠금을 바꾸지 않는다(실패 감사는 남긴다).
        if (isLockoutExempt(user)) {
            if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
                auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                        Map.of("reason", "invalid_credentials", "lockoutExempt", true), clientIp);
                throw new BadCredentialsException("아이디 또는 비밀번호가 올바르지 않습니다.");
            }
            return succeed(user, now, nowUtc, clientIp);
        }

        if (user.getLockedUntil() != null && user.getLockedUntil().toInstant().isAfter(now)) {
            auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "account_locked", "lockedUntil", user.getLockedUntil().toString()), clientIp);
            throw new LockedException("계정이 일시 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.");
        }

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            // T60: 읽은 값 + 1로 덮어쓰지 않고 원자 증가로 올린다(비밀번호를 비교하는 사이에 들어온 TOTP 실패분을 지우지 않는다).
            // 만료된 잠금이 남아 있으면 1부터 다시 센다. 감사의 횟수는 갱신 뒤 다시 읽은 값이다.
            boolean claimed = failedAttemptService.claim(user.getId(), now);
            FailedAttemptService.State state = failedAttemptService.settle(user.getId(), now);
            if (!claimed) {
                // 비밀번호를 비교하는 사이에 다른 요청이 계정을 잠갔거나, 횟수가 이미 한도에 닿아 있었다
                auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                        FailedAttemptService.lockedDetail(state), clientIp);
                failedAttemptService.recordLockIfLockedNow(user, state, clientIp);
                throw new LockedException("계정이 일시 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.");
            }
            auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "invalid_credentials", "failedAttempts", state.failedAttempts()), clientIp);
            failedAttemptService.recordLockIfLockedNow(user, state, clientIp);
            if (state.locked()) {
                throw new LockedException("로그인 연속 실패 횟수 초과로 계정이 잠겼습니다.");
            }
            throw new BadCredentialsException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        return succeed(user, now, nowUtc, clientIp);
    }

    /**
     * 로그인 성공: 허용 캡처 읽기, 성공 감사. 실패 수·잠금은 관리자가 아닌 계정만 여기서 지운다.
     * T60: 관리자는 비밀번호가 맞아도 지우지 않고 TOTP 확인(또는 등록 완료)이 성공했을 때 지운다.
     * 여기서 지우면 비밀번호를 아는 사람이 로그인을 다시 해서 TOTP 실패 횟수를 되돌릴 수 있다.
     */
    private Authentication succeed(DashboardUser user, Instant now, OffsetDateTime nowUtc, String clientIp) {
        if (user.getRole() != UserRole.ADMIN) {
            userMapper.resetLoginFailure(user.getId(), nowUtc);
        }
        List<String> capturePatterns = userMapper.findCapturePatternsByUserId(user.getId());
        DashboardUserPrincipal principal = new DashboardUserPrincipal(user, capturePatterns, now);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_SUCCESS,
                Map.of("totpRequired", user.getRole().name().equals("ADMIN")), clientIp);

        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    /** 잠금 제외: 설정 목록에 저장 이름이 있고(대소문자 무시) 지금 DB 역할이 잠금 제외 허용 역할(VIEWER·ANALYST)인 계정만 */
    private boolean isLockoutExempt(DashboardUser user) {
        return DashboardProperties.Security.isLockoutExemptRole(user.getRole())
                && properties.getSecurity().isLockoutExemptName(user.getUsername());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String resolveCurrentClientIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            HttpServletRequest request = attrs.getRequest();
            return clientIpResolver.resolve(request);
        }
        return "unknown";
    }
}
