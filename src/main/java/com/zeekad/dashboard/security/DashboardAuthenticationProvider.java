package com.zeekad.dashboard.security;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
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
    private final Clock clock;

    public DashboardAuthenticationProvider(UserMapper userMapper,
                                           PasswordEncoder passwordEncoder,
                                           AuditService auditService,
                                           DashboardProperties properties,
                                           ClientIpResolver clientIpResolver,
                                           Clock clock) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.properties = properties;
        this.clientIpResolver = clientIpResolver;
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

        if (user.getLockedUntil() != null && user.getLockedUntil().toInstant().isAfter(now)) {
            auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "account_locked", "lockedUntil", user.getLockedUntil().toString()), clientIp);
            throw new LockedException("계정이 일시 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.");
        }

        int currentFailures = user.getLockedUntil() != null ? 0 : user.getFailedAttempts();

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            int nextFailures = currentFailures + 1;
            int maxFailures = properties.getSecurity().getMaxFailedAttempts();
            if (nextFailures >= maxFailures) {
                OffsetDateTime lockedUntil = OffsetDateTime.ofInstant(
                        now.plusSeconds(properties.getSecurity().getLockoutMinutes() * 60L), ZoneOffset.UTC);
                userMapper.updateLoginFailure(user.getId(), nextFailures, lockedUntil, nowUtc);
                auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                        Map.of("reason", "invalid_credentials", "failedAttempts", nextFailures), clientIp);
                auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.ACCOUNT_LOCKED,
                        Map.of("failedAttempts", nextFailures, "lockedUntil", lockedUntil.toString()), clientIp);
                throw new LockedException("로그인 연속 실패 횟수 초과로 계정이 잠겼습니다.");
            }
            userMapper.updateLoginFailure(user.getId(), nextFailures, null, nowUtc);
            auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_FAILURE,
                    Map.of("reason", "invalid_credentials", "failedAttempts", nextFailures), clientIp);
            throw new BadCredentialsException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        userMapper.resetLoginFailure(user.getId(), nowUtc);
        List<String> capturePatterns = userMapper.findCapturePatternsByUserId(user.getId());
        DashboardUserPrincipal principal = new DashboardUserPrincipal(user, capturePatterns, now);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.LOGIN_SUCCESS,
                Map.of("totpRequired", user.getRole().name().equals("ADMIN")), clientIp);

        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
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
