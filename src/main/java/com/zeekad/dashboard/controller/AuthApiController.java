package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.ActionResultResponse;
import com.zeekad.dashboard.dto.ApiErrorResponse;
import com.zeekad.dashboard.dto.AuthCsrfResponse;
import com.zeekad.dashboard.dto.AuthLoginResponse;
import com.zeekad.dashboard.dto.AuthMeResponse;
import com.zeekad.dashboard.dto.AuthUserDto;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.dto.TotpSetupResponse;
import com.zeekad.dashboard.dto.TotpVerifyResponse;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.security.FailedAttemptService;
import com.zeekad.dashboard.security.SessionAttributes;
import com.zeekad.dashboard.security.SpaCsrfTokenRequestHandler;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.MaskingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/**
 * SPA JSON 인증·세션·CSRF·관리자 TOTP 2단계 인증 REST API 컨트롤러.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthApiController {

    private final AuthenticationManager authenticationManager;
    private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private final HttpSessionSecurityContextRepository securityContextRepository;
    private final CookieCsrfTokenRepository csrfTokenRepository;
    private final SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler;
    private final UserMapper userMapper;
    private final TotpService totpService;
    private final AuditService auditService;
    private final ClientIpResolver clientIpResolver;
    private final FailedAttemptService failedAttemptService;
    private final MaskingService maskingService;
    private final DashboardProperties properties;
    private final ServerProperties serverProperties;
    private final Clock clock;

    public AuthApiController(AuthenticationManager authenticationManager,
                             SessionAuthenticationStrategy sessionAuthenticationStrategy,
                             HttpSessionSecurityContextRepository securityContextRepository,
                             CookieCsrfTokenRepository csrfTokenRepository,
                             SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler,
                             UserMapper userMapper,
                             TotpService totpService,
                             AuditService auditService,
                             ClientIpResolver clientIpResolver,
                             FailedAttemptService failedAttemptService,
                             MaskingService maskingService,
                             DashboardProperties properties,
                             ServerProperties serverProperties,
                             Clock clock) {
        this.authenticationManager = authenticationManager;
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        this.securityContextRepository = securityContextRepository;
        this.csrfTokenRepository = csrfTokenRepository;
        this.spaCsrfTokenRequestHandler = spaCsrfTokenRequestHandler;
        this.userMapper = userMapper;
        this.totpService = totpService;
        this.auditService = auditService;
        this.clientIpResolver = clientIpResolver;
        this.failedAttemptService = failedAttemptService;
        this.maskingService = maskingService;
        this.properties = properties;
        this.serverProperties = serverProperties;
        this.clock = clock;
    }

    @GetMapping("/csrf")
    public ResponseEntity<AuthCsrfResponse> csrf(CsrfToken csrfToken) {
        String tokenValue = csrfToken.getToken();
        return ResponseEntity.ok(new AuthCsrfResponse(
                csrfToken.getHeaderName(),
                csrfToken.getParameterName(),
                tokenValue
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<AuthMeResponse> me(Authentication authentication, HttpServletRequest request) {
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || !(authentication.getPrincipal() instanceof DashboardUserPrincipal principal)) {
            return ResponseEntity.ok(new AuthMeResponse(false, null));
        }

        HttpSession session = request.getSession(false);
        DashboardUser freshUser = userMapper.findByUsername(principal.getUsername());
        if (freshUser != null && !freshUser.isEnabled()) {
            return ResponseEntity.ok(new AuthMeResponse(false, null));
        }
        return ResponseEntity.ok(new AuthMeResponse(true, buildUserDto(principal, freshUser, session)));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest body,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        String username = body.username() == null ? "" : body.username();
        String password = body.password() == null ? "" : body.password();

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        } catch (LockedException ex) {
            return ResponseEntity.status(HttpStatus.LOCKED)
                    .body(new ApiErrorResponse(423, "ACCOUNT_LOCKED", ex.getMessage()));
        } catch (DisabledException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiErrorResponse(403, "ACCOUNT_DISABLED", ex.getMessage()));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiErrorResponse(401, "INVALID_CREDENTIALS", "아이디 또는 비밀번호가 올바르지 않습니다."));
        }

        HttpSession session = request.getSession(true);
        sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
        session = request.getSession(true);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        long nowMillis = clock.instant().toEpochMilli();
        session.setAttribute(SessionAttributes.SESSION_CREATED_AT, nowMillis);
        session.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT, nowMillis);
        int idleSeconds = (int) Math.max(60L, properties.getSecurity().getIdleTimeoutMinutes() * 60L);
        session.setMaxInactiveInterval(idleSeconds);

        DashboardUserPrincipal principal = (DashboardUserPrincipal) authentication.getPrincipal();
        boolean isAdmin = principal.getRole() == UserRole.ADMIN;
        session.setAttribute(SessionAttributes.TOTP_VERIFIED, !isAdmin);

        CsrfToken rotatedToken = csrfTokenRepository.generateToken(request);
        csrfTokenRepository.saveToken(rotatedToken, request, response);
        spaCsrfTokenRequestHandler.handle(request, response, () -> rotatedToken);

        String nextRoute = isAdmin
                ? (principal.isTotpEnabled() ? "/login/totp" : "/login/totp/setup")
                : "/";

        AuthUserDto userDto = buildUserDto(principal, null, session);
        return ResponseEntity.ok(new AuthLoginResponse(true, userDto, nextRoute));
    }

    @PostMapping("/logout")
    public ResponseEntity<ActionResultResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        String cookieName = serverProperties.getServlet().getSession().getCookie().getName();
        if (cookieName == null || cookieName.isBlank()) {
            cookieName = "ZEEKAD_SESSION";
        }
        Boolean secureProp = serverProperties.getServlet().getSession().getCookie().getSecure();
        boolean cookieSecure = secureProp != null ? secureProp : true;

        ResponseCookie expiredSessionCookie = ResponseCookie.from(cookieName, "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .sameSite("Lax")
                .secure(cookieSecure)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, expiredSessionCookie.toString());

        return ResponseEntity.ok(new ActionResultResponse(true, "OK", "로그아웃되었습니다."));
    }

    @GetMapping("/totp/setup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> totpSetupInfo(Authentication authentication) {
        DashboardUser user = findAuthenticatedUser(authentication);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiErrorResponse(401, "UNAUTHENTICATED", "인증이 필요합니다."));
        }
        if (user.isTotpEnabled()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiErrorResponse(409, "TOTP_ALREADY_ENABLED", "이미 TOTP가 등록된 계정입니다."));
        }

        String secret = ensureSecret(user);
        String otpauthUri = totpService.buildOtpAuthUri(user.getUsername(), secret);
        return ResponseEntity.ok(new TotpSetupResponse(
                secret,
                otpauthUri,
                properties.getSecurity().getTotpIssuer(),
                user.getUsername()
        ));
    }

    @PostMapping("/totp/setup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> completeTotpSetup(@RequestBody TotpCodeRequest body,
                                               Authentication authentication,
                                               HttpServletRequest request) {
        DashboardUser user = findAuthenticatedUser(authentication);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiErrorResponse(401, "UNAUTHENTICATED", "인증이 필요합니다."));
        }
        if (user.isTotpEnabled()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiErrorResponse(409, "TOTP_ALREADY_ENABLED", "이미 TOTP가 등록된 계정입니다."));
        }
        String secret = user.getTotpSecret();
        if (secret == null || secret.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiErrorResponse(400, "TOTP_SECRET_NOT_INITIALIZED",
                            "TOTP 시크릿이 아직 초기화되지 않았습니다. 설정 정보를 먼저 조회해 주세요."));
        }
        String code = body.code() == null ? "" : body.code();
        if (!totpService.verifyCode(secret, code)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiErrorResponse(400, "INVALID_TOTP_CODE",
                            "인증 코드가 올바르지 않습니다. 시간 동기화와 6자리 숫자를 확인하세요."));
        }

        Instant nowInstant = clock.instant();
        OffsetDateTime now = OffsetDateTime.ofInstant(nowInstant, ZoneOffset.UTC);
        userMapper.updateTotpState(user.getId(), secret, true, now);
        user.setTotpEnabled(true);
        // T60: 관리자는 비밀번호가 맞은 것만으로는 실패 횟수가 되돌아가지 않는다. 등록 완료를 TOTP 확인 성공과 같이 본다
        failedAttemptService.reset(user.getId(), nowInstant);

        HttpSession session = request.getSession(true);
        session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.TRUE);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.TOTP_VERIFIED,
                Map.of("mode", "setup"), clientIpResolver.resolve(request));

        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        return ResponseEntity.ok(new TotpVerifyResponse(
                true,
                "OK",
                "TOTP 2단계 인증 등록이 완료되었습니다.",
                buildUserDto(principal, user, session)
        ));
    }

    @PostMapping("/totp/verify")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> verifyTotp(@RequestBody TotpCodeRequest body,
                                        Authentication authentication,
                                        HttpServletRequest request) {
        DashboardUser user = findAuthenticatedUser(authentication);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiErrorResponse(401, "UNAUTHENTICATED", "인증이 필요합니다."));
        }
        if (!user.isTotpEnabled()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiErrorResponse(409, "TOTP_NOT_ENABLED",
                            "TOTP가 아직 등록되지 않았습니다. 먼저 TOTP 설정을 완료해 주세요."));
        }
        String code = body.code() == null ? "" : body.code();

        // T60: 이미 확인을 마친 세션은 지금처럼 판정만 한다. 실패 횟수를 건드리지 않고 실패 감사도 남기지 않는다
        // (그 세션은 이미 모든 권한이 있다. 화면을 다시 열어 실수한 관리자를 잠그지 않는다).
        HttpSession existingSession = request.getSession(false);
        boolean alreadyVerified = existingSession != null
                && Boolean.TRUE.equals(existingSession.getAttribute(SessionAttributes.TOTP_VERIFIED));
        if (alreadyVerified) {
            if (!totpService.verifyCode(user.getTotpSecret(), code)) {
                return invalidTotpCode();
            }
        } else {
            // T60: 코드를 보기 전에 시도 하나를 차지한다. 잠겨 있거나 횟수가 한도에 닿아 있으면 코드를 보지 않는다.
            // 판정이 차지 뒤에만 일어나므로 동시에 여러 요청이 와도 판정받는 수가 한도를 넘지 않고,
            // 잠금 전에 비밀번호 로그인만 해 둔 다른 세션도 잠긴 뒤에는 코드를 넣어 볼 수 없다.
            Instant now = clock.instant();
            String clientIp = clientIpResolver.resolve(request);
            String role = user.getRole().name();
            if (!failedAttemptService.claim(user.getId(), now)) {
                FailedAttemptService.State state = failedAttemptService.settle(user.getId(), now);
                auditService.recordAuthEvent(user.getUsername(), role, AuditActionType.TOTP_FAILURE,
                        FailedAttemptService.lockedDetail(state), clientIp);
                failedAttemptService.recordLockIfLockedNow(user, state, clientIp);
                endSession(request);
                return accountLocked("계정이 일시 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요.");
            }
            if (!totpService.verifyCode(user.getTotpSecret(), code)) {
                FailedAttemptService.State state = failedAttemptService.settle(user.getId(), now);
                auditService.recordAuthEvent(user.getUsername(), role, AuditActionType.TOTP_FAILURE,
                        Map.of("reason", "invalid_code", "failedAttempts", state.failedAttempts()), clientIp);
                failedAttemptService.recordLockIfLockedNow(user, state, clientIp);
                if (state.locked()) {
                    endSession(request);
                    return accountLocked("2단계 인증 연속 실패 횟수 초과로 계정이 잠겼습니다.");
                }
                return invalidTotpCode();
            }
            failedAttemptService.reset(user.getId(), now);
        }

        HttpSession session = request.getSession(true);
        session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.TRUE);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.TOTP_VERIFIED,
                Map.of("mode", "verify"), clientIpResolver.resolve(request));

        DashboardUserPrincipal principal = ControllerAuthUtils.requirePrincipal(authentication);
        return ResponseEntity.ok(new TotpVerifyResponse(
                true,
                "OK",
                "TOTP 2단계 인증이 완료되었습니다.",
                buildUserDto(principal, user, session)
        ));
    }

    private static ResponseEntity<ApiErrorResponse> invalidTotpCode() {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiErrorResponse(400, "INVALID_TOTP_CODE", "인증 코드가 올바르지 않습니다."));
    }

    private static ResponseEntity<ApiErrorResponse> accountLocked(String message) {
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(new ApiErrorResponse(423, "ACCOUNT_LOCKED", message));
    }

    /** 요청한 세션만 끝낸다(세션 목록 구조가 없어 같은 계정의 다른 세션은 그대로다) */
    private static void endSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
    }

    private DashboardUser findAuthenticatedUser(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return null;
        }
        return userMapper.findByUsername(authentication.getName());
    }

    private String ensureSecret(DashboardUser user) {
        if (user.getTotpSecret() != null && !user.getTotpSecret().isBlank()) {
            return user.getTotpSecret();
        }
        String generated = totpService.generateSecret();
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.updateTotpState(user.getId(), generated, false, now);
        user.setTotpSecret(generated);
        return generated;
    }

    private AuthUserDto buildUserDto(DashboardUserPrincipal principal, DashboardUser freshUser, HttpSession session) {
        UserRole role = freshUser != null && freshUser.getRole() != null ? freshUser.getRole() : principal.getRole();
        String displayName = freshUser != null && freshUser.getDisplayName() != null
                ? freshUser.getDisplayName()
                : principal.getDisplayName();
        boolean totpEnabled = freshUser != null ? freshUser.isTotpEnabled() : principal.isTotpEnabled();
        boolean totpRequired = role == UserRole.ADMIN;
        boolean totpVerified = !totpRequired
                || (session != null && Boolean.TRUE.equals(session.getAttribute(SessionAttributes.TOTP_VERIFIED)));
        List<String> patterns = principal.getCapturePatterns();

        return new AuthUserDto(
                principal.getUsername(),
                displayName,
                role.name(),
                maskingService.shouldMask(role),
                totpEnabled,
                totpVerified,
                totpRequired,
                patterns
        );
    }
}
