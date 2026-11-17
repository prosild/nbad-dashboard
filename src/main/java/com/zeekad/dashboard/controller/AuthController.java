package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.security.SessionAttributes;
import com.zeekad.dashboard.security.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * 로그인 및 관리자 TOTP 2단계 인증 컨트롤러.
 */
@Controller
public class AuthController {

    private final UserMapper userMapper;
    private final TotpService totpService;
    private final AuditService auditService;
    private final ClientIpResolver clientIpResolver;
    private final Clock clock;

    public AuthController(UserMapper userMapper,
                          TotpService totpService,
                          AuditService auditService,
                          ClientIpResolver clientIpResolver,
                          Clock clock) {
        this.userMapper = userMapper;
        this.totpService = totpService;
        this.auditService = auditService;
        this.clientIpResolver = clientIpResolver;
        this.clock = clock;
    }

    @GetMapping("/login")
    public String loginPage(Authentication authentication, HttpSession session) {
        if (authentication != null && authentication.isAuthenticated()
                && Boolean.TRUE.equals(session.getAttribute(SessionAttributes.TOTP_VERIFIED))) {
            return "redirect:/";
        }
        return "login";
    }

    @GetMapping("/login/totp")
    public String totpVerifyPage(Authentication authentication, HttpSession session) {
        DashboardUser user = userMapper.findByUsername(authentication.getName());
        if (user == null) {
            return "redirect:/login";
        }
        if (!user.isTotpEnabled()) {
            return "redirect:/login/totp/setup";
        }
        if (Boolean.TRUE.equals(session.getAttribute(SessionAttributes.TOTP_VERIFIED))) {
            return "redirect:/";
        }
        return "totp-verify";
    }

    @PostMapping("/login/totp")
    public String verifyTotp(@RequestParam("code") String code,
                             Authentication authentication,
                             HttpServletRequest request,
                             HttpSession session,
                             Model model) {
        DashboardUser user = userMapper.findByUsername(authentication.getName());
        if (user == null) {
            return "redirect:/login";
        }
        if (!user.isTotpEnabled()) {
            return "redirect:/login/totp/setup";
        }
        if (!totpService.verifyCode(user.getTotpSecret(), code)) {
            model.addAttribute("errorMessage", "인증 코드가 올바르지 않습니다.");
            return "totp-verify";
        }
        session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.TRUE);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.TOTP_VERIFIED,
                Map.of("mode", "verify"), clientIpResolver.resolve(request));
        return "redirect:/";
    }

    @GetMapping("/login/totp/setup")
    public String totpSetupPage(Authentication authentication, HttpSession session, Model model) {
        DashboardUser user = userMapper.findByUsername(authentication.getName());
        if (user == null) {
            return "redirect:/login";
        }
        if (user.isTotpEnabled()) {
            return "redirect:/login/totp";
        }
        if (Boolean.TRUE.equals(session.getAttribute(SessionAttributes.TOTP_VERIFIED))) {
            return "redirect:/";
        }
        String secret = ensureSecret(user);
        model.addAttribute("totpSecret", secret);
        model.addAttribute("otpauthUri", totpService.buildOtpAuthUri(user.getUsername(), secret));
        return "totp-setup";
    }

    @PostMapping("/login/totp/setup")
    public String completeTotpSetup(@RequestParam("code") String code,
                                    Authentication authentication,
                                    HttpServletRequest request,
                                    HttpSession session,
                                    Model model) {
        DashboardUser user = userMapper.findByUsername(authentication.getName());
        if (user == null) {
            return "redirect:/login";
        }
        if (user.isTotpEnabled()) {
            return "redirect:/login/totp";
        }
        String secret = ensureSecret(user);
        if (!totpService.verifyCode(secret, code)) {
            model.addAttribute("totpSecret", secret);
            model.addAttribute("otpauthUri", totpService.buildOtpAuthUri(user.getUsername(), secret));
            model.addAttribute("errorMessage", "인증 코드가 올바르지 않습니다. 시간 동기화와 6자리 숫자를 확인하세요.");
            return "totp-setup";
        }

        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.updateTotpState(user.getId(), secret, true, now);
        session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.TRUE);
        auditService.recordAuthEvent(user.getUsername(), user.getRole().name(), AuditActionType.TOTP_VERIFIED,
                Map.of("mode", "setup"), clientIpResolver.resolve(request));
        return "redirect:/";
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
}
