package com.zeekad.dashboard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * ADMIN 계정이 TOTP 2단계 인증을 완료하기 전에는 허용된 인증/정적 리소스 외 접근을 차단한다.
 */
@Component
public class TotpEnforcementFilter extends OncePerRequestFilter {

    private final UserMapper userMapper;
    private final ObjectMapper objectMapper;

    public TotpEnforcementFilter(UserMapper userMapper, ObjectMapper objectMapper) {
        this.userMapper = userMapper;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken) && isAdmin(auth)) {
            HttpSession session = request.getSession(false);
            boolean totpVerified = session != null
                    && Boolean.TRUE.equals(session.getAttribute(SessionAttributes.TOTP_VERIFIED));

            if (!totpVerified && !isAllowedDuringTotp(request)) {
                boolean totpEnabled = resolveTotpEnabled(auth.getName());
                if (ApiRequestUtils.isApiRequest(request)) {
                    String code = totpEnabled ? "TOTP_VERIFICATION_REQUIRED" : "TOTP_SETUP_REQUIRED";
                    String message = totpEnabled
                            ? "TOTP 2단계 인증이 필요합니다."
                            : "TOTP 2단계 인증 등록이 필요합니다.";
                    ApiRequestUtils.writeJsonError(
                            response,
                            objectMapper,
                            HttpServletResponse.SC_FORBIDDEN,
                            code,
                            message);
                    return;
                }
                String target = totpEnabled ? "/login/totp" : "/login/totp/setup";
                response.sendRedirect(request.getContextPath() + target);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAdmin(Authentication auth) {
        for (GrantedAuthority authority : auth.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    private boolean isAllowedDuringTotp(HttpServletRequest request) {
        String path = ApiRequestUtils.extractRelativePath(request);
        return path.equals("/api/auth/me")
                || path.equals("/api/auth/csrf")
                || path.equals("/api/auth/logout")
                || path.equals("/api/auth/totp")
                || path.startsWith("/api/auth/totp/")
                || path.equals("/login")
                || path.equals("/login/totp")
                || path.startsWith("/login/totp/")
                || path.startsWith("/assets/")
                || path.equals("/index.html")
                || path.equals("/favicon.ico")
                || path.equals("/error");
    }

    private boolean resolveTotpEnabled(String username) {
        DashboardUser user = userMapper.findByUsername(username);
        return user != null && user.isTotpEnabled();
    }
}
