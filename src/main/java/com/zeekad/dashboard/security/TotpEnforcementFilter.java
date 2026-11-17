package com.zeekad.dashboard.security;

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
 * ADMIN 계정이 TOTP 2단계 인증을 완료하기 전에는 TOTP/로그아웃/정적 리소스 외 접근을 차단한다.
 */
@Component
public class TotpEnforcementFilter extends OncePerRequestFilter {

    private final UserMapper userMapper;

    public TotpEnforcementFilter(UserMapper userMapper) {
        this.userMapper = userMapper;
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
                String path = extractRelativePath(request);
                if (path.startsWith("/api/")) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "TOTP verification required");
                    return;
                }
                boolean totpEnabled = resolveTotpEnabled(auth.getName());
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
        String path = extractRelativePath(request);
        return path.equals("/login/totp")
                || path.startsWith("/login/totp/")
                || path.equals("/logout")
                || path.equals("/error")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || path.equals("/favicon.ico");
    }

    private String extractRelativePath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
            return uri.substring(ctx.length());
        }
        return uri;
    }

    private boolean resolveTotpEnabled(String username) {
        DashboardUser user = userMapper.findByUsername(username);
        return user != null && user.isTotpEnabled();
    }
}
