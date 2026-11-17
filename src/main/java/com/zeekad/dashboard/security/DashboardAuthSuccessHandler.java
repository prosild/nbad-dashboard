package com.zeekad.dashboard.security;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.model.UserRole;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Clock;

/**
 * 로그인 성공 시 세션 타임스탬프·TOTP 검증 상태를 초기화하고 역할별 초기 경로로 이동한다.
 */
@Component
public class DashboardAuthSuccessHandler implements AuthenticationSuccessHandler {

    private final DashboardProperties properties;
    private final Clock clock;

    public DashboardAuthSuccessHandler(DashboardProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession(true);
        long nowMillis = clock.instant().toEpochMilli();
        session.setAttribute(SessionAttributes.SESSION_CREATED_AT, nowMillis);
        session.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT, nowMillis);

        int idleSeconds = (int) Math.max(60L, properties.getSecurity().getIdleTimeoutMinutes() * 60L);
        session.setMaxInactiveInterval(idleSeconds);

        if (authentication.getPrincipal() instanceof DashboardUserPrincipal principal
                && principal.getRole() == UserRole.ADMIN) {
            session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.FALSE);
            String target = principal.isTotpEnabled() ? "/login/totp" : "/login/totp/setup";
            response.sendRedirect(request.getContextPath() + target);
            return;
        }

        session.setAttribute(SessionAttributes.TOTP_VERIFIED, Boolean.TRUE);
        response.sendRedirect(request.getContextPath() + "/");
    }
}
