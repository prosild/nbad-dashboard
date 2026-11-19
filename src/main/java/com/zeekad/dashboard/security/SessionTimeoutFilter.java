package com.zeekad.dashboard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.config.DashboardProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;

/**
 * 세션 유휴 만료(기본 30분) 및 절대 만료(기본 8시간)를 매 요청에서 강제한다.
 */
@Component
public class SessionTimeoutFilter extends OncePerRequestFilter {

    private final DashboardProperties properties;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    public SessionTimeoutFilter(DashboardProperties properties, Clock clock, ObjectMapper objectMapper) {
        this.properties = properties;
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        HttpSession session = request.getSession(false);

        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken) && session != null) {
            long nowMillis = clock.instant().toEpochMilli();
            long idleLimitMillis = properties.getSecurity().getIdleTimeoutMinutes() * 60_000L;
            long absoluteLimitMillis = properties.getSecurity().getAbsoluteTimeoutMinutes() * 60_000L;

            Long createdAt = getLongAttribute(session, SessionAttributes.SESSION_CREATED_AT);
            Long lastAccessedAt = getLongAttribute(session, SessionAttributes.SESSION_LAST_ACCESSED_AT);

            if (createdAt == null) {
                session.setAttribute(SessionAttributes.SESSION_CREATED_AT, nowMillis);
                createdAt = nowMillis;
            }
            if (lastAccessedAt == null) {
                session.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT, nowMillis);
                lastAccessedAt = nowMillis;
            }

            boolean idleExpired = (nowMillis - lastAccessedAt) > idleLimitMillis;
            boolean absoluteExpired = (nowMillis - createdAt) > absoluteLimitMillis;

            if (idleExpired || absoluteExpired) {
                session.invalidate();
                SecurityContextHolder.clearContext();
                if (ApiRequestUtils.isApiRequest(request)) {
                    ApiRequestUtils.writeJsonError(
                            response,
                            objectMapper,
                            HttpServletResponse.SC_UNAUTHORIZED,
                            "SESSION_EXPIRED",
                            "세션이 만료되었습니다. 다시 로그인해 주세요.");
                    return;
                }
                response.sendRedirect(request.getContextPath() + "/login?expired");
                return;
            }

            session.setAttribute(SessionAttributes.SESSION_LAST_ACCESSED_AT, nowMillis);
        }

        filterChain.doFilter(request, response);
    }

    private Long getLongAttribute(HttpSession session, String name) {
        Object value = session.getAttribute(name);
        return value instanceof Number num ? num.longValue() : null;
    }
}
