package com.zeekad.dashboard.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 로그인 실패 시 내부 예외를 노출하지 않고 안전한 오류 상태 코드로 리다이렉트한다.
 */
@Component
public class DashboardAuthFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String param = "error";
        if (exception instanceof LockedException) {
            param = "locked";
        } else if (exception instanceof DisabledException) {
            param = "disabled";
        }
        response.sendRedirect(request.getContextPath() + "/login?" + param);
    }
}
