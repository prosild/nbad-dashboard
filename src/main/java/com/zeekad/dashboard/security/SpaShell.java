package com.zeekad.dashboard.security;

import com.zeekad.dashboard.controller.SpaForwardController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.PathContainer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * T27: 화면 경로를 새로 연 페이지 요청이 인증 없음·세션 만료·ADMIN OTP 미완료일 때
 * 302 대신 SPA 셸(index.html, 데이터 없음)을 200으로 준다. 화면의 RequireAuth가 그 순간의 주소를 라우터 상태에 실어
 * 로그인·OTP 화면으로 보낸다(원래 주소를 URL 쿼리나 서버 세션에 두지 않는다).
 *
 * <p>대상: GET·HEAD이고 /api가 아니며 SpaForwardController가 화면을 주는 경로(같은 @GetMapping 목록을 읽는다)만이다.
 * 정적 파일과 그 밖의 경로는 지금 동작 그대로다.</p>
 */
public final class SpaShell {

    private static final List<PathPattern> ROUTES = loadRoutes();

    private SpaShell() {
    }

    private static List<PathPattern> loadRoutes() {
        try {
            GetMapping mapping = SpaForwardController.class.getMethod("forwardToSpaShell").getAnnotation(GetMapping.class);
            PathPatternParser parser = new PathPatternParser();
            return Arrays.stream(mapping.value()).map(parser::parse).toList();
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("SpaForwardController 화면 경로를 읽지 못했습니다.", e);
        }
    }

    /** 셸을 줄 수 있는 요청인지(GET·HEAD, /api 아님, 화면 경로) */
    public static boolean isShellRequest(HttpServletRequest request) {
        String method = request.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            return false;
        }
        String uri = request.getRequestURI();
        String context = request.getContextPath() == null ? "" : request.getContextPath();
        String path = uri.startsWith(context) ? uri.substring(context.length()) : uri;
        if (path.isEmpty()) {
            path = "/";
        }
        if (path.equals("/api") || path.startsWith("/api/")) {
            return false;
        }
        PathContainer container = PathContainer.parsePath(path);
        for (PathPattern p : ROUTES) {
            if (p.matches(container)) {
                return true;
            }
        }
        return false;
    }

    /** 셸을 200으로 준다. 보안 헤더는 기존 헤더 필터가 붙이고, 여기서는 캐시만 막는다. */
    public static void forward(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Cache-Control", "no-store");
        request.getRequestDispatcher("/index.html").forward(request, response);
    }

    /** 시험용: 읽은 화면 경로 수 */
    static int routeCount() {
        return ROUTES.size();
    }
}
