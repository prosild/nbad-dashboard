package com.zeekad.dashboard.security;

import com.zeekad.dashboard.controller.SpaForwardController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.InvalidMimeTypeException;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * T27: 화면 경로를 새로 연 페이지 요청이 인증 없음·세션 만료·ADMIN OTP 미완료일 때
 * 302 대신 SPA 셸(index.html, 데이터 없음)을 200으로 준다. 화면의 RequireAuth가 그 순간의 주소를 라우터 상태에 실어
 * 로그인·OTP 화면으로 보낸다(원래 주소를 URL 쿼리나 서버 세션에 두지 않는다).
 *
 * <p>대상: GET·HEAD이고 /api가 아니며 SpaForwardController가 화면을 주는 경로(같은 @GetMapping 목록을 읽는다)만이다.
 * 정적 파일과 그 밖의 경로는 지금 동작 그대로다.</p>
 *
 * <p>T50: 로그인한 사용자가 브라우저로 연 없는 경로에는 같은 셸을 404로 준다({@link #isNotFoundShellRequest},
 * {@link #forwardNotFound}). 화면의 NotFound가 그린다. 비로그인 요청·API·JSON 요청은 대상이 아니다.</p>
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
        forward(request, response, HttpServletResponse.SC_OK);
    }

    /** T50: 셸을 404로 준다(없는 경로). 본문은 같은 index.html이고 요청 경로를 넣지 않는다. */
    public static void forwardNotFound(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        forward(request, response, HttpServletResponse.SC_NOT_FOUND);
    }

    private static void forward(HttpServletRequest request, HttpServletResponse response, int status)
            throws IOException, ServletException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        request.getRequestDispatcher("/index.html").forward(request, response);
    }

    /**
     * T50: 없는 경로(처리기가 404를 낸 요청)에 JSON 대신 셸을 줄 요청인지. 모두 참일 때만이다.
     * <ol>
     *   <li>GET이다.</li>
     *   <li>로그인을 마친 요청이다(익명이 아닌 인증). permitAll 경로는 비로그인 요청도 처리기까지 오므로
     *       처리기까지 왔다는 것만으로 로그인으로 보지 않는다.</li>
     *   <li>경로가 제외 목록(/api, /assets, /index.html, /favicon.ico, /error, /actuator) 밖이다.</li>
     *   <li>Accept를 구체성·q로 정렬했을 때 text/html이 application/json보다 앞이다
     *       (application/json이 없으면 text/html이 있기만 하면 된다). Accept가 없거나 읽지 못하면 아니다.</li>
     * </ol>
     */
    public static boolean isNotFoundShellRequest(HttpServletRequest request) {
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        if (isNotFoundShellExcluded(UrlPathHelper.defaultInstance.getPathWithinApplication(request))) {
            return false;
        }
        return acceptPrefersHtml(Collections.list(request.getHeaders(HttpHeaders.ACCEPT)));
    }

    /** 셸을 주지 않는 경로(디코딩한 경로로 본다): API, 정적 파일, 오류 경로, 액추에이터 */
    static boolean isNotFoundShellExcluded(String path) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        return underPrefix(path, "/api")
                || underPrefix(path, "/assets")
                || underPrefix(path, "/actuator")
                || path.equals("/index.html")
                || path.equals("/favicon.ico")
                || path.equals("/error");
    }

    private static boolean underPrefix(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }

    /**
     * Accept 값들을 구체성·q로 정렬해(같으면 적힌 순서) text/html이 application/json보다 앞인지 본다.
     * 브라우저 탐색(text/html이 맨 앞)은 참이다. JSON을 앞세운 값(application/json, text/html;q=0.9)과
     * 없음·와일드카드뿐·읽지 못하는 값은 거짓이다. q=0은 받지 않는다는 뜻이라 없는 것으로 본다.
     */
    static boolean acceptPrefersHtml(List<String> acceptHeaderValues) {
        List<MediaType> types;
        try {
            types = new ArrayList<>(MediaType.parseMediaTypes(acceptHeaderValues));
            // MediaType은 q를 먼저, 그다음 구체성을 견준다(MediaType.sortBySpecificityAndQuality와 같은 순서)
            MimeTypeUtils.sortBySpecificity(types);
        } catch (InvalidMediaTypeException | InvalidMimeTypeException e) {
            return false;
        }
        int html = -1;
        int json = -1;
        for (int i = 0; i < types.size(); i++) {
            MediaType type = types.get(i);
            if (type.getQualityValue() <= 0) {
                continue;
            }
            if (html < 0 && type.equalsTypeAndSubtype(MediaType.TEXT_HTML)) {
                html = i;
            } else if (json < 0 && type.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
                json = i;
            }
        }
        return html >= 0 && (json < 0 || html < json);
    }

    /** 시험용: 읽은 화면 경로 수 */
    static int routeCount() {
        return ROUTES.size();
    }
}
