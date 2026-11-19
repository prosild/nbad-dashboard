package com.zeekad.dashboard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * API 요청 경로 판별 및 JSON 오류 응답 직접 출력 유틸리티.
 */
public final class ApiRequestUtils {

    private ApiRequestUtils() {
    }

    public static String extractRelativePath(HttpServletRequest request) {
        if (request == null) {
            return "";
        }
        String uri = request.getRequestURI();
        if (uri == null) {
            return "";
        }
        String ctx = request.getContextPath();
        if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
            return uri.substring(ctx.length());
        }
        return uri;
    }

    public static boolean isApiRequest(HttpServletRequest request) {
        String path = extractRelativePath(request);
        return path.equals("/api") || path.startsWith("/api/");
    }

    public static void writeJsonError(HttpServletResponse response,
                                      ObjectMapper objectMapper,
                                      int status,
                                      String code,
                                      String message) throws IOException {
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        objectMapper.writeValue(response.getWriter(), new ApiErrorResponse(status, code, message));
    }
}
