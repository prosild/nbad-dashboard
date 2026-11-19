package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ApiErrorResponse;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 서블릿 오류 경로(/error)에서 스택 트레이스를 노출하지 않고 일관된 JSON 오류 응답을 반환한다.
 */
@RestController
public class DashboardErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<ApiErrorResponse> handleError(HttpServletRequest request) {
        Object statusAttr = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int statusCode = 500;
        if (statusAttr != null) {
            try {
                statusCode = Integer.parseInt(statusAttr.toString());
            } catch (NumberFormatException ignored) {
                statusCode = 500;
            }
        } else if (request.getParameter("forbidden") != null) {
            statusCode = HttpStatus.FORBIDDEN.value();
        }

        if (statusCode == 401) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiErrorResponse(401, "UNAUTHENTICATED", "인증이 필요합니다. 로그인해 주세요."));
        }
        if (statusCode == 403) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiErrorResponse(403, "FORBIDDEN", "요청하신 경로에 접근할 권한이 없습니다."));
        }
        if (statusCode == 404) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiErrorResponse(404, "NOT_FOUND", "요청하신 경로를 찾을 수 없습니다."));
        }
        if (statusCode == 405) {
            return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                    .body(new ApiErrorResponse(405, "METHOD_NOT_ALLOWED", "지원되지 않는 HTTP 메서드입니다."));
        }
        return ResponseEntity.status(statusCode)
                .body(new ApiErrorResponse(statusCode, "INTERNAL_ERROR", "오류가 발생했습니다. 관리자에게 문의하세요."));
    }
}
