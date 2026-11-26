package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.ApiErrorResponse;
import com.zeekad.dashboard.security.SpaShell;
import com.zeekad.dashboard.service.QueueQueryException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.io.IOException;

/**
 * 예외 발생 시 스택 트레이스와 내부 클래스명을 숨기고 일관된 JSON 오류 응답을 반환한다.
 * 예외 하나(T50): 로그인한 사용자가 브라우저로 연 없는 경로에는 JSON 대신 SPA 셸을 404로 준다.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        log.warn("접근 거부: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiErrorResponse(403, "FORBIDDEN", "요청하신 기능을 수행할 권한이 없습니다."));
    }

    /**
     * 없는 경로. 같은 주소가 Accept에 따라 다른 본문(셸 또는 JSON)을 주므로 두 응답 모두 Vary: Accept를 붙인다.
     * 셸을 주는 조건은 {@link SpaShell#isNotFoundShellRequest}에 있다(로그인한 GET, 제외 경로 밖, text/html을 앞세운 Accept).
     * 셸로 넘긴 뒤에는 응답이 끝났으므로 null을 돌려준다.
     */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ResponseEntity<ApiErrorResponse> handleNotFound(Exception ex,
                                                           HttpServletRequest request,
                                                           HttpServletResponse response)
            throws ServletException, IOException {
        if (!response.isCommitted() && SpaShell.isNotFoundShellRequest(request)) {
            response.addHeader(HttpHeaders.VARY, HttpHeaders.ACCEPT);
            SpaShell.forwardNotFound(request, response);
            return null;
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .varyBy(HttpHeaders.ACCEPT)
                .body(new ApiErrorResponse(404, "NOT_FOUND", "요청하신 경로를 찾을 수 없습니다."));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(new ApiErrorResponse(405, "METHOD_NOT_ALLOWED", "지원되지 않는 HTTP 메서드입니다."));
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            MethodArgumentTypeMismatchException.class,
            MissingServletRequestParameterException.class,
            MethodArgumentNotValidException.class
    })
    public ResponseEntity<ApiErrorResponse> handleBadRequest(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiErrorResponse(400, "INVALID_REQUEST", "요청 형식이 올바르지 않습니다."));
    }

    /** T23 통합 큐 요청 값 오류. 메시지는 서버가 정한 고정 문구라 그대로 보인다. */
    @ExceptionHandler(QueueQueryException.class)
    public ResponseEntity<ApiErrorResponse> handleQueueQuery(QueueQueryException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiErrorResponse(400, ex.getCode(), ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpectedException(Exception ex) {
        log.error("처리되지 않은 서버 오류", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiErrorResponse(500, "INTERNAL_ERROR", "일시적인 오류가 발생했습니다. 잠시 후 다시 시도하세요."));
    }
}
