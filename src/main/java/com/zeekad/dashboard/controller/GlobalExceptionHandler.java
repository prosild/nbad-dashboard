package com.zeekad.dashboard.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.ui.Model;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * 예외 발생 시 스택 트레이스와 내부 클래스명을 숨기고 안전한 오류 화면을 반환한다.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public String handleAccessDenied(AccessDeniedException ex, HttpServletResponse response, Model model) {
        log.warn("접근 거부: {}", ex.getMessage());
        response.setStatus(HttpStatus.FORBIDDEN.value());
        model.addAttribute("statusCode", 403);
        model.addAttribute("errorTitle", "접근 권한이 없습니다");
        model.addAttribute("errorMessage", "요청하신 기능을 수행할 권한이 없습니다.");
        return "error";
    }

    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public String handleNotFound(Exception ex, HttpServletResponse response, Model model) {
        response.setStatus(HttpStatus.NOT_FOUND.value());
        model.addAttribute("statusCode", 404);
        model.addAttribute("errorTitle", "페이지를 찾을 수 없습니다");
        model.addAttribute("errorMessage", "요청하신 경로가 존재하지 않습니다.");
        return "error";
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public String handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex,
                                         HttpServletResponse response,
                                         Model model) {
        response.setStatus(HttpStatus.METHOD_NOT_ALLOWED.value());
        model.addAttribute("statusCode", 405);
        model.addAttribute("errorTitle", "허용되지 않은 요청 방식입니다");
        model.addAttribute("errorMessage", "지원되지 않는 HTTP 메서드입니다.");
        return "error";
    }

    @ExceptionHandler(Exception.class)
    public String handleUnexpectedException(Exception ex, HttpServletResponse response, Model model) {
        log.error("처리되지 않은 서버 오류", ex);
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        model.addAttribute("statusCode", 500);
        model.addAttribute("errorTitle", "요청을 처리할 수 없습니다");
        model.addAttribute("errorMessage", "일시적인 오류가 발생했습니다. 잠시 후 다시 시도하세요.");
        return "error";
    }
}
