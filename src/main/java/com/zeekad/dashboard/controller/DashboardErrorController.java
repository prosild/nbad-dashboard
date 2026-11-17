package com.zeekad.dashboard.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 서블릿 오류 경로(/error)에서 스택 트레이스를 노출하지 않고 정제된 오류 페이지를 렌더링한다.
 */
@Controller
public class DashboardErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, HttpServletResponse response, Model model) {
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

        response.setStatus(statusCode);
        model.addAttribute("statusCode", statusCode);
        if (statusCode == 403) {
            model.addAttribute("errorTitle", "접근 권한이 없습니다");
            model.addAttribute("errorMessage", "요청하신 페이지에 접근할 권한이 없습니다.");
        } else if (statusCode == 404) {
            model.addAttribute("errorTitle", "페이지를 찾을 수 없습니다");
            model.addAttribute("errorMessage", "요청하신 경로가 존재하지 않습니다.");
        } else {
            model.addAttribute("errorTitle", "요청을 처리할 수 없습니다");
            model.addAttribute("errorMessage", "오류가 발생했습니다. 관리자에게 문의하세요.");
        }
        return "error";
    }
}
