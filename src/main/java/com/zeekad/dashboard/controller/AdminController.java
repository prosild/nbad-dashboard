package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * 관리자 전용 사용자 관리 및 감사 로그 조회 컨트롤러.
 */
@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserAdminService userAdminService;
    private final ClientIpResolver clientIpResolver;

    public AdminController(UserAdminService userAdminService, ClientIpResolver clientIpResolver) {
        this.userAdminService = userAdminService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        model.addAttribute("activeMenu", "admin-users");
        model.addAttribute("users", userAdminService.listUsersWithPatterns());
        model.addAttribute("roles", UserRole.values());
        return "admin/users";
    }

    @PostMapping("/users")
    public String createUser(@RequestParam("username") String username,
                             @RequestParam("displayName") String displayName,
                             @RequestParam("password") String password,
                             @RequestParam("role") String role,
                             @RequestParam("capturePatterns") String capturePatterns,
                             Authentication authentication,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        try {
            userAdminService.createUser(
                    username,
                    displayName,
                    password,
                    UserRole.fromString(role),
                    capturePatterns,
                    authentication.getName(),
                    "ADMIN",
                    clientIpResolver.resolve(request));
            redirectAttributes.addFlashAttribute("successMessage", "사용자가 생성되었습니다.");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/update")
    public String updateUser(@PathVariable("id") Long id,
                             @RequestParam("displayName") String displayName,
                             @RequestParam("role") String role,
                             @RequestParam("capturePatterns") String capturePatterns,
                             Authentication authentication,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        try {
            userAdminService.updateUserAccess(
                    id,
                    displayName,
                    UserRole.fromString(role),
                    capturePatterns,
                    authentication.getName(),
                    "ADMIN",
                    clientIpResolver.resolve(request));
            redirectAttributes.addFlashAttribute("successMessage", "사용자 정보가 수정되었습니다.");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/toggle-enabled")
    public String toggleEnabled(@PathVariable("id") Long id,
                                Authentication authentication,
                                HttpServletRequest request,
                                RedirectAttributes redirectAttributes) {
        try {
            userAdminService.toggleEnabled(id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            redirectAttributes.addFlashAttribute("successMessage", "계정 활성 상태가 변경되었습니다.");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/unlock")
    public String unlockUser(@PathVariable("id") Long id,
                             Authentication authentication,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        try {
            userAdminService.unlockUser(id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            redirectAttributes.addFlashAttribute("successMessage", "계정 잠금이 해제되었습니다.");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/reset-totp")
    public String resetTotp(@PathVariable("id") Long id,
                            Authentication authentication,
                            HttpServletRequest request,
                            RedirectAttributes redirectAttributes) {
        try {
            userAdminService.resetTotp(id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            redirectAttributes.addFlashAttribute("successMessage", "관리자 TOTP가 초기화되었습니다.");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @GetMapping("/audit-logs")
    public String listAuditLogs(@RequestParam(name = "actionType", required = false) String actionType,
                                @RequestParam(name = "actorUsername", required = false) String actorUsername,
                                @RequestParam(name = "limit", defaultValue = "100") int limit,
                                Model model) {
        model.addAttribute("activeMenu", "admin-audit");
        model.addAttribute("logs", userAdminService.findAuditLogs(actionType, actorUsername, limit));
        model.addAttribute("actionTypes", AuditActionType.values());
        model.addAttribute("selectedActionType", actionType == null ? "" : actionType);
        model.addAttribute("selectedActorUsername", actorUsername == null ? "" : actorUsername);
        model.addAttribute("selectedLimit", Math.max(1, Math.min(limit, 500)));
        return "admin/audit-logs";
    }
}
