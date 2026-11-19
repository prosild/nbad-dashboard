package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.AdminAuditLogsResponse;
import com.zeekad.dashboard.dto.AdminUserDto;
import com.zeekad.dashboard.dto.AdminUserMutationResponse;
import com.zeekad.dashboard.dto.AdminUsersListResponse;
import com.zeekad.dashboard.dto.ApiErrorResponse;
import com.zeekad.dashboard.dto.CreateUserRequest;
import com.zeekad.dashboard.dto.UpdateUserRequest;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * 관리자 전용 사용자 관리 및 감사 로그 조회 REST API 컨트롤러.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminApiController {

    private final UserAdminService userAdminService;
    private final ClientIpResolver clientIpResolver;

    public AdminApiController(UserAdminService userAdminService, ClientIpResolver clientIpResolver) {
        this.userAdminService = userAdminService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/users")
    public ResponseEntity<AdminUsersListResponse> listUsers() {
        List<AdminUserDto> users = userAdminService.listUsersWithPatterns().stream()
                .map(AdminUserDto::from)
                .toList();
        return ResponseEntity.ok(new AdminUsersListResponse(users, List.of(UserRole.values())));
    }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest body,
                                        Authentication authentication,
                                        HttpServletRequest request) {
        try {
            DashboardUser created = userAdminService.createUser(
                    body.username(),
                    body.displayName(),
                    body.password(),
                    UserRole.fromString(body.role()),
                    joinCapturePatterns(body.capturePatterns()),
                    authentication.getName(),
                    "ADMIN",
                    clientIpResolver.resolve(request));
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new AdminUserMutationResponse("사용자가 생성되었습니다.", AdminUserDto.from(created)));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiErrorResponse(400, "INVALID_REQUEST", ex.getMessage()));
        }
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable("id") Long id,
                                        @RequestBody UpdateUserRequest body,
                                        Authentication authentication,
                                        HttpServletRequest request) {
        try {
            DashboardUser updated = userAdminService.updateUserAccess(
                    id,
                    body.displayName(),
                    UserRole.fromString(body.role()),
                    joinCapturePatterns(body.capturePatterns()),
                    authentication.getName(),
                    "ADMIN",
                    clientIpResolver.resolve(request));
            return ResponseEntity.ok(new AdminUserMutationResponse("사용자 정보가 수정되었습니다.", AdminUserDto.from(updated)));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiErrorResponse(400, "INVALID_REQUEST", ex.getMessage()));
        }
    }

    @PostMapping("/users/{id}/toggle-enabled")
    public ResponseEntity<?> toggleEnabled(@PathVariable("id") Long id,
                                           Authentication authentication,
                                           HttpServletRequest request) {
        try {
            DashboardUser updated = userAdminService.toggleEnabled(
                    id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            return ResponseEntity.ok(new AdminUserMutationResponse("계정 활성 상태가 변경되었습니다.", AdminUserDto.from(updated)));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiErrorResponse(400, "INVALID_REQUEST", ex.getMessage()));
        }
    }

    @PostMapping("/users/{id}/unlock")
    public ResponseEntity<?> unlockUser(@PathVariable("id") Long id,
                                        Authentication authentication,
                                        HttpServletRequest request) {
        try {
            DashboardUser updated = userAdminService.unlockUser(
                    id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            return ResponseEntity.ok(new AdminUserMutationResponse("계정 잠금이 해제되었습니다.", AdminUserDto.from(updated)));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiErrorResponse(400, "INVALID_REQUEST", ex.getMessage()));
        }
    }

    @PostMapping("/users/{id}/reset-totp")
    public ResponseEntity<?> resetTotp(@PathVariable("id") Long id,
                                       Authentication authentication,
                                       HttpServletRequest request) {
        try {
            DashboardUser updated = userAdminService.resetTotp(
                    id, authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            return ResponseEntity.ok(new AdminUserMutationResponse("관리자 TOTP가 초기화되었습니다.", AdminUserDto.from(updated)));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ApiErrorResponse(400, "INVALID_REQUEST", ex.getMessage()));
        }
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<AdminAuditLogsResponse> listAuditLogs(
            @RequestParam(name = "actionType", required = false) String actionType,
            @RequestParam(name = "actorUsername", required = false) String actorUsername,
            @RequestParam(name = "limit", defaultValue = "100") int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        String cleanAction = actionType == null ? "" : actionType.trim();
        String cleanActor = actorUsername == null ? "" : actorUsername.trim();
        List<AuditLog> logs = userAdminService.findAuditLogs(cleanAction, cleanActor, safeLimit);

        return ResponseEntity.ok(new AdminAuditLogsResponse(
                logs,
                List.of(AuditActionType.values()),
                cleanAction,
                cleanActor,
                safeLimit
        ));
    }

    private String joinCapturePatterns(List<String> capturePatterns) {
        if (capturePatterns == null || capturePatterns.isEmpty()) {
            throw new IllegalArgumentException("허용 캡처 패턴을 하나 이상 입력해야 합니다.");
        }
        return capturePatterns.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.joining("\n"));
    }
}
