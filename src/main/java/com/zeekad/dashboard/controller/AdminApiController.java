package com.zeekad.dashboard.controller;

import com.zeekad.dashboard.dto.AdminAuditLogsResponse;
import com.zeekad.dashboard.dto.AdminUserDto;
import com.zeekad.dashboard.dto.AdminUserMutationResponse;
import com.zeekad.dashboard.dto.AdminUsersListResponse;
import com.zeekad.dashboard.dto.ApiErrorResponse;
import com.zeekad.dashboard.dto.CreateUserRequest;
import com.zeekad.dashboard.dto.CriticalAssetDtos;
import com.zeekad.dashboard.dto.UpdateUserRequest;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.CriticalAsset;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.ClientIpResolver;
import com.zeekad.dashboard.service.CriticalAssetException;
import com.zeekad.dashboard.service.CriticalAssetService;
import com.zeekad.dashboard.service.QueueQueryException;
import com.zeekad.dashboard.service.ResponseTextCatalog;
import com.zeekad.dashboard.service.ResponseTextGuard;
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
 * 관리자 전용 사용자 관리, 감사 로그 조회, 중요 자산(T52) REST API 컨트롤러.
 * 지우기도 POST(…/{id}/delete)다. WAF 허용 메서드에 DELETE가 없고 앱도 DELETE를 쓰지 않는다.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminApiController {

    private final UserAdminService userAdminService;
    private final CriticalAssetService criticalAssetService;
    private final ClientIpResolver clientIpResolver;
    private final ResponseTextGuard responseTextGuard;

    /** T63 감사 로그 행위자 검색어 상한(UTF-16 단위, 큐 asset·호스트 위험도 q와 같다) */
    static final int ACTOR_QUERY_MAX_LENGTH = 100;

    public AdminApiController(UserAdminService userAdminService,
                              CriticalAssetService criticalAssetService,
                              ClientIpResolver clientIpResolver,
                              ResponseTextGuard responseTextGuard) {
        this.userAdminService = userAdminService;
        this.criticalAssetService = criticalAssetService;
        this.clientIpResolver = clientIpResolver;
        this.responseTextGuard = responseTextGuard;
    }

    /* ───────────── T52 중요 자산 ───────────── */

    @GetMapping("/critical-assets")
    public ResponseEntity<ResponseTextGuard.GuardedJson> listCriticalAssets() {
        List<CriticalAssetDtos.Item> items = criticalAssetService.list().stream()
                .map(CriticalAssetDtos.Item::from)
                .toList();
        // T63: 이름·설명은 관리자가 넣은 글이다(제어 문자는 받지 않지만 방향 전환 같은 서식 문자는 들 수 있다). 관리자에게 표지·상한
        return ResponseEntity.ok(responseTextGuard.apply(new CriticalAssetDtos.ListResponse(items, CriticalAssetService.MAX_ASSETS),
                UserRole.ADMIN, ResponseTextCatalog.CRITICAL_ASSETS));
    }

    @PostMapping("/critical-assets")
    public ResponseEntity<?> createCriticalAsset(@RequestBody(required = false) CriticalAssetDtos.CreateRequest body,
                                                 Authentication authentication,
                                                 HttpServletRequest request) {
        if (body == null) {
            return criticalAssetError(new CriticalAssetException(400, "INVALID_REQUEST", "요청 본문이 필요합니다."));
        }
        try {
            CriticalAsset created = criticalAssetService.create(body.hostIp(), body.name(), body.description(),
                    authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(mutation(new CriticalAssetDtos.MutationResponse("중요 자산을 등록했습니다.", CriticalAssetDtos.Item.from(created))));
        } catch (CriticalAssetException ex) {
            return criticalAssetError(ex);
        }
    }

    /** 이름·설명만 고친다(본문의 주소는 쓰지 않는다. 주소를 바꾸려면 지우고 새로 만든다) */
    @PutMapping("/critical-assets/{id}")
    public ResponseEntity<?> updateCriticalAsset(@PathVariable("id") long id,
                                                 @RequestBody(required = false) CriticalAssetDtos.UpdateRequest body,
                                                 Authentication authentication,
                                                 HttpServletRequest request) {
        if (body == null) {
            return criticalAssetError(new CriticalAssetException(400, "INVALID_REQUEST", "요청 본문이 필요합니다."));
        }
        try {
            CriticalAsset updated = criticalAssetService.update(id, body.name(), body.description(),
                    authentication.getName(), "ADMIN", clientIpResolver.resolve(request));
            return ResponseEntity.ok(mutation(new CriticalAssetDtos.MutationResponse("중요 자산을 수정했습니다.", CriticalAssetDtos.Item.from(updated))));
        } catch (CriticalAssetException ex) {
            return criticalAssetError(ex);
        }
    }

    /** 지우기(본문 없음). DELETE 메서드를 쓰지 않는다 */
    @PostMapping("/critical-assets/{id}/delete")
    public ResponseEntity<?> deleteCriticalAsset(@PathVariable("id") long id,
                                                 Authentication authentication,
                                                 HttpServletRequest request) {
        try {
            CriticalAsset deleted = criticalAssetService.delete(id, authentication.getName(), "ADMIN",
                    clientIpResolver.resolve(request));
            return ResponseEntity.ok(mutation(new CriticalAssetDtos.MutationResponse("중요 자산을 삭제했습니다.", CriticalAssetDtos.Item.from(deleted))));
        } catch (CriticalAssetException ex) {
            return criticalAssetError(ex);
        }
    }

    /** T63: 중요 자산 등록·고침·지우기 응답의 이름·설명에도 목록과 같은 정책 */
    private ResponseTextGuard.GuardedJson mutation(CriticalAssetDtos.MutationResponse body) {
        return responseTextGuard.apply(body, UserRole.ADMIN, ResponseTextCatalog.CRITICAL_ASSET_MUTATION);
    }

    private static ResponseEntity<ApiErrorResponse> criticalAssetError(CriticalAssetException ex) {
        return ResponseEntity.status(ex.getStatus())
                .body(new ApiErrorResponse(ex.getStatus(), ex.getCode(), ex.getMessage()));
    }

    /* ───────────── 사용자 관리 ───────────── */

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
        if (cleanActor.length() > ACTOR_QUERY_MAX_LENGTH) {
            // 400 INVALID_REQUEST(GlobalExceptionHandler가 고정 문구로 돌려준다)
            throw new QueueQueryException("INVALID_REQUEST", "행위자 검색어는 100자를 넘을 수 없습니다.");
        }
        List<AuditLog> logs = userAdminService.findAuditLogs(cleanAction, cleanActor, safeLimit);

        AdminAuditLogsResponse body = new AdminAuditLogsResponse(
                logs,
                List.of(AuditActionType.values()),
                cleanAction,
                cleanActor,
                safeLimit
        );
        // T63: 관리자만 보므로 표지. 저장값은 원문(증거)이고 응답에서만 정책을 적용한다.
        // 이 메서드를 바로 부르는 시험(T58)이 있어 응답 형을 그대로 두고 처리한 값으로 되읽는다
        return ResponseEntity.ok(responseTextGuard.applyAs(body, UserRole.ADMIN, ResponseTextCatalog.AUDIT_LOGS,
                AdminAuditLogsResponse.class));
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
