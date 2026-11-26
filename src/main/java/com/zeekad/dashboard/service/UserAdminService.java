package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.CapturePatternMatcher;
import com.zeekad.dashboard.security.TotpService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/**
 * 관리자 사용자 관리 및 감사 로그 조회 서비스.
 */
@Service
public class UserAdminService {

    private final UserMapper userMapper;
    private final AuditLogMapper auditLogMapper;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;
    private final AuditService auditService;
    private final Clock clock;

    public UserAdminService(UserMapper userMapper,
                            AuditLogMapper auditLogMapper,
                            PasswordEncoder passwordEncoder,
                            TotpService totpService,
                            AuditService auditService,
                            Clock clock) {
        this.userMapper = userMapper;
        this.auditLogMapper = auditLogMapper;
        this.passwordEncoder = passwordEncoder;
        this.totpService = totpService;
        this.auditService = auditService;
        this.clock = clock;
    }

    public List<DashboardUser> listUsersWithPatterns() {
        List<DashboardUser> users = userMapper.findAll();
        for (DashboardUser user : users) {
            user.setCapturePatterns(userMapper.findCapturePatternsByUserId(user.getId()));
        }
        return users;
    }

    public List<AuditLog> findAuditLogs(String actionType, String actorUsername, int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        String cleanAction = (actionType == null || actionType.isBlank()) ? null : actionType.trim();
        String cleanActor = (actorUsername == null || actorUsername.isBlank()) ? null : actorUsername.trim();
        return auditLogMapper.findFiltered(cleanAction, likeEscape(cleanActor), safeLimit);
    }

    /**
     * T63: LIKE 검색어의 역슬래시·%·_를 글자 그대로 찾게 이스케이프한다(매퍼는 ESCAPE '\'). H2·PostgreSQL 모두 같은 문장이 돈다
     * (PostgreSQL은 standard_conforming_strings=on 기본값에서 '\'가 한 글자다).
     */
    static String likeEscape(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '%' || c == '_') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    @Transactional
    public DashboardUser createUser(String username,
                                    String displayName,
                                    String rawPassword,
                                    UserRole role,
                                    String rawCapturePatterns,
                                    String actorUsername,
                                    String actorRole,
                                    String clientIp) {
        String cleanUsername = username == null ? "" : username.trim();
        if (!cleanUsername.matches("^[a-zA-Z0-9._-]{3,64}$")) {
            throw new IllegalArgumentException("아이디는 영문, 숫자, '.', '_', '-' 조합 3~64자여야 합니다.");
        }
        String cleanDisplayName = displayName == null ? "" : displayName.trim();
        if (cleanDisplayName.isEmpty() || cleanDisplayName.length() > 150) {
            throw new IllegalArgumentException("표시 이름을 올바르게 입력하세요.");
        }
        if (rawPassword == null || rawPassword.length() < 4) {
            throw new IllegalArgumentException("비밀번호는 4자 이상이어야 합니다.");
        }
        if (userMapper.findByUsername(cleanUsername) != null) {
            throw new IllegalArgumentException("이미 존재하는 사용자 아이디입니다.");
        }
        List<String> patterns = CapturePatternMatcher.parseAndValidateList(rawCapturePatterns);

        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        DashboardUser user = new DashboardUser();
        user.setUsername(cleanUsername);
        user.setDisplayName(cleanDisplayName);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setRole(role);
        user.setTotpSecret(role == UserRole.ADMIN ? totpService.generateSecret() : null);
        user.setTotpEnabled(false);
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);

        userMapper.insertUser(user);
        for (String pattern : patterns) {
            userMapper.insertCapturePattern(user.getId(), pattern);
        }
        user.setCapturePatterns(patterns);

        auditService.record(actorUsername, actorRole, AuditActionType.USER_ADMIN_CHANGE,
                null, null, null,
                Map.of("operation", "CREATE_USER",
                        "targetUsername", cleanUsername,
                        "role", role.name(),
                        "capturePatterns", patterns),
                clientIp);
        return user;
    }

    @Transactional
    public DashboardUser updateUserAccess(Long userId,
                                          String displayName,
                                          UserRole role,
                                          String rawCapturePatterns,
                                          String actorUsername,
                                          String actorRole,
                                          String clientIp) {
        DashboardUser target = requireUser(userId);
        String cleanDisplayName = displayName == null ? "" : displayName.trim();
        if (cleanDisplayName.isEmpty() || cleanDisplayName.length() > 150) {
            throw new IllegalArgumentException("표시 이름을 올바르게 입력하세요.");
        }
        List<String> patterns = CapturePatternMatcher.parseAndValidateList(rawCapturePatterns);
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);

        userMapper.updateUserRoleAndDisplayName(userId, cleanDisplayName, role, now);
        if (role == UserRole.ADMIN && (target.getTotpSecret() == null || target.getTotpSecret().isBlank())) {
            userMapper.updateTotpState(userId, totpService.generateSecret(), false, now);
        }

        userMapper.deleteCapturePatternsByUserId(userId);
        for (String pattern : patterns) {
            userMapper.insertCapturePattern(userId, pattern);
        }

        auditService.record(actorUsername, actorRole, AuditActionType.USER_ADMIN_CHANGE,
                null, null, null,
                Map.of("operation", "UPDATE_USER",
                        "targetUsername", target.getUsername(),
                        "role", role.name(),
                        "capturePatterns", patterns),
                clientIp);
        return requireUserWithPatterns(userId);
    }

    @Transactional
    public DashboardUser toggleEnabled(Long userId,
                                       String actorUsername,
                                       String actorRole,
                                       String clientIp) {
        DashboardUser target = requireUser(userId);
        if (target.isEnabled() && target.getUsername().equalsIgnoreCase(actorUsername)) {
            throw new IllegalArgumentException("현재 로그인된 자신의 계정은 비활성화할 수 없습니다.");
        }
        boolean nextEnabled = !target.isEnabled();
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.updateEnabled(userId, nextEnabled, now);

        auditService.record(actorUsername, actorRole, AuditActionType.USER_ADMIN_CHANGE,
                null, null, null,
                Map.of("operation", "TOGGLE_ENABLED",
                        "targetUsername", target.getUsername(),
                        "enabled", nextEnabled),
                clientIp);
        return requireUserWithPatterns(userId);
    }

    @Transactional
    public DashboardUser unlockUser(Long userId,
                                    String actorUsername,
                                    String actorRole,
                                    String clientIp) {
        DashboardUser target = requireUser(userId);
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        userMapper.resetLoginFailure(userId, now);

        auditService.record(actorUsername, actorRole, AuditActionType.USER_ADMIN_CHANGE,
                null, null, null,
                Map.of("operation", "UNLOCK_ACCOUNT",
                        "targetUsername", target.getUsername()),
                clientIp);
        return requireUserWithPatterns(userId);
    }

    @Transactional
    public DashboardUser resetTotp(Long userId,
                                   String actorUsername,
                                   String actorRole,
                                   String clientIp) {
        DashboardUser target = requireUser(userId);
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        String nextSecret = target.getRole() == UserRole.ADMIN ? totpService.generateSecret() : null;
        userMapper.updateTotpState(userId, nextSecret, false, now);

        auditService.record(actorUsername, actorRole, AuditActionType.USER_ADMIN_CHANGE,
                null, null, null,
                Map.of("operation", "RESET_TOTP",
                        "targetUsername", target.getUsername()),
                clientIp);
        return requireUserWithPatterns(userId);
    }

    private DashboardUser requireUserWithPatterns(Long userId) {
        DashboardUser updated = requireUser(userId);
        updated.setCapturePatterns(userMapper.findCapturePatternsByUserId(userId));
        return updated;
    }

    private DashboardUser requireUser(Long userId) {
        DashboardUser user = userMapper.findById(userId);
        if (user == null) {
            throw new IllegalArgumentException("대상 사용자를 찾을 수 없습니다.");
        }
        return user;
    }
}
