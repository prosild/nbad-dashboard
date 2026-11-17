package com.zeekad.dashboard.service;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

/**
 * users 테이블이 비어 있고 부트스트랩 비밀번호 환경 변수가 설정된 경우 기본 4계정을 시드한다.
 */
@Component
public class BootstrapUserInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapUserInitializer.class);

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;
    private final DashboardProperties properties;
    private final Clock clock;

    public BootstrapUserInitializer(UserMapper userMapper,
                                    PasswordEncoder passwordEncoder,
                                    TotpService totpService,
                                    DashboardProperties properties,
                                    Clock clock) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.totpService = totpService;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedIfEmpty();
    }

    public void seedIfEmpty() {
        if (userMapper.countAll() > 0) {
            return;
        }

        DashboardProperties.Bootstrap bootstrap = properties.getBootstrap();
        String viewerPwd = resolvePassword(bootstrap.getViewer1Password(), bootstrap.getCommonPassword());
        String analyst1Pwd = resolvePassword(bootstrap.getAnalyst1Password(), bootstrap.getCommonPassword());
        String analyst2Pwd = resolvePassword(bootstrap.getAnalyst2Password(), bootstrap.getCommonPassword());
        String adminPwd = resolvePassword(bootstrap.getAdminPassword(), bootstrap.getCommonPassword());

        if (isBlank(viewerPwd) && isBlank(analyst1Pwd) && isBlank(analyst2Pwd) && isBlank(adminPwd)) {
            log.info("부트스트랩 비밀번호 환경 변수가 설정되지 않아 기본 계정 시드를 건너뜁니다.");
            return;
        }

        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        int seeded = 0;
        seeded += seedUserIfPasswordPresent("viewer1", "조회자 1", viewerPwd, UserRole.VIEWER, List.of("cic17-*"), null, false, now);
        seeded += seedUserIfPasswordPresent("analyst1", "분석가 1", analyst1Pwd, UserRole.ANALYST, List.of("cic17-*"), null, false, now);
        seeded += seedUserIfPasswordPresent("analyst2", "분석가 2", analyst2Pwd, UserRole.ANALYST, List.of("syn1-*"), null, false, now);

        if (!isBlank(adminPwd)) {
            String configuredSecret = bootstrap.getAdminTotpSecret();
            boolean hasConfiguredSecret = !isBlank(configuredSecret);
            String adminSecret = hasConfiguredSecret
                    ? totpService.normalizeSecret(configuredSecret)
                    : totpService.generateSecret();
            seeded += seedUserIfPasswordPresent("admin", "관리자", adminPwd, UserRole.ADMIN, List.of("*"),
                    adminSecret, hasConfiguredSecret, now);
        }

        log.info("초기 대시보드 계정 {}건을 부트스트랩 시드했습니다.", seeded);
    }

    private int seedUserIfPasswordPresent(String username,
                                          String displayName,
                                          String rawPassword,
                                          UserRole role,
                                          List<String> capturePatterns,
                                          String totpSecret,
                                          boolean totpEnabled,
                                          OffsetDateTime now) {
        if (isBlank(rawPassword)) {
            return 0;
        }
        DashboardUser user = new DashboardUser();
        user.setUsername(username);
        user.setDisplayName(displayName);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setRole(role);
        user.setTotpSecret(totpSecret);
        user.setTotpEnabled(totpEnabled);
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        userMapper.insertUser(user);
        for (String pattern : capturePatterns) {
            userMapper.insertCapturePattern(user.getId(), pattern);
        }
        return 1;
    }

    private String resolvePassword(String specific, String common) {
        if (!isBlank(specific)) {
            return specific;
        }
        return isBlank(common) ? null : common;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
