package com.zeekad.dashboard;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.BootstrapUserInitializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.time.Clock;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class BootstrapInitializerTest {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TotpService totpService;

    @Autowired
    private DataSource appDataSource;

    @Autowired
    private Clock clock;

    @Test
    void skipsSeedWithoutPasswordsAndSeedsFourUsersWhenConfigured() {
        JdbcTemplate jdbc = new JdbcTemplate(appDataSource);
        jdbc.update("DELETE FROM user_capture_access");
        jdbc.update("DELETE FROM users");

        DashboardProperties emptyProps = new DashboardProperties();
        BootstrapUserInitializer emptyInit = new BootstrapUserInitializer(
                userMapper, passwordEncoder, totpService, emptyProps, clock);
        emptyInit.seedIfEmpty();
        assertThat(userMapper.countAll()).isZero();

        DashboardProperties props = new DashboardProperties();
        props.getBootstrap().setCommonPassword("InitPass!123");
        BootstrapUserInitializer initWithCommon = new BootstrapUserInitializer(
                userMapper, passwordEncoder, totpService, props, clock);
        initWithCommon.seedIfEmpty();

        assertThat(userMapper.countAll()).isEqualTo(4L);
        DashboardUser viewer1 = userMapper.findByUsername("viewer1");
        DashboardUser analyst1 = userMapper.findByUsername("analyst1");
        DashboardUser analyst2 = userMapper.findByUsername("analyst2");
        DashboardUser admin = userMapper.findByUsername("admin");

        assertThat(viewer1).isNotNull();
        assertThat(passwordEncoder.matches("InitPass!123", viewer1.getPasswordHash())).isTrue();
        assertThat(userMapper.findCapturePatternsByUserId(viewer1.getId())).containsExactly("cic17-*");
        assertThat(userMapper.findCapturePatternsByUserId(analyst1.getId())).containsExactly("cic17-*");
        assertThat(userMapper.findCapturePatternsByUserId(analyst2.getId())).containsExactly("syn1-*");
        assertThat(userMapper.findCapturePatternsByUserId(admin.getId())).containsExactly("*");
        assertThat(admin.getTotpSecret()).isNotBlank();
        assertThat(admin.isTotpEnabled()).isFalse();

        // Clean up and verify BOOTSTRAP_ADMIN_TOTP_SECRET sets totp_enabled=true
        jdbc.update("DELETE FROM user_capture_access");
        jdbc.update("DELETE FROM users");

        DashboardProperties totpProps = new DashboardProperties();
        totpProps.getBootstrap().setAdminPassword("AdminOnly!123");
        totpProps.getBootstrap().setAdminTotpSecret("JBSWY3DPEHPK3PXP");
        BootstrapUserInitializer initWithTotp = new BootstrapUserInitializer(
                userMapper, passwordEncoder, totpService, totpProps, clock);
        initWithTotp.seedIfEmpty();

        DashboardUser seededAdmin = userMapper.findByUsername("admin");
        assertThat(seededAdmin).isNotNull();
        assertThat(seededAdmin.isTotpEnabled()).isTrue();
        assertThat(seededAdmin.getTotpSecret()).isEqualTo("JBSWY3DPEHPK3PXP");

        // Cleanup so other tests start clean
        jdbc.update("DELETE FROM user_capture_access");
        jdbc.update("DELETE FROM users");
    }
}
