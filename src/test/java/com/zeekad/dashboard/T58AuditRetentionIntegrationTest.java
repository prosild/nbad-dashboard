package com.zeekad.dashboard;

import com.zeekad.dashboard.controller.AdminApiController;
import com.zeekad.dashboard.dto.AdminAuditLogsResponse;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T58 감사 로그 보관 기한: 앱 쪽(H2)에서 볼 수 있는 것만 본다.
 * 기한 지난 행 삭제·TRUNCATE 차단·30일 바닥값은 PostgreSQL에만 있고 scripts/audit-retention-check.ps1이 PostgreSQL에서 직접 시험한다.
 */
@SpringBootTest
@ActiveProfiles("test")
class T58AuditRetentionIntegrationTest {

    @Autowired
    @Qualifier("appDataSource")
    private DataSource appDataSource;

    @Autowired
    private AdminApiController adminApiController;

    @Test
    void v4IsAppliedOnH2AndTheTriggerStillRejectsEveryDelete() {
        JdbcTemplate a = new JdbcTemplate(appDataSource);
        assertThat(a.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version = '4' AND success = TRUE",
                Integer.class)).isEqualTo(1);

        // H2에는 삭제 함수가 없고 트리거는 오래된 행의 DELETE도 거부한다(앱 계정으로 지우는 길이 없다).
        String actor = "t58-h2-old-row";
        a.update("INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES (?, ?, 'SYSTEM', ?)",
                OffsetDateTime.now(ZoneOffset.UTC).minusDays(100), actor, AuditActionType.LOGIN_SUCCESS.name());
        assertThatThrownBy(() -> a.update("DELETE FROM audit_logs WHERE actor_username = ?", actor))
                .rootCause().hasMessageContaining("audit_logs is append-only");
        assertThatThrownBy(() -> a.update("UPDATE audit_logs SET actor_role = 'ADMIN' WHERE actor_username = ?", actor))
                .rootCause().hasMessageContaining("audit_logs is append-only");
        assertThat(a.queryForObject("SELECT COUNT(*) FROM audit_logs WHERE actor_username = ?", Integer.class, actor))
                .isEqualTo(1);
    }

    @Test
    @WithMockUser(username = "t58-admin", roles = "ADMIN")
    void retentionPurgeRowsAreListedAndFilterableInTheAdminAuditApi() {
        // DB 함수가 남기는 행과 같은 꼴(행위자 audit-retention, 역할 SYSTEM, 접속 주소 없음)
        JdbcTemplate a = new JdbcTemplate(appDataSource);
        String detail = "{\"deleted\" : 3, \"cutoff\" : \"2026-08-28T00:00:00Z\", \"retentionDays\" : 90}";
        a.update("INSERT INTO audit_logs (actor_username, actor_role, action_type, detail_json) VALUES (?, ?, ?, ?)",
                "audit-retention", "SYSTEM", "AUDIT_RETENTION_PURGE", detail);

        ResponseEntity<AdminAuditLogsResponse> response =
                adminApiController.listAuditLogs("AUDIT_RETENTION_PURGE", "audit-retention", 10);
        AdminAuditLogsResponse body = response.getBody();
        assertThat(body).isNotNull();
        // 화면의 유형 필터는 이 목록으로 만든다.
        assertThat(body.actionTypes()).contains(AuditActionType.AUDIT_RETENTION_PURGE, AuditActionType.INCIDENT_ASSIGNMENT);
        List<AuditLog> logs = body.logs();
        assertThat(logs).isNotEmpty();
        AuditLog row = logs.get(0);
        assertThat(row.getActionType()).isEqualTo("AUDIT_RETENTION_PURGE");
        assertThat(row.getActorRole()).isEqualTo("SYSTEM");
        assertThat(row.getClientIp()).isNull();
        assertThat(row.getDetailJson()).isEqualTo(detail);
    }
}
