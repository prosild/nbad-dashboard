package com.zeekad.dashboard;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class AuditLogImmutabilityTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    @Qualifier("appDataSource")
    private DataSource appDataSource;

    @Test
    void auditLogsAllowInsertAndBlockUpdateAndDeleteViaTrigger() {
        String actor = "audit_immut_actor";
        auditService.record(actor, "ADMIN", AuditActionType.USER_ADMIN_CHANGE,
                "cic17-wed", 10L, "inc-1", Map.of("test", "immutable"), "127.0.0.1");

        List<AuditLog> found = auditLogMapper.findFiltered(AuditActionType.USER_ADMIN_CHANGE.name(), actor, 10);
        assertThat(found).isNotEmpty();
        Long insertedId = found.get(0).getId();

        JdbcTemplate jdbc = new JdbcTemplate(appDataSource);
        assertThatThrownBy(() -> jdbc.update("UPDATE audit_logs SET actor_username = 'tampered' WHERE id = ?", insertedId))
                .isInstanceOf(DataAccessException.class)
                .hasRootCauseMessage("audit_logs is append-only: UPDATE and DELETE are forbidden");

        assertThatThrownBy(() -> jdbc.update("DELETE FROM audit_logs WHERE id = ?", insertedId))
                .isInstanceOf(DataAccessException.class)
                .hasRootCauseMessage("audit_logs is append-only: UPDATE and DELETE are forbidden");

        List<AuditLog> afterTamper = auditLogMapper.findFiltered(AuditActionType.USER_ADMIN_CHANGE.name(), actor, 10);
        assertThat(afterTamper).hasSize(found.size());
        assertThat(afterTamper.get(0).getActorUsername()).isEqualTo(actor);
    }
}
