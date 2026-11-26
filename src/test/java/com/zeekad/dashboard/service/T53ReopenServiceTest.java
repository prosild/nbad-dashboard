package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * T53 다시 열기 서비스: 담당자 자동 지정이 실패해도 다시 열기는 성공으로 응답하고 안내만 덧붙인다(조사 시작과 같다).
 * canReopen은 ANALYST·ADMIN이고 지금 종결일 때만 참이다.
 */
class T53ReopenServiceTest {

    private final ZeekadWriteMapper writeMapper = Mockito.mock(ZeekadWriteMapper.class);
    private final CaptureAccessService access = Mockito.mock(CaptureAccessService.class);
    private final AuditService audit = Mockito.mock(AuditService.class);
    private final IncidentAssignmentService assignment = Mockito.mock(IncidentAssignmentService.class);
    private final IncidentReopenService service = new IncidentReopenService(writeMapper, access, audit, assignment);

    @Test
    void autoAssignFailureStillSucceedsWithNote() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        when(assignment.autoAssignOnStart(any(), any(), any(), any())).thenThrow(new IllegalStateException("app db down"));

        var r = service.reopen(principal(UserRole.ANALYST), 1L, 1, " 재검토 ", "BENIGN", "127.0.0.1");
        assertThat(r.succeeded()).isTrue();
        assertThat(r.httpStatus()).isEqualTo(200);
        assertThat(r.message()).isEqualTo("인시던트를 다시 열었습니다. 상태는 분석 중입니다. 담당자 자동 지정은 실패했습니다.");
        verify(writeMapper).reopenIncident(eq(1L), eq("inc-1"), eq("t53_analyst"), eq("재검토"), eq("benign"));
    }

    @Test
    void validationFailuresNeverCallWriteMapperOrAudit() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        assertThat(service.reopen(principal(UserRole.ANALYST), 1L, 1, "", "benign", "127.0.0.1").httpStatus()).isEqualTo(400);
        assertThat(service.reopen(principal(UserRole.ANALYST), 1L, 1, "사유", null, "127.0.0.1").httpStatus()).isEqualTo(400);
        assertThat(service.reopen(principal(UserRole.ANALYST), 1L, 1, "사유", "closed", "127.0.0.1").httpStatus()).isEqualTo(400);
        verifyNoInteractions(writeMapper, audit, assignment);
    }

    @Test
    void canReopenOnlyAnalystOrAdminOnClosed() {
        assertThat(IncidentReopenService.canReopen(UserRole.ANALYST, "closed")).isTrue();
        assertThat(IncidentReopenService.canReopen(UserRole.ADMIN, "closed")).isTrue();
        assertThat(IncidentReopenService.canReopen(UserRole.VIEWER, "closed")).isFalse();
        for (String status : List.of("open", "investigating", "")) {
            assertThat(IncidentReopenService.canReopen(UserRole.ANALYST, status)).isFalse();
        }
        assertThat(IncidentReopenService.canReopen(UserRole.ANALYST, null)).isFalse();
        assertThat(IncidentReopenService.canReopen(null, "closed")).isFalse();
    }

    private static IncidentQueueItem item() {
        IncidentQueueItem item = new IncidentQueueItem();
        item.setIncidentId("inc-1");
        item.setCaptureId("cap-1");
        return item;
    }

    private static DashboardUserPrincipal principal(UserRole role) {
        DashboardUser user = new DashboardUser();
        user.setId(1L);
        user.setUsername("t53_analyst");
        user.setDisplayName("t53");
        user.setRole(role);
        user.setEnabled(true);
        return new DashboardUserPrincipal(user, List.of("*"), Instant.now());
    }
}
