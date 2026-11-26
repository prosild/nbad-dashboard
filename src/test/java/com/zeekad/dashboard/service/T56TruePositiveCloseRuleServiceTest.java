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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * T56 정탐 종결 규칙: 분석 중 + 정탐 + 조치 기록 0건이면 409이고 zeek_AD 쓰기 함수와 감사를 부르지 않는다.
 * 기록이 있으면, 판정이 오탐·정상이면, 지금 상태가 분석 중이 아니면 zeek_AD 쓰기 함수를 그대로 부른다.
 */
class T56TruePositiveCloseRuleServiceTest {

    private final ZeekadWriteMapper writeMapper = Mockito.mock(ZeekadWriteMapper.class);
    private final CaptureAccessService access = Mockito.mock(CaptureAccessService.class);
    private final AuditService audit = Mockito.mock(AuditService.class);
    private final IncidentAssignmentService assignment = Mockito.mock(IncidentAssignmentService.class);
    private final IncidentResponseActionService responseActions = Mockito.mock(IncidentResponseActionService.class);
    private final DashboardUserPrincipal analyst = principal();
    private final IncidentTransitionService service =
            new IncidentTransitionService(writeMapper, access, audit, assignment, responseActions);

    @Test
    void investigatingTruePositiveWithoutRecordIs409AndNeverCallsZeekadWrite() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        when(responseActions.currentStatus(any())).thenReturn("investigating");
        when(responseActions.countFor("inc-1")).thenReturn(0);

        var r = service.transition(analyst, 1L, 1, "closed", " True_Positive ", "정탐 확정", "127.0.0.1");
        assertThat(r.succeeded()).isFalse();
        assertThat(r.httpStatus()).isEqualTo(409);
        assertThat(r.code()).isEqualTo("RESPONSE_ACTION_REQUIRED");
        assertThat(r.message()).isEqualTo(
                "정탐으로 종결하려면 대응 조치를 먼저 기록하세요. 조치가 없었다면 '조치 없음'을 기록하세요.");
        verifyNoInteractions(writeMapper, audit, assignment);
    }

    @Test
    void recordExistsOrOtherResolutionOrOtherStatusCallsZeekadWrite() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        when(responseActions.currentStatus(any())).thenReturn("investigating");

        // 기록 1건: 정탐 종결이 zeek_AD 함수까지 간다
        when(responseActions.countFor("inc-1")).thenReturn(1);
        assertThat(service.transition(analyst, 1L, 1, "closed", "true_positive", "정탐 확정", "127.0.0.1").succeeded()).isTrue();
        verify(writeMapper).transitionIncident(eq(1L), eq("inc-1"), eq("closed"), eq("t56_analyst"), eq("정탐 확정"),
                eq("true_positive"));

        // 기록 0건이어도 오탐·정상은 그대로
        when(responseActions.countFor("inc-1")).thenReturn(0);
        for (String resolution : List.of("false_positive", "benign")) {
            assertThat(service.transition(analyst, 1L, 1, "closed", resolution, "종결", "127.0.0.1").succeeded()).isTrue();
            verify(writeMapper).transitionIncident(eq(1L), eq("inc-1"), eq("closed"), eq("t56_analyst"), eq("종결"),
                    eq(resolution));
        }
        // 착수(investigating) 전이는 기록 수를 보지 않는다
        when(responseActions.currentStatus(any())).thenReturn("open");
        assertThat(service.transition(analyst, 1L, 1, "investigating", null, "착수", "127.0.0.1").succeeded()).isTrue();

        // 지금 상태가 분석 중이 아니면(신규·종결) 규칙을 적용하지 않고 zeek_AD 함수가 판단하게 둔다
        for (String status : List.of("open", "closed")) {
            when(responseActions.currentStatus(any())).thenReturn(status);
            service.transition(analyst, 1L, 1, "closed", "true_positive", "상태 " + status, "127.0.0.1");
            verify(writeMapper).transitionIncident(eq(1L), eq("inc-1"), eq("closed"), eq("t56_analyst"), eq("상태 " + status),
                    eq("true_positive"));
        }
    }

    @Test
    void earlierValidationsComeFirst() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        when(responseActions.currentStatus(any())).thenReturn("investigating");
        when(responseActions.countFor("inc-1")).thenReturn(0);

        assertThat(service.transition(analyst, 1L, 1, "closed", "true_positive", "  ", "127.0.0.1").code())
                .isEqualTo("INVALID_REQUEST");
        assertThat(service.transition(analyst, 1L, 1, "closed", "unknown", "사유", "127.0.0.1").code())
                .isEqualTo("INVALID_REQUEST");
        assertThat(service.transition(analyst, 1L, 1, "reopened", "true_positive", "사유", "127.0.0.1").code())
                .isEqualTo("INVALID_REQUEST");
        verify(writeMapper, never()).transitionIncident(any(), any(), any(), any(), any(), any());
        verifyNoInteractions(audit);
    }

    private static IncidentQueueItem item() {
        IncidentQueueItem item = new IncidentQueueItem();
        item.setIncidentId("inc-1");
        item.setCaptureId("cap-1");
        return item;
    }

    private static DashboardUserPrincipal principal() {
        DashboardUser user = new DashboardUser();
        user.setId(1L);
        user.setUsername("t56_analyst");
        user.setDisplayName("t56");
        user.setRole(UserRole.ANALYST);
        user.setEnabled(true);
        return new DashboardUserPrincipal(user, List.of("*"), Instant.now());
    }
}
