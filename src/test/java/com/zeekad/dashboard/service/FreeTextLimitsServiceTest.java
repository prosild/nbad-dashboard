package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * T33 사유·메모 길이 상한(500 코드 포인트, 앞뒤 공백 제외): 넘으면 400이고 DB 쓰기 함수와 감사를 부르지 않는다.
 */
class FreeTextLimitsServiceTest {

    private final ZeekadWriteMapper writeMapper = Mockito.mock(ZeekadWriteMapper.class);
    private final CaptureAccessService access = Mockito.mock(CaptureAccessService.class);
    private final AuditService audit = Mockito.mock(AuditService.class);
    private final IncidentAssignmentService assignment = Mockito.mock(IncidentAssignmentService.class);
    private final IncidentResponseActionService responseActions = Mockito.mock(IncidentResponseActionService.class);
    private final DashboardUserPrincipal analyst = principal();

    @Test
    void countsCodePointsAfterTrim() {
        assertThat(FreeTextLimits.MAX_CODE_POINTS).isEqualTo(500);
        assertThat(FreeTextLimits.exceeds(null)).isFalse();
        assertThat(FreeTextLimits.exceeds("a".repeat(500))).isFalse();
        assertThat(FreeTextLimits.exceeds("a".repeat(501))).isTrue();
        // 보조 평면 문자 500개는 UTF-16 1000단위지만 500자
        assertThat(FreeTextLimits.exceeds("😀".repeat(500))).isFalse();
        assertThat(FreeTextLimits.exceeds("😀".repeat(501))).isTrue();
    }

    @Test
    void transitionReasonOverLimitNeverCallsDbFunctionOrAudit() {
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item());
        IncidentTransitionService service = new IncidentTransitionService(writeMapper, access, audit, assignment, responseActions);

        var rejected = service.transition(analyst, 1L, 1, "investigating", null, " " + "x".repeat(501) + " ", "127.0.0.1");
        assertThat(rejected.succeeded()).isFalse();
        assertThat(rejected.httpStatus()).isEqualTo(400);
        assertThat(rejected.code()).isEqualTo("INVALID_REQUEST");
        assertThat(rejected.message()).isEqualTo("상태 변경 사유는 500자까지 입력할 수 있습니다.");
        verifyNoInteractions(writeMapper, audit, assignment);

        var accepted = service.transition(analyst, 1L, 1, "investigating", null, " " + "x".repeat(500) + " ", "127.0.0.1");
        assertThat(accepted.succeeded()).isTrue();
        verify(writeMapper).transitionIncident(eq(1L), eq("inc-1"), eq("investigating"), eq("t33_analyst"),
                eq("x".repeat(500)), isNull());
    }

    @Test
    void reviewNoteOverLimitNeverCallsDbFunctionOrAuditOnBothPaths() {
        IncidentQueueItem item = item();
        item.setZeekadReportJobId(2L);
        ScoringJob job = new ScoringJob();
        job.setCaptureId("cap-1");
        when(access.requireIncidentAccessByRank(any(), anyLong(), anyInt(), any())).thenReturn(item);
        when(access.requireJobAccess(any(), anyLong(), any(), any())).thenReturn(job);
        AnalystReviewDecisionService service = new AnalystReviewDecisionService(writeMapper, access, audit);
        String over = "😀".repeat(501);

        var fromReviews = service.decideFromReviews(analyst, 2L, "inc-1", "confirm", over, "127.0.0.1");
        var fromDetail = service.decideFromIncidentDetail(analyst, 1L, 1, "dismiss", over, "127.0.0.1");
        for (var r : List.of(fromReviews, fromDetail)) {
            assertThat(r.succeeded()).isFalse();
            assertThat(r.httpStatus()).isEqualTo(400);
            assertThat(r.code()).isEqualTo("INVALID_REQUEST");
            assertThat(r.message()).isEqualTo("검토 메모는 500자까지 입력할 수 있습니다.");
        }
        verify(writeMapper, never()).decideReview(any(), anyString(), anyString(), anyString(), any());
        verifyNoInteractions(audit);

        assertThat(service.decideFromReviews(analyst, 2L, "inc-1", "confirm", "😀".repeat(500), "127.0.0.1")
                .succeeded()).isTrue();
        verify(writeMapper).decideReview(eq(2L), eq("inc-1"), eq("confirm"), eq("t33_analyst"), eq("😀".repeat(500)));
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
        user.setUsername("t33_analyst");
        user.setDisplayName("t33");
        user.setRole(UserRole.ANALYST);
        user.setEnabled(true);
        return new DashboardUserPrincipal(user, List.of("*"), Instant.now());
    }
}
