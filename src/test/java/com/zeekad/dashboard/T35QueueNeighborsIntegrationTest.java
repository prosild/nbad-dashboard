package com.zeekad.dashboard;

import com.zeekad.dashboard.dto.QueueNeighborsResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.dto.UnifiedQueueRow;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentAssignmentService;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T35 이전·다음(neighbors)을 DB 창 질의로 바꾼 뒤에도 결과가 옛 방식과 같은지 비교한다.
 * 기준(옛 방식) = 같은 조건의 목록 API 쪽을 모두 이은 순서에서 지금 행을 찾아 앞뒤를 고르는 것(T23 neighbors의 Java 계산).
 * 정렬 키 5 × 방향 2, 기간(전체·프리셋·지정), 수집원·우선순위·담당·착수 지연·상태·띠 조건, VIEWER·ANALYST(허용 일부).
 * 시험용 행은 작업 35001~35013(캡처 lab-t35 실습망, t35x-cap 가져온 데이터)이고 시험마다 넣고 지운다(공유 H2).
 */
@SpringBootTest
@ActiveProfiles("test")
class T35QueueNeighborsIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final String LIVE_CAPTURE = "lab-t35";
    private static final String IMPORTED_CAPTURE = "t35x-cap";
    private static final long[] LIVE_JOBS = {35001L, 35002L, 35003L};
    private static final long[] IMPORTED_JOBS = {35011L, 35012L, 35013L};
    private static final int ROWS_PER_CAPTURE = 45;

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(FIXED_NOW);
        }
    }

    @Autowired private IncidentQueueService queueService;
    @Autowired private MutableTestClock clock;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @MockitoSpyBean private IncidentAssignmentService assignmentService;
    @MockitoSpyBean private ZeekadReadMapper zeekadReadMapper;

    private final List<String> assignedIds = new ArrayList<>();

    @BeforeEach
    void setUp() {
        clock.set(FIXED_NOW);
        deleteRows();
        insertRows();
        Mockito.doReturn(assignedIds).when(assignmentService)
                .assignedIncidentIds(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        deleteRows();
        Mockito.reset(assignmentService, zeekadReadMapper);
    }

    /* ───────────── 같은 결과 ───────────── */

    @Test
    void everySortKeyAndDirectionMatchesOldMethodForBothRoles() {
        int compared = 0;
        for (DashboardUserPrincipal who : List.of(analystSubset(), viewerAll())) {
            for (String sort : List.of("priority", "detected", "start", "connections", "status")) {
                for (String dir : List.of("asc", "desc")) {
                    compared += compareAll(who, p("all", sort, dir));
                }
            }
        }
        assertThat(compared).isGreaterThan(500);
    }

    @Test
    void periodsSourcesAndFiltersMatchOldMethodForBothRoles() {
        List<QueueParams> cases = new ArrayList<>();
        for (String period : List.of("24h", "7d", "30d")) {
            cases.add(p(period, null, null));
            cases.add(p(period, "detected", "asc"));
        }
        cases.add(custom("2026-11-10T00:00:00Z", "2026-11-20T15:00:00Z", null, null));
        cases.add(custom("2026-11-10T09:00:00+09:00", "2026-11-21T09:00:00+09:00", "connections", "asc"));
        cases.add(full("all", "live", null, null, null, null, null, null, null, "start", "desc"));
        cases.add(full("all", "imported", null, null, null, null, null, null, null, null, null));
        cases.add(full("all", null, "high", null, null, null, null, null, null, null, null));
        cases.add(full("30d", null, "medium", null, null, null, null, null, null, "detected", "desc"));
        cases.add(full("all", null, null, "investigating", null, null, null, null, null, "status", "desc"));
        cases.add(full("all", null, null, null, "true", null, null, null, null, null, null));
        cases.add(full("all", null, null, null, null, "true", null, null, null, "connections", "desc"));
        cases.add(full("all", null, null, null, null, null, "hbos", null, null, null, null));
        cases.add(full("all", null, null, null, null, null, null, "me", null, null, null));
        cases.add(full("all", null, null, null, null, null, null, "none", null, "detected", "asc"));
        cases.add(full("all", null, null, null, null, null, null, null, "true", null, null));
        cases.add(full("7d", "live", "high", null, null, null, null, null, "true", "start", "asc"));

        // 담당 조건: 각 캡처의 일부를 '나에게' 담당으로 둔다
        assignedIds.clear();
        for (int i = 1; i <= ROWS_PER_CAPTURE; i += 4) {
            assignedIds.add(incidentId(LIVE_CAPTURE, i));
            assignedIds.add(incidentId(IMPORTED_CAPTURE, i));
        }

        int compared = 0;
        int outside = 0;
        for (DashboardUserPrincipal who : List.of(analystSubset(), viewerAll())) {
            for (QueueParams q : cases) {
                int[] r = compareSampledWithOutside(who, q);
                compared += r[0];
                outside += r[1];
            }
        }
        assertThat(compared).isGreaterThan(200);
        assertThat(outside).as("조건 밖 비교").isGreaterThan(50);
    }

    @Test
    void staleJobResolvesToLatestRowAndTiedRowsAreOrderedLikeTheList() {
        DashboardUserPrincipal who = analystSubset();
        QueueParams q = p("all", "connections", "desc");
        List<UnifiedQueueRow> list = listAll(who, q);
        // 낡은 작업(35001)의 행으로 불러도 같은 incident_id의 최신 행(35003) 위치를 준다
        int staleRank = 3; // incidentId(lab, 3)은 35001에도 있다(3 % 3 == 0)
        QueueNeighborsResponse stale = queueService.neighbors(who, LIVE_JOBS[0], staleRank, q, "127.0.0.1");
        assertThat(stale.current().jobId()).isEqualTo(LIVE_JOBS[2]);
        assertSame(oldMethod(list, LIVE_JOBS[2], staleRank), stale, "낡은 작업");

        // 정렬 값(세션 수·탐지 시각)이 같은 행이 이어진 구간이 있어야 의미가 있다
        int tiedRuns = 0;
        for (int i = 1; i < list.size(); i++) {
            UnifiedQueueRow a = list.get(i - 1);
            UnifiedQueueRow b = list.get(i);
            if (Objects.equals(a.getItem().getConnectionCount(), b.getItem().getConnectionCount())
                    && Objects.equals(a.getDetectedAt(), b.getDetectedAt())) {
                tiedRuns++;
            }
        }
        assertThat(tiedRuns).isGreaterThan(10);
    }

    /* ───────────── 권한·전체 목록을 읽지 않음 ───────────── */

    @Test
    void deniedCaptureStays403WithIdorAuditAndNonAssetPathDoesNotReadWholeQueue() {
        DashboardUserPrincipal who = analystSubset();
        long before = countIdorAudits();
        // t35x-cap은 허용 밖이다
        assertThatThrownBy(() -> queueService.neighbors(who, IMPORTED_JOBS[2], 1, p("all", null, null), "127.0.0.1"))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(countIdorAudits()).isEqualTo(before + 1);

        Mockito.clearInvocations(zeekadReadMapper);
        QueueNeighborsResponse n = queueService.neighbors(who, LIVE_JOBS[2], 10, p("all", null, null), "127.0.0.1");
        assertThat(n.position()).isNotNull();
        // 상한 없는 목록 질의는 부르지 않는다(지금 행 찾기는 limit 1)
        Mockito.verify(zeekadReadMapper, Mockito.never())
                .findUnifiedQueue(ArgumentMatchers.argThat((UnifiedQueueCriteria c) -> c.getLimit() == null));
        Mockito.verify(zeekadReadMapper, Mockito.times(1))
                .findUnifiedQueueNeighbors(ArgumentMatchers.argThat((UnifiedQueueCriteria c) ->
                        c.getIncidentId() == null && c.getLimit() == null && c.getOffset() == null),
                        ArgumentMatchers.eq(LIVE_JOBS[2]), ArgumentMatchers.eq(10));
        Mockito.verify(zeekadReadMapper, Mockito.never()).countUnifiedQueue(ArgumentMatchers.any());

        // 조건 밖이면 전체 수만 따로 센다
        Mockito.clearInvocations(zeekadReadMapper);
        QueueParams closedOnly = full("all", null, null, "closed", null, null, null, null, null, null, null);
        int openRank = 1; // 1 % 5 == 1 → open
        QueueNeighborsResponse out = queueService.neighbors(who, LIVE_JOBS[2], openRank, closedOnly, "127.0.0.1");
        assertThat(out.position()).isNull();
        assertThat(out.total()).isEqualTo(listAll(who, closedOnly).size());
        Mockito.verify(zeekadReadMapper, Mockito.never())
                .findUnifiedQueue(ArgumentMatchers.argThat((UnifiedQueueCriteria c) -> c.getLimit() == null));
    }

    /* ───────────── 비교 도구 ───────────── */

    /** 모든 행에서 비교. 비교한 수 */
    private int compareAll(DashboardUserPrincipal who, QueueParams q) {
        List<UnifiedQueueRow> list = listAll(who, q);
        assertThat(list).as("빈 목록이면 비교 의미가 없다 %s", q).hasSizeGreaterThan(20);
        for (UnifiedQueueRow row : list) {
            long job = row.getItem().getJobId();
            int rank = row.getItem().getQueueRank();
            assertSame(oldMethod(list, job, rank), queueService.neighbors(who, job, rank, q, "127.0.0.1"), q.toString());
        }
        return list.size();
    }

    /** 맨 앞·둘째·가운데·끝 앞·맨 뒤와 5번째마다 + 조건 밖 행(같은 정렬의 전체 기간·조건 없는 목록에서 빠진 것) */
    private int[] compareSampledWithOutside(DashboardUserPrincipal who, QueueParams q) {
        List<UnifiedQueueRow> list = listAll(who, q);
        Set<Integer> idx = new LinkedHashSet<>();
        int n = list.size();
        if (n > 0) {
            for (int i : new int[]{0, 1, n / 2, n - 2, n - 1}) {
                if (i >= 0 && i < n) idx.add(i);
            }
            for (int i = 0; i < n; i += 5) idx.add(i);
        }
        for (int i : idx) {
            UnifiedQueueRow row = list.get(i);
            long job = row.getItem().getJobId();
            int rank = row.getItem().getQueueRank();
            assertSame(oldMethod(list, job, rank), queueService.neighbors(who, job, rank, q, "127.0.0.1"), q.toString());
        }
        List<UnifiedQueueRow> universe = listAll(who, p("all", q.sort(), q.dir()));
        int outside = 0;
        for (UnifiedQueueRow row : universe) {
            if (outside >= 4) break;
            long job = row.getItem().getJobId();
            int rank = row.getItem().getQueueRank();
            boolean inList = list.stream().anyMatch(r -> r.getItem().getJobId() == job && r.getItem().getQueueRank() == rank);
            if (inList) continue;
            QueueNeighborsResponse actual = queueService.neighbors(who, job, rank, q, "127.0.0.1");
            assertSame(oldMethod(list, job, rank), actual, "조건 밖 " + q);
            assertThat(actual.position()).isNull();
            outside++;
        }
        return new int[]{idx.size(), outside};
    }

    /** 목록 API 쪽(100건)을 모두 이은 순서 */
    private List<UnifiedQueueRow> listAll(DashboardUserPrincipal who, QueueParams q) {
        List<UnifiedQueueRow> all = new ArrayList<>();
        UnifiedQueueResponse first = queueService.loadQueue(who, withPage(q, 1), "127.0.0.1");
        all.addAll(first.items());
        for (int page = 2; page <= first.pageCount(); page++) {
            all.addAll(queueService.loadQueue(who, withPage(q, page), "127.0.0.1").items());
        }
        assertThat((long) all.size()).isEqualTo(first.total());
        return all;
    }

    /** 옛 방식(T23 neighbors): 정렬된 전체에서 지금 행을 찾아 앞뒤를 고른다. 위치 못 찾으면 위치·앞뒤 없음, 전체 수는 행 수 */
    private static Expected oldMethod(List<UnifiedQueueRow> ordered, long jobId, int queueRank) {
        int index = -1;
        for (int i = 0; i < ordered.size(); i++) {
            UnifiedQueueRow r = ordered.get(i);
            if (r.getItem().getJobId() == jobId && r.getItem().getQueueRank() == queueRank) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            return new Expected(null, ordered.size(), null, null);
        }
        return new Expected(index + 1, ordered.size(),
                index > 0 ? ordered.get(index - 1) : null,
                index < ordered.size() - 1 ? ordered.get(index + 1) : null);
    }

    private record Expected(Integer position, long total, UnifiedQueueRow prev, UnifiedQueueRow next) {
    }

    private static void assertSame(Expected expected, QueueNeighborsResponse actual, String label) {
        assertThat(actual.position()).as("위치 %s", label).isEqualTo(expected.position());
        assertThat(actual.total()).as("전체 수 %s", label).isEqualTo(expected.total());
        assertKey(expected.prev(), actual.prev(), "이전 " + label);
        assertKey(expected.next(), actual.next(), "다음 " + label);
        assertThat(actual.current()).as("지금 %s", label).isNotNull();
    }

    private static void assertKey(UnifiedQueueRow expected, QueueNeighborsResponse.Key actual, String label) {
        if (expected == null) {
            assertThat(actual).as(label).isNull();
            return;
        }
        assertThat(actual).as(label).isNotNull();
        assertThat(actual.jobId()).as(label).isEqualTo(expected.getItem().getJobId());
        assertThat(actual.queueRank()).as(label).isEqualTo(expected.getItem().getQueueRank());
        // 응답 host는 역할 마스킹 뒤 값이다(VIEWER는 목록과 같은 가려진 값)
        assertThat(actual.hostIp()).as(label + " host").isEqualTo(expected.getItem().getHostIp());
        assertThat(actual.incidentNo()).as(label + " 번호").isEqualTo(expected.getIncidentNo());
    }

    /* ───────────── 요청 조건 ───────────── */

    private static QueueParams p(String period, String sort, String dir) {
        return full(period, null, null, null, null, null, null, null, null, sort, dir);
    }

    private static QueueParams full(String period, String source, String priority, String status, String reviewPending,
                                    String alerted, String pickedBy, String assignee, String overdue,
                                    String sort, String dir) {
        return new QueueParams(period, source, null, priority, status, reviewPending, alerted, pickedBy, null, null,
                null, null, sort, dir, null, "100", assignee, overdue, null, null);
    }

    private static QueueParams custom(String start, String end, String sort, String dir) {
        return new QueueParams("custom", null, null, null, null, null, null, null, null, null, null, null, sort, dir,
                null, "100", null, null, start, end);
    }

    private static QueueParams withPage(QueueParams q, int page) {
        return new QueueParams(q.period(), q.source(), q.captureId(), q.priority(), q.status(), q.reviewPending(),
                q.alerted(), q.pickedBy(), q.role(), q.hasReport(), q.wouldSend(), q.asset(), q.sort(), q.dir(),
                String.valueOf(page), q.size(), q.assignee(), q.overdue(), q.start(), q.end());
    }

    /** ANALYST: 허용 캡처 일부(lab-*·cic17-*, t35x-cap·syn1은 밖) */
    private static DashboardUserPrincipal analystSubset() {
        return principal(UserRole.ANALYST, List.of("lab-*", "cic17-*"));
    }

    /** VIEWER: 전체(호스트·incident_id는 가려진 값) */
    private static DashboardUserPrincipal viewerAll() {
        return principal(UserRole.VIEWER, List.of("*"));
    }

    private static DashboardUserPrincipal principal(UserRole role, List<String> patterns) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t35-principal");
        u.setDisplayName("t35");
        u.setRole(role);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, patterns, FIXED_NOW);
    }

    private long countIdorAudits() {
        return auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), "t35-principal", 1000).size();
    }

    /* ───────────── 시험 데이터 ───────────── */

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private static String incidentId(String capture, int i) {
        return capture + "|10.35." + (capture.equals(LIVE_CAPTURE) ? 1 : 2) + "." + i + "|t35-" + i;
    }

    /**
     * 캡처마다 작업 셋. 마지막 작업(최신 큐)에 45행, 앞 두 작업에 i%3==0·i%3==1 행이 먼저 나와 탐지 시각이 세 값으로 겹친다.
     * 실습망: 2026-11-20 10:00·20:00·23:45Z(기준 시각 11-21 00:00Z). 가져온 데이터: 11-05·11-12·11-15 00:00Z.
     * 상태·보고서·발송·검토 대기·교차 탐지·경보·세션 수·시작 시각은 i로 정해 같은 값이 여럿 겹친다.
     */
    private void insertRows() {
        insertCapture(LIVE_CAPTURE, LIVE_JOBS, new String[]{"2026-11-20 10:00:00Z", "2026-11-20 20:00:00Z", "2026-11-20 23:45:00Z"});
        insertCapture(IMPORTED_CAPTURE, IMPORTED_JOBS, new String[]{"2026-11-05 00:00:00Z", "2026-11-12 00:00:00Z", "2026-11-15 00:00:00Z"});
    }

    private void insertCapture(String capture, long[] jobs, String[] finished) {
        JdbcTemplate jdbc = jdbc();
        for (int j = 0; j < jobs.length; j++) {
            jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                    + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', CAST(? AS TIMESTAMP WITH TIME ZONE), CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, ?)",
                    jobs[j], capture, finished[j], finished[j], ROWS_PER_CAPTURE);
        }
        long latest = jobs[2];
        for (int i = 1; i <= ROWS_PER_CAPTURE; i++) {
            String id = incidentId(capture, i);
            String ip = "10.35." + (capture.equals(LIVE_CAPTURE) ? 1 : 2) + "." + i;
            String also = i % 4 == 1 ? "ARRAY['autoencoder']" : "NULL";
            String start = String.format("2026-11-%02d %02d:00:00Z", capture.equals(LIVE_CAPTURE) ? 20 : 4, i % 4);
            long connections = (i % 3) * 10L;
            String picked = i % 2 == 0 ? "hbos" : "iforest";
            List<Long> appearIn = new ArrayList<>();
            if (i % 3 == 0) appearIn.add(jobs[0]);
            if (i % 3 == 1) appearIn.add(jobs[1]);
            appearIn.add(latest);
            for (long job : appearIn) {
                jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-20 06:00:00Z', ?, " + also + ", ?, ARRAY['t35-host-" + i + "'])",
                        job, capture, i, id, ip, i % 2 == 0 ? "originator" : "responder", start, picked, connections);
            }
            String status = switch (i % 5) {
                case 1 -> "open";
                case 2 -> "investigating";
                case 3 -> "closed";
                case 4 -> "archived";
                default -> null;
            };
            if (status != null) {
                jdbc.update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                        + "VALUES (?, ?, ?, NULL, TIMESTAMP WITH TIME ZONE '2026-11-20 23:50:00Z', 't35')", latest, id, status);
            }
            if (i % 3 == 0) {
                jdbc.update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                        + "zeekad_report, created_at) VALUES (?, ?, 'template', 'template.v1', '{}' FORMAT JSON, "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-20 23:46:00Z')", latest, id);
                if (i % 6 == 0) {
                    jdbc.update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                            + "VALUES (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-20 23:47:00Z')", latest, id);
                }
                if (i % 9 == 3) {
                    jdbc.update("INSERT INTO dashboard.raw_analyst_review_queue (job_id, incident_id, queue_rank, host_ip, zeekad_role, "
                            + "zeekad_review_reason, requested_at, zeekad_review_action) VALUES (?, ?, ?, ?, 'originator', 't35', "
                            + "TIMESTAMP WITH TIME ZONE '2026-11-20 23:47:00Z', NULL)", latest, id, i, ip);
                }
            }
            if (i % 5 == 2 || i % 7 == 0) {
                String version = i % 5 == 2 ? "alert.v1" : "status:v1";
                jdbc.update("INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version, "
                        + "zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at, "
                        + "zeekad_thread_parent, zeekad_reply_broadcast) VALUES (?, ?, 'alert', ?, 'dry_run', 'recorded', "
                        + "'{}' FORMAT JSON, NULL, NULL, NULL, TIMESTAMP WITH TIME ZONE '2026-11-20 23:48:00Z', NULL, FALSE)",
                        latest, id, version);
            }
        }
    }

    private void deleteRows() {
        JdbcTemplate jdbc = jdbc();
        for (long job : new long[]{LIVE_JOBS[0], LIVE_JOBS[1], LIVE_JOBS[2], IMPORTED_JOBS[0], IMPORTED_JOBS[1], IMPORTED_JOBS[2]}) {
            jdbc.update("DELETE FROM dashboard.raw_slack_deliveries WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_analyst_review_queue WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_send_decisions WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_status WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", job);
        }
    }
}
