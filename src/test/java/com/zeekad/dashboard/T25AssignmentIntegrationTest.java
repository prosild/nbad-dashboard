package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentAssignmentService;
import com.zeekad.dashboard.service.IncidentTransitionService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T25 담당자: V2(H2)·이력 추가만, 지정 규칙(권한·IDOR·담당 가능·종결·충돌·NO_CHANGE·해제·감사·이력), 동시 지정,
 * 조사 시작 때 자동 지정(가짜 실패 포함), 큐 assignee=me|none(불변식·빈 목록·잘못된 값·해제·숨긴 캡처·API 사이 일치),
 * 큐 overdue(경계·가져온 데이터·조사 중·우선순위별·summary). 시험용 zeekad 행은 job 96000~96099, 담당 행은 시험마다 지운다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T25AssignmentIntegrationTest {

    static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    static final String LIVE = "lab-t25a";
    static final String HIDDEN = "lab-t25b";
    static final String IMPORTED = "t25imp";

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(FIXED_NOW);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private UserMapper userMapper;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private IncidentTransitionService transitionService;
    @MockitoSpyBean private IncidentAssignmentService assignmentService;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int userSeq = 0;

    @BeforeEach
    void seed() {
        // 지난 날짜 작업 둘(탐지 시각을 앞당김) + 최신 작업
        job(96000, LIVE, "2026-11-19T22:00:00Z", "2026-11-19T23:00:00Z");
        job(96001, LIVE, "2026-11-19T23:30:00Z", "2026-11-20T00:00:00Z");
        job(96003, LIVE, "2026-11-20T22:30:00Z", "2026-11-20T23:00:00Z");
        incident(96000, LIVE, 4, "10.71.0.4", "low");
        incident(96001, LIVE, 3, "10.71.0.3", "low");
        incident(96003, LIVE, 1, "10.71.0.1", "high");          // 탐지 23:00, 목표 30분 → 지연
        incident(96003, LIVE, 2, "10.71.0.2", "medium");        // 탐지 23:00, 목표 4시간 → 지연 아님
        incident(96003, LIVE, 3, "10.71.0.3", "low");           // 탐지 20일 00:00, 목표 24시간 = 기준 시각 → 지연 아님(경계)
        incident(96003, LIVE, 4, "10.71.0.4", "low");           // 탐지 19일 23:00 → 지연
        incident(96003, LIVE, 5, "10.71.0.5", "high");          // 조사 중 → 지연 아님
        setStatus(96003, LIVE, 5, "10.71.0.5", "investigating", null, "2026-11-20T23:10:00Z");
        incident(96003, LIVE, 6, "10.71.0.6", "low");           // 종결
        setStatus(96003, LIVE, 6, "10.71.0.6", "closed", "benign", "2026-11-20T23:20:00Z");
        job(96010, IMPORTED, "2026-11-19T00:00:00Z", "2026-11-19T01:00:00Z");
        incident(96010, IMPORTED, 1, "10.72.0.1", "high");      // 가져온 데이터 → 목표 없음
        incident(96010, IMPORTED, 2, "10.72.0.2", "low");
        job(96020, HIDDEN, "2026-11-20T22:00:00Z", "2026-11-20T22:30:00Z");
        incident(96020, HIDDEN, 1, "10.73.0.1", "high");
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = new JdbcTemplate(zeekadReadDataSource);
        String range = "job_id BETWEEN 96000 AND 96099";
        z.update("DELETE FROM dashboard.raw_send_decisions WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_reports WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        // 이력 표는 추가만이라 트리거를 잠시 빼고 지운다(시험 DB 정리 전용)
        JdbcTemplate a = new JdbcTemplate(appDataSource);
        a.execute("DROP TRIGGER IF EXISTS trg_incident_assignment_history_immutable");
        a.update("DELETE FROM incident_assignment_history");
        a.update("DELETE FROM incident_assignments");
        a.execute("CREATE TRIGGER trg_incident_assignment_history_immutable BEFORE UPDATE, DELETE ON incident_assignment_history "
                + "FOR EACH ROW CALL \"com.zeekad.dashboard.audit.H2AssignmentHistoryImmutableTrigger\"");
        Mockito.reset(assignmentService);
    }

    /* ───────────── V2 ───────────── */

    @Test
    void v2MigrationCreatesTablesAndHistoryIsAppendOnly() throws Exception {
        JdbcTemplate a = new JdbcTemplate(appDataSource);
        assertThat(a.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version = '2' AND success = TRUE",
                Integer.class)).isEqualTo(1);
        MockHttpSession s = login(UserRole.ANALYST, LIVE);
        assign(s, 96003, 1, me(s), null).andExpect(status().isOk());
        assertThat(a.queryForObject("SELECT COUNT(*) FROM incident_assignment_history", Integer.class)).isEqualTo(1);
        assertThatThrownBy(() -> a.update("UPDATE incident_assignment_history SET reason = 'manual'"))
                .rootCause().hasMessageContaining("append-only");
        assertThatThrownBy(() -> a.update("DELETE FROM incident_assignment_history"))
                .rootCause().hasMessageContaining("append-only");
        assertThat(a.queryForObject("SELECT COUNT(*) FROM incident_assignment_history", Integer.class)).isEqualTo(1);
    }

    /* ───────────── 지정 규칙 ───────────── */

    @Test
    void analystAssignsChangesAndUnassignsWithHistoryAndAudit() throws Exception {
        MockHttpSession a1 = login(UserRole.ANALYST, LIVE);
        MockHttpSession a2 = login(UserRole.ANALYST, LIVE + "," + IMPORTED);
        String n1 = me(a1);
        String n2 = me(a2);

        JsonNode r = json(assign(a1, 96003, 1, n1, null).andExpect(status().isOk()).andReturn());
        assertThat(r.at("/assignment/assignee/username").asText()).isEqualTo(n1);
        assertThat(r.at("/assignment/assignee/enabled").asBoolean()).isTrue();
        assertThat(r.at("/assignment/assignedByDisplay").asText()).contains(n1);

        // 담당자 변경(a1 → a2), 해제
        assign(a1, 96003, 1, n2, n1).andExpect(status().isOk());
        JsonNode cleared = json(assign(a2, 96003, 1, null, n2).andExpect(status().isOk()).andReturn());
        assertThat(cleared.at("/assignment/assignee").isNull()).isTrue();

        // 이력: 시간 역순 세 행, 사유 manual
        JsonNode detail = getJson(a1, "/api/incidents/96003/rank/1");
        JsonNode hist = detail.get("assignmentHistory");
        assertThat(hist).hasSize(3);
        assertThat(hist.get(0).get("to").isNull()).isTrue();
        assertThat(hist.get(0).at("/from/username").asText()).isEqualTo(n2);
        assertThat(hist.get(2).get("from").isNull()).isTrue();
        assertThat(hist.get(2).at("/to/username").asText()).isEqualTo(n1);
        assertThat(hist.get(2).get("reason").asText()).isEqualTo("manual");
        assertThat(detail.get("canAssign").asBoolean()).isTrue();
        assertThat(detail.at("/assignment/assignee").isNull()).isTrue();

        // 감사: from·to·reason, 대상 캡처·작업·인시던트
        List<AuditLog> logs = auditLogMapper.findFiltered(AuditActionType.INCIDENT_ASSIGNMENT.name(), n1, 10);
        assertThat(logs).hasSize(2);
        AuditLog first = logs.get(logs.size() - 1);
        assertThat(first.getTargetCaptureId()).isEqualTo(LIVE);
        assertThat(first.getTargetJobId()).isEqualTo(96003L);
        assertThat(first.getTargetIncidentId()).isEqualTo(id(LIVE, 1, "10.71.0.1"));
        JsonNode d = objectMapper.readTree(first.getDetailJson());
        assertThat(d.get("from").isNull()).isTrue();
        assertThat(d.get("to").asText()).isEqualTo(n1);
        assertThat(d.get("reason").asText()).isEqualTo("manual");
    }

    @Test
    void conflictsNoChangeAndClosedAre409() throws Exception {
        MockHttpSession a1 = login(UserRole.ANALYST, LIVE);
        MockHttpSession a2 = login(UserRole.ANALYST, LIVE);
        String n1 = me(a1);
        String n2 = me(a2);
        assign(a1, 96003, 2, n1, null).andExpect(status().isOk());
        // 화면이 본 값(미배정)과 서버 값(n1)이 다르다
        JsonNode c = json(assign(a2, 96003, 2, n2, null).andExpect(status().isConflict()).andReturn());
        assertThat(c.get("code").asText()).isEqualTo("ASSIGNMENT_CONFLICT");
        // 같은 값으로
        JsonNode nc = json(assign(a2, 96003, 2, n1, n1).andExpect(status().isConflict()).andReturn());
        assertThat(nc.get("code").asText()).isEqualTo("NO_CHANGE");
        // 미배정을 해제
        JsonNode nc2 = json(assign(a2, 96003, 3, null, null).andExpect(status().isConflict()).andReturn());
        assertThat(nc2.get("code").asText()).isEqualTo("NO_CHANGE");
        // 종결
        JsonNode closed = json(assign(a1, 96003, 6, n1, null).andExpect(status().isConflict()).andReturn());
        assertThat(closed.get("code").asText()).isEqualTo("INCIDENT_CLOSED");
        assertThat(getJson(a1, "/api/incidents/96003/rank/6").get("canAssign").asBoolean()).isFalse();
        // 충돌·종결은 쓰지 않는다
        assertThat(new JdbcTemplate(appDataSource).queryForObject(
                "SELECT COUNT(*) FROM incident_assignment_history", Integer.class)).isEqualTo(1);
    }

    @Test
    void roleAndIdorChecksFollowTransitionOrder() throws Exception {
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE);
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String vName = me(viewer);
        String aName = me(analyst);
        // VIEWER, 허용 캡처: 403, IDOR 감사 없음
        assign(viewer, 96003, 1, aName, null).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/96003/rank/1/assignees").session(viewer)).andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), vName, 10)).isEmpty();
        // VIEWER, 허용 밖: 403과 IDOR 감사
        assign(viewer, 96020, 1, aName, null).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/96020/rank/1/assignees").session(viewer)).andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), vName, 10)).hasSize(2);
        // ANALYST, 허용 밖: 403과 IDOR 감사
        assign(analyst, 96020, 1, aName, null).andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), aName, 10)).hasSize(1);
        // CSRF 없는 POST
        mockMvc.perform(post("/api/incidents/96003/rank/1/assignment").session(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"assignee\":null,\"expected\":null}"))
                .andExpect(status().isForbidden());
        // VIEWER는 담당자 이름을 본다, 바꿀 수는 없다
        assign(analyst, 96003, 1, aName, null).andExpect(status().isOk());
        JsonNode vd = getJson(viewer, "/api/incidents/96003/rank/1");
        assertThat(vd.at("/assignment/assignee/username").asText()).isEqualTo(aName);
        assertThat(vd.get("canAssign").asBoolean()).isFalse();
        // ADMIN 역할(서비스 경로): 허용
        DashboardUserPrincipal admin = principal(UserRole.ADMIN, LIVE);
        assertThat(assignmentService.assign(admin, 96003L, 1, null, aName, "127.0.0.1").succeeded()).isTrue();
    }

    @Test
    void eligibilityRejectsInactiveViewerAndOutOfScopeUsers() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String inactive = createUser(UserRole.ANALYST, LIVE);
        DashboardUser u = userMapper.findByUsername(inactive);
        userAdminService.toggleEnabled(u.getId(), "seed", "ADMIN", "127.0.0.1");
        String viewer = createUser(UserRole.VIEWER, LIVE);
        String outOfScope = createUser(UserRole.ANALYST, IMPORTED);
        String eligible = createUser(UserRole.ANALYST, "lab-*");
        for (String name : List.of(inactive, viewer, outOfScope, "t25_nobody")) {
            JsonNode r = json(assign(analyst, 96003, 1, name, null).andExpect(status().isBadRequest()).andReturn());
            assertThat(r.get("code").asText()).as(name).isEqualTo("ASSIGNEE_NOT_ELIGIBLE");
        }
        assign(analyst, 96003, 1, eligible, null).andExpect(status().isOk());
        // 담당 가능자 목록: 활성 ANALYST·ADMIN이고 그 캡처를 볼 수 있는 사람만
        JsonNode list = getJson(analyst, "/api/incidents/96003/rank/1/assignees");
        List<String> names = new ArrayList<>();
        list.get("assignees").forEach(n -> names.add(n.get("username").asText()));
        assertThat(names).contains(eligible, me(analyst)).doesNotContain(inactive, viewer, outOfScope);

        // 비활성이 된 담당자는 풀지 않고 "비활성"으로 보인다
        DashboardUser e = userMapper.findByUsername(eligible);
        userAdminService.toggleEnabled(e.getId(), "seed", "ADMIN", "127.0.0.1");
        JsonNode d = getJson(analyst, "/api/incidents/96003/rank/1");
        assertThat(d.at("/assignment/assignee/username").asText()).isEqualTo(eligible);
        assertThat(d.at("/assignment/assignee/enabled").asBoolean()).isFalse();
    }

    @Test
    void concurrentAssignWithSameExpectedLetsOnlyOneWin() throws Exception {
        String n1 = createUser(UserRole.ANALYST, LIVE);
        String n2 = createUser(UserRole.ANALYST, LIVE);
        DashboardUserPrincipal p = principal(UserRole.ANALYST, LIVE);
        for (int round = 0; round < 5; round++) {
            int rank = round % 2 == 0 ? 2 : 4;
            JdbcTemplate a = new JdbcTemplate(appDataSource);
            String expected = a.queryForList("SELECT u.username FROM incident_assignments x JOIN users u ON u.id = x.assignee_user_id "
                    + "WHERE x.incident_id = ?", String.class, id(LIVE, rank, "10.71.0." + rank)).stream().findFirst().orElse(null);
            String t1 = n1.equals(expected) ? null : n1;
            String t2 = n2.equals(expected) ? null : n2;
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<IncidentAssignmentService.AssignResult>> fs = new ArrayList<>();
            for (String target : new String[]{t1, t2}) {
                fs.add(pool.submit(() -> {
                    start.await();
                    return assignmentService.assign(p, 96003L, rank, target, expected, "127.0.0.1");
                }));
            }
            start.countDown();
            int ok = 0;
            int conflict = 0;
            for (Future<IncidentAssignmentService.AssignResult> f : fs) {
                IncidentAssignmentService.AssignResult r = f.get();
                if (r.succeeded()) ok++;
                else if ("ASSIGNMENT_CONFLICT".equals(r.code()) || "NO_CHANGE".equals(r.code())) conflict++;
            }
            pool.shutdown();
            assertThat(ok).as("round %s", round).isEqualTo(1);
            assertThat(conflict).isEqualTo(1);
        }
    }

    /* ───────────── 자동 지정 ───────────── */

    @Test
    void startInvestigatingAutoAssignsOnlyWhenUnassigned() throws Exception {
        MockHttpSession a1 = login(UserRole.ANALYST, LIVE);
        MockHttpSession a2 = login(UserRole.ANALYST, LIVE);
        String n1 = me(a1);
        String n2 = me(a2);
        // 미배정 → 시작한 사람
        JsonNode r = json(transition(a1, 96003, 1, "investigating").andExpect(status().isOk()).andReturn());
        assertThat(r.get("message").asText()).doesNotContain("자동 지정은 실패");
        JsonNode d = getJson(a1, "/api/incidents/96003/rank/1");
        assertThat(d.at("/assignment/assignee/username").asText()).isEqualTo(n1);
        assertThat(d.get("assignmentHistory").get(0).get("reason").asText()).isEqualTo("auto_on_start");
        List<AuditLog> logs = auditLogMapper.findFiltered(AuditActionType.INCIDENT_ASSIGNMENT.name(), n1, 10);
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getDetailJson()).contains("auto_on_start");
        // 이미 담당 있음(다른 사람) → 그대로
        assign(a1, 96003, 2, n1, null).andExpect(status().isOk());
        transition(a2, 96003, 2, "investigating").andExpect(status().isOk());
        assertThat(getJson(a2, "/api/incidents/96003/rank/2").at("/assignment/assignee/username").asText()).isEqualTo(n1);
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_ASSIGNMENT.name(), n2, 10)).isEmpty();
        // 종결은 자동 지정하지 않는다
        transition(a2, 96003, 2, "closed").andExpect(status().isOk());
        assertThat(getJson(a2, "/api/incidents/96003/rank/2").at("/assignment/assignee/username").asText()).isEqualTo(n1);
    }

    @Test
    void autoAssignFailureStillSucceedsTransitionWithNote() throws Exception {
        MockHttpSession a1 = login(UserRole.ANALYST, LIVE);
        Mockito.doThrow(new IllegalStateException("가짜 실패"))
                .when(assignmentService).autoAssignOnStart(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any());
        JsonNode r = json(transition(a1, 96003, 3, "investigating").andExpect(status().isOk()).andReturn());
        assertThat(r.get("succeeded").asBoolean()).isTrue();
        assertThat(r.get("message").asText()).endsWith("담당자 자동 지정은 실패했습니다.");
        JsonNode d = getJson(a1, "/api/incidents/96003/rank/3");
        assertThat(d.get("detail").get("currentStatus").asText()).isEqualTo("investigating");
        assertThat(d.at("/assignment/assignee").isNull()).isTrue();
    }

    /* ───────────── 큐 assignee ───────────── */

    @Test
    void queueAssigneeFilterInvariantsAndConsistency() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, LIVE + "," + IMPORTED);
        MockHttpSession b = login(UserRole.ANALYST, LIVE + "," + IMPORTED);
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE + "," + IMPORTED);
        String na = me(a);
        String nb = me(b);
        // 빈 목록: me = 0, none = 조건 없음
        Map<String, Long> base = totals(a, "");
        assertThat(totals(a, "&assignee=me").get("all")).isZero();
        assertThat(totals(a, "&assignee=none")).isEqualTo(base);

        assign(a, 96003, 1, na, null).andExpect(status().isOk());
        assign(a, 96003, 2, na, null).andExpect(status().isOk());
        assign(b, 96010, 1, nb, null).andExpect(status().isOk());
        assign(b, 96003, 4, nb, null).andExpect(status().isOk());
        assign(b, 96003, 4, null, nb).andExpect(status().isOk()); // 해제 → 미배정

        for (String cond : List.of("", "&source=live", "&source=imported", "&captureId=" + LIVE, "&status=open")) {
            for (String period : List.of("all", "24h")) {
                String q = "&period=" + period + cond;
                long total = totals(a, q).get("all");
                long me = totals(a, q + "&assignee=me").get("all");
                long meB = totals(b, q + "&assignee=me").get("all");
                long none = totals(a, q + "&assignee=none").get("all");
                assertThat(me + meB + none).as("me(A)+me(B)+none = total %s", q).isEqualTo(total);
                long assignedInSet = me + meB;
                assertThat(none + assignedInSet).isEqualTo(total);
            }
        }
        assertThat(totals(a, "&period=all&assignee=me").get("all")).isEqualTo(2);
        // 해제된 인시던트는 미배정
        assertThat(ids(a, "&period=all&assignee=none")).contains(id(LIVE, 4, "10.71.0.4"));
        // VIEWER의 me는 빈 결과
        assertThat(totals(viewer, "&period=all&assignee=me").get("all")).isZero();
        // 잘못된 값 400
        mockMvc.perform(get("/api/incidents/queue?assignee=someone").session(a)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/incidents/queue/new-count?since=2026-11-01T00:00:00Z&assignee=x").session(a))
                .andExpect(status().isBadRequest());

        // 목록·요약·new-count·neighbors가 같은 규칙
        for (String asg : List.of("me", "none")) {
            String q = "&period=all&assignee=" + asg;
            JsonNode queue = getJson(a, "/api/incidents/queue?size=100" + q);
            long total = queue.get("total").asLong();
            assertThat(queue.get("items")).hasSize((int) total);
            assertThat(queue.at("/summary/total").asLong()).isEqualTo(total);
            JsonNode nc = getJson(a, "/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z&assignee=" + asg);
            assertThat(nc.get("count").asLong()).isEqualTo(total);
            JsonNode first = queue.get("items").get(0);
            JsonNode nb2 = getJson(a, "/api/incidents/queue/neighbors?jobId=" + first.get("jobId").asLong()
                    + "&queueRank=" + first.get("queueRank").asLong() + q);
            assertThat(nb2.get("total").asLong()).isEqualTo(total);
            for (JsonNode it : queue.get("items")) {
                assertThat(it.get("assignee").isNull()).isEqualTo("none".equals(asg));
            }
            // 자산 검색(Java) 경로도 같은 집합
            JsonNode viaAsset = getJson(a, "/api/incidents/queue?size=100&asset=." + q);
            assertThat(viaAsset.get("total").asLong()).isEqualTo(total);
        }
    }

    @Test
    void hiddenCaptureIdsInAssignmentListNeverLeak() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, LIVE);
        String na = me(a);
        DashboardUser u = userMapper.findByUsername(na);
        // 담당 행의 capture_id를 허용 캡처로 속인 숨김 캡처 인시던트(미리 줄이기를 지나도 SQL 경계에서 막혀야 한다)
        new JdbcTemplate(appDataSource).update("INSERT INTO incident_assignments (incident_id, capture_id, assignee_user_id, "
                + "assigned_at, assigned_by, version) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'seed', 1)",
                id(HIDDEN, 1, "10.73.0.1"), LIVE, u.getId());
        JsonNode me = getJson(a, "/api/incidents/queue?period=all&assignee=me&size=100");
        assertThat(me.get("total").asLong()).isZero();
        assertThat(me.toString()).doesNotContain(HIDDEN).doesNotContain("10.73.0.1");
        JsonNode none = getJson(a, "/api/incidents/queue?period=all&assignee=none&size=100");
        assertThat(none.toString()).doesNotContain(HIDDEN);
        assertThat(none.get("total").asLong()).isEqualTo(getJson(a, "/api/incidents/queue?period=all&size=100").get("total").asLong());
        JsonNode ops = getJson(a, "/api/operations?period=all");
        assertThat(ops.at("/workload/assigned").asLong()).isZero();
        assertThat(ops.at("/workload/byAssignee")).isEmpty();
    }

    /* ───────────── 큐 overdue ───────────── */

    @Test
    void ackOverdueRowsStripFilterAndSummary() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, LIVE + "," + IMPORTED);
        JsonNode q = getJson(a, "/api/incidents/queue?period=all&size=100");
        Map<String, JsonNode> byId = new HashMap<>();
        q.get("items").forEach(it -> byId.put(it.get("incidentId").asText(), it));
        assertThat(byId.get(id(LIVE, 1, "10.71.0.1")).get("ackOverdue").asBoolean()).isTrue();
        assertThat(byId.get(id(LIVE, 1, "10.71.0.1")).get("ackDueAt").asText()).isEqualTo("2026-11-20T23:30:00Z");
        assertThat(byId.get(id(LIVE, 2, "10.71.0.2")).get("ackOverdue").asBoolean()).isFalse();
        assertThat(byId.get(id(LIVE, 2, "10.71.0.2")).get("ackDueAt").asText()).isEqualTo("2026-11-21T03:00:00Z");
        // 경계: 목표 시각 = 기준 시각이면 지연 아님
        assertThat(byId.get(id(LIVE, 3, "10.71.0.3")).get("ackDueAt").asText()).isEqualTo("2026-11-21T00:00:00Z");
        assertThat(byId.get(id(LIVE, 3, "10.71.0.3")).get("ackOverdue").asBoolean()).isFalse();
        assertThat(byId.get(id(LIVE, 4, "10.71.0.4")).get("ackOverdue").asBoolean()).isTrue();
        // 조사 중·종결·가져온 데이터는 목표 없음
        assertThat(byId.get(id(LIVE, 5, "10.71.0.5")).get("ackDueAt").isNull()).isTrue();
        assertThat(byId.get(id(LIVE, 6, "10.71.0.6")).get("ackDueAt").isNull()).isTrue();
        assertThat(byId.get(id(IMPORTED, 1, "10.72.0.1")).get("ackDueAt").isNull()).isTrue();
        assertThat(byId.get(id(IMPORTED, 1, "10.72.0.1")).get("ackOverdue").asBoolean()).isFalse();
        assertThat(q.at("/summary/overdue").asLong()).isEqualTo(2);

        // 띠 필터: total = 지연 행, summary는 띠 축을 빼고 센다(같은 summary)
        JsonNode od = getJson(a, "/api/incidents/queue?period=all&size=100&overdue=true");
        assertThat(od.get("total").asLong()).isEqualTo(2);
        assertThat(od.get("summary")).isEqualTo(q.get("summary"));
        od.get("items").forEach(it -> assertThat(it.get("ackOverdue").asBoolean()).isTrue());
        // 다른 띠 축과 함께
        assertThat(getJson(a, "/api/incidents/queue?period=all&overdue=true&priority=high").get("total").asLong()).isEqualTo(1);
        assertThat(getJson(a, "/api/incidents/queue?period=all&overdue=true&source=imported").get("total").asLong()).isZero();
        // 자산 검색(Java) 경로와 같다
        JsonNode viaAsset = getJson(a, "/api/incidents/queue?period=all&size=100&overdue=true&asset=.");
        assertThat(viaAsset.get("total").asLong()).isEqualTo(2);
        assertThat(viaAsset.get("summary")).isEqualTo(q.get("summary"));
        // 상세 머리
        JsonNode meta = getJson(a, "/api/incidents/96003/rank/1").get("queueMeta");
        assertThat(meta.get("ackOverdue").asBoolean()).isTrue();
        assertThat(meta.get("anchor").asText()).isEqualTo("2026-11-21T00:00:00Z");
    }

    /* ───────────── 도우미 ───────────── */

    private Map<String, Long> totals(MockHttpSession s, String q) throws Exception {
        JsonNode r = getJson(s, "/api/incidents/queue?size=25" + (q.startsWith("&period") || q.contains("period=") ? "" : "&period=all") + q);
        Map<String, Long> out = new HashMap<>();
        out.put("all", r.get("total").asLong());
        out.put("summary", r.at("/summary/total").asLong());
        return out;
    }

    private List<String> ids(MockHttpSession s, String q) throws Exception {
        JsonNode r = getJson(s, "/api/incidents/queue?size=100" + q);
        List<String> out = new ArrayList<>();
        r.get("items").forEach(it -> out.add(it.get("incidentId").asText()));
        return out;
    }

    private org.springframework.test.web.servlet.ResultActions assign(MockHttpSession s, long jobId, int rank,
                                                                      String assignee, String expected) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("assignee", assignee);
        body.put("expected", expected);
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
        var req = post("/api/incidents/" + jobId + "/rank/" + rank + "/assignment").session(s)
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (csrf != null) {
            req = req.cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        }
        return mockMvc.perform(req);
    }

    private org.springframework.test.web.servlet.ResultActions transition(MockHttpSession s, long jobId, int rank,
                                                                          String to) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("toStatus", to);
        body.put("reason", "t25 시험");
        if ("closed".equals(to)) body.put("resolution", "benign");
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
        var req = post("/api/incidents/" + jobId + "/rank/" + rank + "/transition").session(s)
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (csrf != null) {
            req = req.cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        }
        return mockMvc.perform(req);
    }

    private final Map<MockHttpSession, String> names = new HashMap<>();

    private String me(MockHttpSession s) {
        return names.get(s);
    }

    private String createUser(UserRole role, String patterns) {
        String username = "t25_u" + (++userSeq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
        return username;
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = createUser(role, patterns);
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession s = (MockHttpSession) result.getRequest().getSession(false);
        names.put(s, username);
        return s;
    }

    private DashboardUserPrincipal principal(UserRole role, String patterns) {
        String username = createUser(role, patterns);
        DashboardUser u = userMapper.findByUsername(username);
        return new DashboardUserPrincipal(u, List.of(patterns.split(",")), FIXED_NOW);
    }

    static String id(String capture, int rank, String ip) {
        return capture + "|" + ip + "|originator|t25";
    }

    private void job(long id, String capture, String started, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', CAST(? AS TIMESTAMP WITH TIME ZONE), CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                id, capture, started, finished);
    }

    /** kind: low / medium(교차 탐지) / high(리포트 + 발송). incident_id는 캡처·IP로 정해 작업이 바뀌어도 같다 */
    private void incident(long jobId, String capture, int rank, String ip, String kind) {
        String iid = id(capture, rank, ip);
        String also = "medium".equals(kind) ? "ARRAY['autoencoder']" : "NULL";
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-19T20:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-19T20:05:00Z', 'hbos', " + also + ", 10, NULL)",
                jobId, capture, rank, iid, ip);
        if ("high".equals(kind)) {
            jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                    + "zeekad_report, created_at) VALUES (?, ?, 'template', 'template.v1', '{}' FORMAT JSON, TIMESTAMP WITH TIME ZONE '2026-11-19T20:05:00Z')",
                    jobId, iid);
            jdbc().update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                    + "VALUES (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-19T20:05:00Z')", jobId, iid);
        }
    }

    private void setStatus(long jobId, String capture, int rank, String ip, String status, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), 't25')", jobId, id(capture, rank, ip), status, resolution, at);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private JsonNode json(MvcResult r) throws Exception {
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
