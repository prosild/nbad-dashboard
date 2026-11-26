package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.HandlingPoint;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T53 다시 열기: POST /api/incidents/{jobId}/rank/{rank}/reopen → dashboard.reopen_incident(H2 대역, 계약은 zeek_AD migration 018).
 * 검사 순서(접근 → 역할 → 사유 → 화면의 판정), 성공의 상태·이력·감사·담당, 거부(종결 아님·판정 다름·없는 인시던트·동시 두 번),
 * 다시 연 뒤의 규칙(담당 변경, 정탐 재종결의 조치 기록 규칙, 처리 시간, 판정 집계, 우선순위), 상세 응답의 canReopen.
 * 기존 전이 경로(transition)의 closed → investigating 거부는 IncidentTransitionIntegrationTest가 그대로 본다.
 * 시험용 zeekad 행은 job 97530~97549.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T53ReopenIntegrationTest {

    static final String LIVE = "lab-t53a";
    static final String HIDDEN = "lab-t53b";
    static final long JOB = 97530L;
    static final long HIDDEN_JOB = 97540L;
    static final String TRANSITION_AUDIT = "INCIDENT_STATUS_TRANSITION";
    static final String CONFLICT_MESSAGE = "다른 사람이 먼저 상태나 판정을 바꿨습니다. 새로고침한 뒤 다시 확인하세요.";
    static final String SUCCESS_MESSAGE = "인시던트를 다시 열었습니다. 상태는 분석 중입니다.";
    /** 시드한 첫 착수·첫 종결 시각 */
    static final String FIRST_ACK = "2026-11-25T01:00:00Z";
    static final String FIRST_CLOSE = "2026-11-25T01:10:00Z";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private ZeekadReadMapper zeekadReadMapper;
    @Autowired private ZeekadWriteMapper zeekadWriteMapper;
    @Autowired private IncidentQueueService queueService;
    @Autowired private UserMapper userMapper;
    @Autowired private TotpService totpService;
    @Autowired private Clock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int userSeq = 0;
    private final Map<MockHttpSession, String> names = new HashMap<>();

    @BeforeEach
    void seed() {
        cleanup();
        job(JOB, LIVE);
        job(HIDDEN_JOB, HIDDEN);
        incident(JOB, LIVE, 1);                                    // 신규(open): 상태 행 없음
        incident(JOB, LIVE, 2);                                    // 분석 중
        history(JOB, LIVE, 2, "open", "investigating", null, "t53_seed", FIRST_ACK);
        setStatus(JOB, LIVE, 2, "investigating", null, FIRST_ACK);
        closedAfterInvestigation(3, "false_positive");             // 오탐 종결
        closedAfterInvestigation(4, "true_positive");              // 정탐 종결
        incident(JOB, LIVE, 5);                                    // 분석 중 이력 없이 종결(파이프라인이 닫은 건)
        history(JOB, LIVE, 5, "open", "closed", "benign", "zeekad-pipeline", FIRST_CLOSE);
        setStatus(JOB, LIVE, 5, "closed", "benign", FIRST_CLOSE);
        closedAfterInvestigation(6, "false_positive");             // 동시 요청용
        incident(HIDDEN_JOB, HIDDEN, 1);                           // 허용 밖 캡처의 종결 건
        setStatus(HIDDEN_JOB, HIDDEN, 1, "closed", "false_positive", FIRST_CLOSE);
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 97530 AND 97549";
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        // 착수·다시 열기 때 자동 지정된 담당 행과 정탐 재종결 시험의 조치 기록. T25·T56 시험과 같은 방식으로 지운다.
        JdbcTemplate a = app();
        a.execute("DROP TRIGGER IF EXISTS trg_incident_assignment_history_immutable");
        a.update("DELETE FROM incident_assignment_history");
        a.update("DELETE FROM incident_assignments");
        a.execute("CREATE TRIGGER trg_incident_assignment_history_immutable BEFORE UPDATE, DELETE ON incident_assignment_history "
                + "FOR EACH ROW CALL \"com.zeekad.dashboard.audit.H2AssignmentHistoryImmutableTrigger\"");
        a.execute("DROP TRIGGER IF EXISTS trg_incident_response_actions_immutable");
        a.update("DELETE FROM incident_response_actions");
        a.execute("CREATE TRIGGER trg_incident_response_actions_immutable BEFORE UPDATE, DELETE ON incident_response_actions "
                + "FOR EACH ROW CALL \"com.zeekad.dashboard.audit.H2ResponseActionImmutableTrigger\"");
    }

    /* ───────────── 성공 ───────────── */

    @Test
    void reopenClosedIncidentReturnsToInvestigatingKeepsHistoryAuditsAndAutoAssigns() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String aName = names.get(analyst);

        JsonNode r = json(reopen(analyst, JOB, 3, "  다른 호스트에서도 같은 접속이 보여 다시 본다  ", "false_positive")
                .andExpect(status().isOk()).andReturn());
        assertThat(r.get("succeeded").asBoolean()).isTrue();
        assertThat(r.get("code").asText()).isEqualTo("OK");
        assertThat(r.get("message").asText()).isEqualTo(SUCCESS_MESSAGE);

        // 상태 분석 중, 판정 없음. 앞선 종결 이력은 그대로 남고 closed → investigating 한 행이 더해진다(행위자, 다듬은 사유).
        assertThat(statusOf(3)).isEqualTo("investigating|null");
        List<Map<String, Object>> rows = historyRows(3);
        assertThat(rows).hasSize(3);
        assertThat(rows.get(1).get("to_status")).isEqualTo("closed");
        assertThat(rows.get(1).get("zeekad_resolution")).isEqualTo("false_positive");
        Map<String, Object> last = rows.get(2);
        assertThat(last.get("from_status")).isEqualTo("closed");
        assertThat(last.get("to_status")).isEqualTo("investigating");
        assertThat(last.get("zeekad_resolution")).isNull();
        assertThat(last.get("actor")).isEqualTo(aName);
        assertThat(last.get("reason")).isEqualTo("다른 호스트에서도 같은 접속이 보여 다시 본다");
        assertThat(((Number) last.get("job_id")).longValue()).isEqualTo(JOB);

        // 감사: 기존 유형 한 건, detail = {operation, toStatus, previousResolution, reason}
        List<AuditLog> logs = audits(TRANSITION_AUDIT, aName);
        assertThat(logs).hasSize(1);
        JsonNode detail = objectMapper.readTree(logs.get(0).getDetailJson());
        assertThat(detail.get("operation").asText()).isEqualTo("reopen");
        assertThat(detail.get("toStatus").asText()).isEqualTo("investigating");
        assertThat(detail.get("previousResolution").asText()).isEqualTo("false_positive");
        assertThat(detail.get("reason").asText()).isEqualTo("다른 호스트에서도 같은 접속이 보여 다시 본다");
        assertThat(detail.size()).isEqualTo(4);
        assertThat(logs.get(0).getTargetIncidentId()).isEqualTo(id(LIVE, 3));

        // 미배정이면 다시 연 사람이 담당자다(착수 때와 같은 자동 지정)
        JsonNode d = detail(analyst, JOB, 3);
        assertThat(d.at("/assignment/assignee/username").asText()).isEqualTo(aName);
        assertThat(d.at("/assignmentHistory/0/reason").asText()).isEqualTo("auto_on_start");
        assertThat(d.at("/detail/currentStatus").asText()).isEqualTo("investigating");
        assertThat(d.at("/detail/currentResolution").isNull()).isTrue();
        assertThat(d.at("/detail/nextAllowedStatus").asText()).isEqualTo("closed");
        assertThat(d.get("canReopen").asBoolean()).isFalse();
    }

    @Test
    void reopenKeepsExistingAssigneeAndNormalizesExpectedResolution() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        MockHttpSession owner = login(UserRole.ANALYST, LIVE);
        String ownerName = names.get(owner);
        // 종결 전 담당자가 남아 있는 경우: 종결 건은 담당을 바꿀 수 없어 시드에서 직접 넣는다(종결해도 담당자는 남는다)
        assignDirect(4, owner);

        // 대소문자·공백이 섞인 판정은 맞춰서 통과한다
        reopen(analyst, JOB, 4, "정탐 근거 재확인", "  True_Positive ").andExpect(status().isOk());
        assertThat(statusOf(4)).isEqualTo("investigating|null");
        JsonNode d = detail(analyst, JOB, 4);
        assertThat(d.at("/assignment/assignee/username").asText()).isEqualTo(ownerName);
        assertThat(d.get("assignmentHistory").size()).isEqualTo(1);
        assertThat(audits("INCIDENT_ASSIGNMENT", names.get(analyst))).isEmpty();
        assertThat(objectMapper.readTree(audits(TRANSITION_AUDIT, names.get(analyst)).get(0).getDetailJson())
                .get("previousResolution").asText()).isEqualTo("true_positive");
    }

    /* ───────────── 거부 ───────────── */

    @Test
    void rejectsInOrderAccessRoleReasonExpectedResolutionThenDbRules() throws Exception {
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE);
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String vName = names.get(viewer);
        String aName = names.get(analyst);

        // 허용 밖 캡처: 조회자도 분석가도 403 + IDOR 감사(역할보다 접근을 먼저 본다). 상태는 그대로.
        reopen(viewer, HIDDEN_JOB, 1, "사유", "false_positive").andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", vName)).hasSize(1);
        reopen(analyst, HIDDEN_JOB, 1, "사유", "false_positive").andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", aName)).hasSize(1);
        assertThat(statusOfHidden()).isEqualTo("closed|false_positive");

        // 조회자, 허용 캡처: 403(사유·판정이 틀려도 역할을 먼저 본다), IDOR 감사 없음
        reopen(viewer, JOB, 3, "사유", "false_positive").andExpect(status().isForbidden());
        reopen(viewer, JOB, 3, "", "bogus").andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", vName)).hasSize(1);
        // CSRF 없는 POST
        mockMvc.perform(post("/api/incidents/" + JOB + "/rank/3/reopen").session(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"사유\",\"expectedResolution\":\"false_positive\"}"))
                .andExpect(status().isForbidden());

        // 사유: trim 뒤 비면 400, 500 코드 포인트 초과 400(판정 검사보다 먼저)
        for (String blank : new String[]{null, "", "   "}) {
            JsonNode b = json(reopen(analyst, JOB, 3, blank, "bogus").andExpect(status().isBadRequest()).andReturn());
            assertThat(b.get("code").asText()).isEqualTo("INVALID_REQUEST");
            assertThat(b.get("message").asText()).isEqualTo("다시 여는 사유를 입력해 주세요.");
        }
        JsonNode tooLong = json(reopen(analyst, JOB, 3, " " + "😀".repeat(501) + " ", "false_positive")
                .andExpect(status().isBadRequest()).andReturn());
        assertThat(tooLong.get("message").asText()).isEqualTo("다시 여는 사유는 500자까지 입력할 수 있습니다.");

        // 화면의 판정(expectedResolution): 필수, 세 값 밖이면 400
        for (String bad : new String[]{null, "", "  ", "unknown", "closed", "true positive"}) {
            JsonNode b = json(reopen(analyst, JOB, 3, "사유", bad).andExpect(status().isBadRequest()).andReturn());
            assertThat(b.get("code").asText()).as("expected '%s'", bad).isEqualTo("INVALID_REQUEST");
            assertThat(b.get("message").asText()).isEqualTo("다시 열려면 화면에 보이는 판정(정탐·오탐·정상)을 함께 보내야 합니다.");
        }
        // 본문이 JSON null이어도 같은 순서(사유에서 400)
        mockMvc.perform(post("/api/incidents/" + JOB + "/rank/3/reopen").session(analyst).with(csrfOf(analyst))
                        .contentType(MediaType.APPLICATION_JSON).content("null"))
                .andExpect(status().isBadRequest());
        assertThat(statusOf(3)).isEqualTo("closed|false_positive");

        // 종결이 아닌 건: 409, 고정 문장(DB 문구의 상태 코드 원문을 내보내지 않는다), 상태 행을 만들지 않는다
        for (int rank : new int[]{1, 2}) {
            MvcResult res = reopen(analyst, JOB, rank, "사유", "false_positive").andExpect(status().isConflict()).andReturn();
            JsonNode c = json(res);
            assertThat(c.get("code").asText()).isEqualTo("CONFLICT");
            assertThat(c.get("message").asText()).isEqualTo(CONFLICT_MESSAGE);
            assertThat(res.getResponse().getContentAsString(StandardCharsets.UTF_8))
                    .doesNotContain("investigating", "open", "지금 상태", "SQL");
        }
        assertThat(statusRowCount(1)).isZero();
        assertThat(statusOf(2)).isEqualTo("investigating|null");

        // 화면의 판정이 지금과 다르다: 409, 아무것도 바뀌지 않고 응답에 DB 문구가 없다
        MvcResult differ = reopen(analyst, JOB, 3, "사유", "true_positive").andExpect(status().isConflict()).andReturn();
        assertThat(json(differ).get("message").asText()).isEqualTo(CONFLICT_MESSAGE);
        assertThat(differ.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .doesNotContain("false_positive", "지금 결론", "결론");
        assertThat(statusOf(3)).isEqualTo("closed|false_positive");
        assertThat(historyRows(3)).hasSize(2);

        // 큐에 없는 순위는 접근 검사가 먼저 막는다(403 + IDOR 감사. 전이와 같다). DB 함수의 02000 → 404는
        // T53ReopenUnavailableIntegrationTest(쓰기 매퍼 대역)와 아래 H2 대역 직접 호출로 본다.
        reopen(analyst, JOB, 99, "사유", "false_positive").andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", aName)).hasSize(2);

        // 거부된 요청은 상태 변경 감사를 남기지 않는다
        assertThat(audits(TRANSITION_AUDIT, aName)).isEmpty();
        assertThat(audits(TRANSITION_AUDIT, vName)).isEmpty();
    }

    @Test
    void concurrentReopenAllowsOnlyOneWinner() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, LIVE);
        MockHttpSession b = login(UserRole.ANALYST, LIVE);
        Cookie csrfA = csrf(a);
        Cookie csrfB = csrf(b);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Callable<MvcResult>> tasks = new ArrayList<>();
            for (Object[] who : new Object[][]{{a, csrfA, "동시 A"}, {b, csrfB, "동시 B"}}) {
                tasks.add(() -> {
                    ready.countDown();
                    start.await(5, TimeUnit.SECONDS);
                    Cookie c = (Cookie) who[1];
                    return mockMvc.perform(post("/api/incidents/" + JOB + "/rank/6/reopen").session((MockHttpSession) who[0])
                                    .cookie(c).header("X-XSRF-TOKEN", c.getValue())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(Map.of("reason", who[2], "expectedResolution", "false_positive"))))
                            .andReturn();
                });
            }
            List<Future<MvcResult>> futures = new ArrayList<>();
            for (Callable<MvcResult> t : tasks) {
                futures.add(pool.submit(t));
            }
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            int ok = 0;
            int conflict = 0;
            for (Future<MvcResult> f : futures) {
                MvcResult res = f.get(10, TimeUnit.SECONDS);
                if (res.getResponse().getStatus() == 200) {
                    ok++;
                } else if (res.getResponse().getStatus() == 409) {
                    conflict++;
                    assertThat(json(res).get("message").asText()).isEqualTo(CONFLICT_MESSAGE);
                }
            }
            assertThat(ok).isEqualTo(1);
            assertThat(conflict).isEqualTo(1);
            assertThat(statusOf(6)).isEqualTo("investigating|null");
            assertThat(historyRows(6).stream().filter(r -> "closed".equals(r.get("from_status")))).hasSize(1);
        } finally {
            pool.shutdownNow();
        }
    }

    /* ───────────── 상세 응답의 canReopen ───────────── */

    @Test
    void canReopenOnlyForAnalystOrAdminOnClosedIncident() throws Exception {
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE);
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        MockHttpSession admin = login(UserRole.ADMIN, LIVE);
        for (MockHttpSession s : List.of(analyst, admin)) {
            assertThat(detail(s, JOB, 3).get("canReopen").asBoolean()).isTrue();   // 종결
            assertThat(detail(s, JOB, 5).get("canReopen").asBoolean()).isTrue();
            assertThat(detail(s, JOB, 1).get("canReopen").asBoolean()).isFalse();  // 신규
            assertThat(detail(s, JOB, 2).get("canReopen").asBoolean()).isFalse();  // 분석 중
        }
        for (int rank : new int[]{1, 2, 3}) {
            JsonNode d = detail(viewer, JOB, rank);
            assertThat(d.has("canReopen")).isTrue();
            assertThat(d.get("canReopen").asBoolean()).isFalse();
        }
        // 기존 값은 그대로: 종결 건은 상태 변경 다음 단계가 없다
        JsonNode closed = detail(analyst, JOB, 3);
        assertThat(closed.at("/detail/canTransition").asBoolean()).isTrue();
        assertThat(closed.at("/detail/nextAllowedStatus").isNull() || closed.at("/detail/nextAllowedStatus").isMissingNode()).isTrue();
        // 관리자도 다시 열 수 있다
        reopen(admin, JOB, 5, "관리자 재검토", "benign").andExpect(status().isOk());
        assertThat(statusOf(5)).isEqualTo("investigating|null");
    }

    /* ───────────── 다시 연 뒤의 규칙 ───────────── */

    @Test
    void afterReopenAssignmentCanChangeAndTruePositiveReCloseNeedsResponseAction() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        MockHttpSession other = login(UserRole.ANALYST, LIVE);
        String aName = names.get(analyst);
        reopen(analyst, JOB, 3, "오탐 판정 재검토", "false_positive").andExpect(status().isOk());

        // 담당을 바꿀 수 있다(종결 건에서는 409 INCIDENT_CLOSED였다)
        assertThat(detail(analyst, JOB, 3).get("canAssign").asBoolean()).isTrue();
        assign(analyst, JOB, 3, names.get(other), aName).andExpect(status().isOk());
        assertThat(detail(analyst, JOB, 3).at("/assignment/assignee/username").asText()).isEqualTo(names.get(other));

        // 정탐으로 다시 종결: 이 인시던트에 조치 기록이 없으면 409 RESPONSE_ACTION_REQUIRED, 있으면 통과
        assertThat(json(transition(analyst, JOB, 3, "closed", "true_positive", "정탐으로 정정").andExpect(status().isConflict())
                .andReturn()).get("code").asText()).isEqualTo("RESPONSE_ACTION_REQUIRED");
        assertThat(statusOf(3)).isEqualTo("investigating|null");
        recordAction(analyst, JOB, 3, "block_ip", "방화벽 차단 요청").andExpect(status().isOk());
        transition(analyst, JOB, 3, "closed", "true_positive", "정탐으로 정정").andExpect(status().isOk());
        assertThat(statusOf(3)).isEqualTo("closed|true_positive");
        // 앞선 판정(오탐)과 새 판정(정탐)이 모두 이력에 남는다
        assertThat(historyRows(3)).extracting(r -> r.get("from_status") + ">" + r.get("to_status") + ":" + r.get("zeekad_resolution"))
                .containsExactly("open>investigating:null", "investigating>closed:false_positive",
                        "closed>investigating:null", "investigating>closed:true_positive");
        // 다시 종결한 건을 또 다시 열 수 있다(새 판정을 기대값으로)
        reopen(analyst, JOB, 3, "한 번 더", "false_positive").andExpect(status().isConflict());
        reopen(analyst, JOB, 3, "한 번 더", "true_positive").andExpect(status().isOk());
    }

    @Test
    void afterReopenHandlingTimesPriorityAndResolutionCounts() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);

        // 다시 열기 전: 종결 건은 우선순위가 없고, 판정 집계에 든다(종결이고 판정 있음 3·4·5·6)
        assertThat(detail(analyst, JOB, 3).at("/queueMeta/priority").isNull()).isTrue();
        FeedbackSummaryRecord before = feedbackAll();
        assertThat(before.getResolved()).isEqualTo(4L);
        assertThat(before.getFalsePositive()).isEqualTo(2L);
        assertThat(before.getTruePositive()).isEqualTo(1L);
        assertThat(before.getBenign()).isEqualTo(1L);

        reopen(analyst, JOB, 3, "재검토", "false_positive").andExpect(status().isOk());

        // 다시 열면 우선순위가 다시 매겨지고 판정 집계에서 빠진다
        assertThat(detail(analyst, JOB, 3).at("/queueMeta/priority").asText()).isNotBlank();
        assertThat(point(3).getPriority()).isNotNull();
        FeedbackSummaryRecord reopened = feedbackAll();
        assertThat(reopened.getResolved()).isEqualTo(3L);
        assertThat(reopened.getFalsePositive()).isEqualTo(1L);

        // 착수 시각은 처음 값(첫 investigating 이력) 그대로, 분석 중이라 종결 시각 기준 처리 시간은 없다
        HandlingPoint open = point(3);
        assertThat(open.getStatusNorm()).isEqualTo("investigating");
        assertThat(open.getAckAt().toInstant()).isEqualTo(Instant.parse(FIRST_ACK));

        // 다시 종결(정상): 처리 시간은 마지막 종결 시각(상태 행의 갱신 시각) 기준, 착수 시각은 처음 값 그대로
        transition(analyst, JOB, 3, "closed", "benign", "정상 업무로 확인").andExpect(status().isOk());
        HandlingPoint reclosed = point(3);
        assertThat(reclosed.getStatusNorm()).isEqualTo("closed");
        assertThat(reclosed.getPriority()).isNull();
        assertThat(reclosed.getAckAt().toInstant()).isEqualTo(Instant.parse(FIRST_ACK));
        assertThat(reclosed.getStatusUpdatedAt().toInstant()).isAfter(Instant.parse(FIRST_CLOSE));
        assertThat(reclosed.getStatusUpdatedAt().toInstant()).isEqualTo(statusUpdatedAt(3));
        assertThat(reclosed.getZeekadResolution()).isEqualTo("benign");
        // 새 판정으로 집계에 다시 든다
        FeedbackSummaryRecord after = feedbackAll();
        assertThat(after.getResolved()).isEqualTo(4L);
        assertThat(after.getFalsePositive()).isEqualTo(1L);
        assertThat(after.getBenign()).isEqualTo(2L);
    }

    @Test
    void reopeningIncidentClosedWithoutInvestigationMakesReopenTimeTheAckTime() throws Exception {
        // 지금 식(착수 = to_status가 investigating인 이력의 가장 이른 시각)의 결과를 적어 둔다. 고치지 않는다.
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        assertThat(point(5).getAckAt()).isNull();
        reopen(analyst, JOB, 5, "파이프라인 판정 재검토", "benign").andExpect(status().isOk());
        Map<String, Object> reopenRow = historyRows(5).get(1);
        assertThat(reopenRow.get("from_status")).isEqualTo("closed");
        HandlingPoint p = point(5);
        assertThat(p.getAckAt()).isNotNull();
        assertThat(p.getAckAt().toInstant()).isEqualTo(toInstant(reopenRow.get("changed_at")));
        assertThat(p.getAckAt().toInstant()).isAfter(Instant.parse(FIRST_CLOSE));
    }

    /* ───────────── H2 대역이 migration 018의 계약을 따른다 ───────────── */

    @Test
    void h2DoubleFollowsMigration018Contract() {
        // 1) actor·reason이 비거나 공백만이면 22023(사건 확인보다 먼저)
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, "없는 사건", "  ", "사유", null), "22023", "누가(actor)와 왜(reason)");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), "t53", " ", null), "22023", "누가(actor)와 왜(reason)");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), null, "사유", null), "22023", "누가(actor)와 왜(reason)");
        // 2) 화면이 보던 작업에 사건이 없으면 02000
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, "없는 사건", "t53", "사유", null), "02000", "사건이 없다");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(HIDDEN_JOB, id(LIVE, 3), "t53", "사유", null), "02000", "사건이 없다");
        // 3·4) 종결이 아니면 22023(상태 행이 없으면 열림). 거부할 때 상태 행을 만들지 않는다
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 1), "t53", "사유", null), "22023", "지금 상태: open");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 2), "t53", "사유", null), "22023", "지금 상태: investigating");
        assertThat(statusRowCount(1)).isZero();
        // 5) 기대 결론: 세 값 밖이면 22023, 지금 결론과 다르면 22023. trim·소문자 변환 없이 글자 그대로 견준다
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), "t53", "사유", "False_Positive"), "22023", "기대 결론");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), "t53", "사유", "false_positive "), "22023", "기대 결론");
        assertSqlState(() -> zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), "t53", "사유", "true_positive"), "22023",
                "지금 결론: false_positive");
        assertThat(statusOf(3)).isEqualTo("closed|false_positive");
        assertThat(historyRows(3)).hasSize(2);
        // 기대 결론이 NULL이면 상태만 본다. actor·reason은 받은 값 그대로 기록한다(다듬기는 서비스가 한다)
        assertThat(zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 3), " t53 ", " 사유 ", null)).isEqualTo("investigating");
        assertThat(statusOf(3)).isEqualTo("investigating|null");
        assertThat(jdbc().queryForObject("SELECT updated_by FROM dashboard.raw_incident_status WHERE incident_id = ?", String.class,
                id(LIVE, 3))).isEqualTo(" t53 ");
        Map<String, Object> row = historyRows(3).get(2);
        assertThat(row.get("from_status")).isEqualTo("closed");
        assertThat(row.get("to_status")).isEqualTo("investigating");
        assertThat(row.get("zeekad_resolution")).isNull();
        assertThat(row.get("actor")).isEqualTo(" t53 ");
        assertThat(row.get("reason")).isEqualTo(" 사유 ");
        // 같은 결론으로 다시 열기(4번, 정탐)
        assertThat(zeekadWriteMapper.reopenIncident(JOB, id(LIVE, 4), "t53", "사유", "true_positive")).isEqualTo("investigating");
    }

    private void assertSqlState(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String state, String messagePart) {
        assertThatThrownBy(call).satisfies(ex -> {
            SQLException found = null;
            for (Throwable cur = ex; cur != null; cur = cur.getCause()) {
                if (cur instanceof SQLException sql && state.equals(sql.getSQLState())) {
                    found = sql;
                    break;
                }
            }
            assertThat((Throwable) found).as("SQLSTATE %s", state).isNotNull();
            assertThat(found.getMessage()).contains(messagePart);
        });
    }

    /* ───────────── 도우미 ───────────── */

    private void closedAfterInvestigation(int rank, String resolution) {
        incident(JOB, LIVE, rank);
        history(JOB, LIVE, rank, "open", "investigating", null, "t53_seed", FIRST_ACK);
        history(JOB, LIVE, rank, "investigating", "closed", resolution, "t53_seed", FIRST_CLOSE);
        setStatus(JOB, LIVE, rank, "closed", resolution, FIRST_CLOSE);
    }

    private ResultActions reopen(MockHttpSession s, long jobId, int rank, String reason, String expected) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("reason", reason);
        body.put("expectedResolution", expected);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/reopen", body);
    }

    private ResultActions transition(MockHttpSession s, long jobId, int rank, String to, String resolution, String reason)
            throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("toStatus", to);
        body.put("resolution", resolution);
        body.put("reason", reason);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/transition", body);
    }

    private ResultActions assign(MockHttpSession s, long jobId, int rank, String assignee, String expected) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("assignee", assignee);
        body.put("expected", expected);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/assignment", body);
    }

    private ResultActions recordAction(MockHttpSession s, long jobId, int rank, String action, String note) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("action", action);
        body.put("note", note);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/response-actions", body);
    }

    /** 종결 전 담당자(종결 건은 API로 담당을 바꿀 수 없다). 앱 DB의 현재 담당 행 + 이력 행 하나. */
    private void assignDirect(int rank, MockHttpSession owner) {
        String username = names.get(owner);
        Long userId = app().queryForObject("SELECT id FROM users WHERE username = ?", Long.class, username);
        app().update("INSERT INTO incident_assignments (incident_id, capture_id, assignee_user_id, assigned_at, assigned_by, version) "
                + "VALUES (?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-25T01:00:00Z', ?, 1)", id(LIVE, rank), LIVE, userId, username);
        app().update("INSERT INTO incident_assignment_history (incident_id, capture_id, job_id, from_user_id, to_user_id, actor_username, "
                + "reason, changed_at) VALUES (?, ?, ?, NULL, ?, ?, 'manual', TIMESTAMP WITH TIME ZONE '2026-11-25T01:00:00Z')",
                id(LIVE, rank), LIVE, JOB, userId, username);
    }

    private ResultActions postJson(MockHttpSession s, String url, Map<String, String> body) throws Exception {
        Cookie csrf = csrf(s);
        var req = post(url).session(s).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (csrf != null) {
            req = req.cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        }
        return mockMvc.perform(req);
    }

    private Cookie csrf(MockHttpSession s) throws Exception {
        return mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
    }

    private org.springframework.test.web.servlet.request.RequestPostProcessor csrfOf(MockHttpSession s) throws Exception {
        Cookie c = csrf(s);
        return req -> {
            req.setCookies(c);
            req.addHeader("X-XSRF-TOKEN", c.getValue());
            return req;
        };
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t53_u" + (++userSeq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
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
        if (role == UserRole.ADMIN) {
            // 관리자는 TOTP 설정을 마쳐야 API를 쓸 수 있다(AnalystReviewDecisionIntegrationTest와 같은 방식)
            DashboardUser admin = userMapper.findByUsername(username);
            String code = totpService.generateCode(admin.getTotpSecret(), clock.instant());
            mockMvc.perform(post("/api/auth/totp/setup").session(s).with(csrfOf(s))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                    .andExpect(status().isOk());
        }
        return s;
    }

    private List<AuditLog> audits(String actionType, String actor) {
        return auditLogMapper.findFiltered(actionType, actor, 50);
    }

    private HandlingPoint point(int rank) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t53-principal");
        u.setDisplayName("t53");
        u.setRole(UserRole.ANALYST);
        u.setEnabled(true);
        DashboardUserPrincipal p = new DashboardUserPrincipal(u, List.of(LIVE), Instant.now());
        IncidentQueueService.Condition cond = queueService.resolveCondition(p, "all", null, null, "127.0.0.1");
        return zeekadReadMapper.findHandlingPoints(cond.criteria(), null).stream()
                .filter(h -> id(LIVE, rank).equals(h.getIncidentId()))
                .findFirst().orElseThrow();
    }

    private FeedbackSummaryRecord feedbackAll() {
        return zeekadReadMapper.findRawFeedbackSummaries(LIVE).stream()
                .map(FeedbackSummaryRecord::fromRawMap)
                .filter(r -> "all".equals(r.getZeekadPickedBy()))
                .findFirst().orElseThrow();
    }

    private String statusOf(int rank) {
        return jdbc().queryForObject("SELECT zeekad_status || '|' || COALESCE(zeekad_resolution, 'null') FROM dashboard.raw_incident_status "
                + "WHERE incident_id = ?", String.class, id(LIVE, rank));
    }

    private String statusOfHidden() {
        return jdbc().queryForObject("SELECT zeekad_status || '|' || COALESCE(zeekad_resolution, 'null') FROM dashboard.raw_incident_status "
                + "WHERE incident_id = ?", String.class, id(HIDDEN, 1));
    }

    private int statusRowCount(int rank) {
        Integer n = jdbc().queryForObject("SELECT COUNT(*) FROM dashboard.raw_incident_status WHERE incident_id = ?",
                Integer.class, id(LIVE, rank));
        return n == null ? 0 : n;
    }

    private Instant statusUpdatedAt(int rank) {
        return toInstant(jdbc().queryForObject("SELECT updated_at FROM dashboard.raw_incident_status WHERE incident_id = ?",
                Object.class, id(LIVE, rank)));
    }

    private List<Map<String, Object>> historyRows(int rank) {
        return jdbc().queryForList("SELECT job_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at "
                + "FROM dashboard.raw_incident_status_history WHERE incident_id = ? ORDER BY changed_at, _ROWID_", id(LIVE, rank));
    }

    private static Instant toInstant(Object value) {
        if (value instanceof OffsetDateTime odt) {
            return odt.toInstant();
        }
        if (value instanceof Timestamp ts) {
            return ts.toInstant();
        }
        if (value instanceof java.time.ZonedDateTime zdt) {
            return zdt.toInstant();
        }
        throw new IllegalStateException("시각 형식을 모른다: " + value);
    }

    static String id(String capture, int rank) {
        return capture + "|10.53.0." + rank + "|originator|t53";
    }

    private void job(long jobId, String capture) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-25T00:55:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-25T00:58:00Z', NULL, 0)", jobId, capture);
    }

    private void incident(long jobId, String capture, int rank) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-25T00:40:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-25T00:45:00Z', 'hbos', NULL, 10, NULL)",
                jobId, capture, rank, id(capture, rank), "10.53.0." + rank);
    }

    private void setStatus(long jobId, String capture, int rank, String status, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), 't53_seed')", jobId, id(capture, rank), status, resolution, at);
    }

    private void history(long jobId, String capture, int rank, String from, String to, String resolution, String actor, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution, "
                + "actor, reason, changed_at) VALUES (?, ?, ?, ?, ?, ?, 't53 시드', CAST(? AS TIMESTAMP WITH TIME ZONE))",
                jobId, id(capture, rank), from, to, resolution, actor, at);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private JsonNode detail(MockHttpSession session, long jobId, int rank) throws Exception {
        MvcResult r = mockMvc.perform(get("/api/incidents/" + jobId + "/rank/" + rank).session(session))
                .andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private JsonNode json(MvcResult r) throws Exception {
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
