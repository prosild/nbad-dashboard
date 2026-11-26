package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.UserRole;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T56 대응 조치 기록: V5(H2)와 고칠 수 없는 행, 기록 API의 검증 순서(접근 → 역할 → 상태 → 종류 → 메모)와 오류 코드·감사,
 * 상세 응답의 목록·canRecordResponse, 조회자 응답에 메모가 없음, 정탐 종결 규칙(분석 중 + 정탐 + 기록 0건이면 409이고 상태가 그대로).
 * 시험용 zeekad 행은 job 97560~97579, 조치 행은 시험마다 지운다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T56ResponseActionIntegrationTest {

    static final String LIVE = "lab-t56a";
    static final String HIDDEN = "lab-t56b";
    static final long JOB = 97560L;
    static final long HIDDEN_JOB = 97570L;
    static final String REQUIRED_MESSAGE =
            "정탐으로 종결하려면 대응 조치를 먼저 기록하세요. 조치가 없었다면 '조치 없음'을 기록하세요.";
    static final String ACTION_AUDIT = "INCIDENT_RESPONSE_ACTION";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int userSeq = 0;
    private final Map<MockHttpSession, String> names = new HashMap<>();

    @BeforeEach
    void seed() {
        // 다른 시험 클래스가 같은 H2에 남긴 조치 행(고칠 수 없어 그쪽에서 못 지운다)이 있으면 먼저 비운다.
        clearResponseActions();
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-25T01:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-25T01:05:00Z', NULL, 0)", JOB, LIVE);
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-25T01:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-25T01:05:00Z', NULL, 0)", HIDDEN_JOB, HIDDEN);
        incident(JOB, LIVE, 1);                                   // 신규(open): 상태 행 없음
        incident(JOB, LIVE, 2);
        setStatus(JOB, LIVE, 2, "investigating", null);
        incident(JOB, LIVE, 3);
        setStatus(JOB, LIVE, 3, "closed", "benign");
        incident(JOB, LIVE, 4);
        setStatus(JOB, LIVE, 4, "investigating", null);
        incident(JOB, LIVE, 5);
        setStatus(JOB, LIVE, 5, "investigating", null);
        incident(JOB, LIVE, 6);
        setStatus(JOB, LIVE, 6, "investigating", null);
        incident(HIDDEN_JOB, HIDDEN, 1);
        setStatus(HIDDEN_JOB, HIDDEN, 1, "investigating", null);
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 97560 AND 97579";
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        clearResponseActions();
        // 착수 때 자동 지정된 담당 행. T25 시험과 같은 방식으로 지운다.
        JdbcTemplate a = app();
        a.execute("DROP TRIGGER IF EXISTS trg_incident_assignment_history_immutable");
        a.update("DELETE FROM incident_assignment_history");
        a.update("DELETE FROM incident_assignments");
        a.execute("CREATE TRIGGER trg_incident_assignment_history_immutable BEFORE UPDATE, DELETE ON incident_assignment_history "
                + "FOR EACH ROW CALL \"com.zeekad.dashboard.audit.H2AssignmentHistoryImmutableTrigger\"");
    }

    /* ───────────── V5 ───────────── */

    @Test
    void v5MigrationCreatesTableAndRowsCannotBeChanged() throws Exception {
        JdbcTemplate a = app();
        assertThat(a.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version = '5' AND success = TRUE",
                Integer.class)).isEqualTo(1);
        MockHttpSession s = login(UserRole.ANALYST, LIVE);
        record(s, JOB, 2, "block_ip", "방화벽 정책 요청").andExpect(status().isOk());
        assertThat(count()).isEqualTo(1);
        assertThatThrownBy(() -> a.update("UPDATE incident_response_actions SET note = 'tampered'"))
                .rootCause().hasMessageContaining("append-only");
        assertThatThrownBy(() -> a.update("UPDATE incident_response_actions SET action_type = 'none'"))
                .rootCause().hasMessageContaining("append-only");
        assertThatThrownBy(() -> a.update("DELETE FROM incident_response_actions"))
                .rootCause().hasMessageContaining("append-only");
        assertThat(a.queryForObject("SELECT note FROM incident_response_actions", String.class)).isEqualTo("방화벽 정책 요청");
        // 종류는 일곱 값만(CHECK)
        assertThatThrownBy(() -> a.update("INSERT INTO incident_response_actions (incident_id, capture_id, job_id, action_type, "
                + "note, actor_username, recorded_at) VALUES ('x', 'x', 1, 'shutdown', NULL, 'x', CURRENT_TIMESTAMP)"))
                .isInstanceOf(Exception.class);
        for (String action : List.of("block_ip", "isolate_host", "lock_account", "handover", "monitor", "none", "other")) {
            a.update("INSERT INTO incident_response_actions (incident_id, capture_id, job_id, action_type, note, actor_username, "
                    + "recorded_at) VALUES ('x', 'x', 1, ?, 'n', 'x', CURRENT_TIMESTAMP)", action);
        }
        assertThat(count()).isEqualTo(8);
    }

    /* ───────────── 기록 API: 검증 순서와 오류 ───────────── */

    @Test
    void recordChecksAccessThenRoleThenStatusThenActionThenNote() throws Exception {
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE);
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String vName = names.get(viewer);
        String aName = names.get(analyst);

        // 조회자, 허용 캡처: 403, IDOR 감사 없음. 상태(신규)·종류(틀림)보다 역할을 먼저 본다.
        record(viewer, JOB, 2, "block_ip", null).andExpect(status().isForbidden());
        record(viewer, JOB, 1, "shutdown", null).andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", vName)).isEmpty();
        // 허용 밖 캡처: 조회자도 분석가도 403 + IDOR 감사(역할보다 접근을 먼저 본다)
        record(viewer, HIDDEN_JOB, 1, "block_ip", null).andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", vName)).hasSize(1);
        record(analyst, HIDDEN_JOB, 1, "block_ip", null).andExpect(status().isForbidden());
        assertThat(audits("ACCESS_DENIED_IDOR", aName)).hasSize(1);
        // CSRF 없는 POST
        mockMvc.perform(post("/api/incidents/" + JOB + "/rank/2/response-actions").session(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"action\":\"block_ip\",\"note\":null}"))
                .andExpect(status().isForbidden());

        // 신규(open): 409 INCIDENT_NOT_STARTED. 종류가 틀려도 상태를 먼저 본다.
        JsonNode notStarted = json(record(analyst, JOB, 1, "block_ip", null).andExpect(status().isConflict()).andReturn());
        assertThat(notStarted.get("succeeded").asBoolean()).isFalse();
        assertThat(notStarted.get("code").asText()).isEqualTo("INCIDENT_NOT_STARTED");
        assertThat(json(record(analyst, JOB, 1, "shutdown", null).andExpect(status().isConflict()).andReturn())
                .get("code").asText()).isEqualTo("INCIDENT_NOT_STARTED");

        // 종류: 일곱 값 밖이거나 없으면 400. 메모 조건보다 먼저 본다.
        for (String bad : new String[]{"shutdown", "", "BLOCK", null}) {
            JsonNode r = json(record(analyst, JOB, 2, bad, "x".repeat(501)).andExpect(status().isBadRequest()).andReturn());
            assertThat(r.get("code").asText()).as("action %s", bad).isEqualTo("INVALID_REQUEST");
            assertThat(r.get("message").asText()).contains("대응 조치 종류");
        }
        // 메모: 500 코드 포인트 상한, 조치 없음·기타는 필수
        JsonNode tooLong = json(record(analyst, JOB, 2, "block_ip", " " + "😀".repeat(501) + " ")
                .andExpect(status().isBadRequest()).andReturn());
        assertThat(tooLong.get("code").asText()).isEqualTo("INVALID_REQUEST");
        assertThat(tooLong.get("message").asText()).isEqualTo("대응 조치 메모는 500자까지 입력할 수 있습니다.");
        for (String needsNote : List.of("none", "other")) {
            for (String blank : new String[]{null, "", "   "}) {
                JsonNode r = json(record(analyst, JOB, 2, needsNote, blank).andExpect(status().isBadRequest()).andReturn());
                assertThat(r.get("code").asText()).as("%s / '%s'", needsNote, blank).isEqualTo("INVALID_REQUEST");
                assertThat(r.get("message").asText()).contains("메모");
            }
        }
        // 거부된 요청은 행도 감사도 남기지 않는다
        assertThat(count()).isZero();
        assertThat(audits(ACTION_AUDIT, aName)).isEmpty();
        assertThat(audits(ACTION_AUDIT, vName)).isEmpty();
    }

    /* ───────────── 기록 성공: 행·감사·상세 응답 ───────────── */

    @Test
    void analystRecordsActionsWithAuditAndDetailList() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String aName = names.get(analyst);

        JsonNode first = json(record(analyst, JOB, 2, " Block_IP ", null).andExpect(status().isOk()).andReturn());
        assertThat(first.get("succeeded").asBoolean()).isTrue();
        assertThat(first.get("code").asText()).isEqualTo("OK");
        assertThat(first.get("message").asText()).contains("IP 차단");
        record(analyst, JOB, 2, "lock_account", "  j.kim 계정 잠금 요청, 10.0.0.5에서 로그인  ").andExpect(status().isOk());
        // 보조 평면 문자 500개(코드 포인트 500)는 받는다
        record(analyst, JOB, 2, "other", "😀".repeat(500)).andExpect(status().isOk());
        // 종결된 인시던트에도 덧붙일 수 있다(뒤늦은 조치)
        record(analyst, JOB, 3, "none", "정상 업무로 확인돼 조치하지 않음").andExpect(status().isOk());

        JsonNode detail = getJson(analyst, "/api/incidents/" + JOB + "/rank/2");
        assertThat(detail.get("canRecordResponse").asBoolean()).isTrue();
        JsonNode list = detail.get("responseActions");
        assertThat(list).hasSize(3);
        // 시간 역순(같은 시각이면 나중에 넣은 것이 먼저)
        assertThat(list.get(0).get("action").asText()).isEqualTo("other");
        assertThat(list.get(1).get("action").asText()).isEqualTo("lock_account");
        assertThat(list.get(1).get("note").asText()).isEqualTo("j.kim 계정 잠금 요청, 10.0.0.5에서 로그인");
        assertThat(list.get(2).get("action").asText()).isEqualTo("block_ip");
        assertThat(list.get(2).get("note").isNull()).isTrue();
        assertThat(list.get(2).get("actorDisplay").asText()).isEqualTo("표시 " + aName + " (" + aName + ")");
        assertThat(list.get(2).get("recordedAt").asText()).isNotBlank();
        // 다른 인시던트의 기록은 섞이지 않는다
        JsonNode closedDetail = getJson(analyst, "/api/incidents/" + JOB + "/rank/3");
        assertThat(closedDetail.get("responseActions")).hasSize(1);
        assertThat(closedDetail.get("canRecordResponse").asBoolean()).isTrue();
        // 신규는 목록이 비고 기록할 수 없다
        JsonNode openDetail = getJson(analyst, "/api/incidents/" + JOB + "/rank/1");
        assertThat(openDetail.get("responseActions")).isEmpty();
        assertThat(openDetail.get("canRecordResponse").asBoolean()).isFalse();

        // 행: incident_id·capture_id·job_id·기록자
        Map<String, Object> row = app().queryForMap("SELECT incident_id, capture_id, job_id, actor_username FROM incident_response_actions "
                + "WHERE action_type = 'block_ip'");
        assertThat(row.get("INCIDENT_ID")).isEqualTo(id(LIVE, 2));
        assertThat(row.get("CAPTURE_ID")).isEqualTo(LIVE);
        assertThat(((Number) row.get("JOB_ID")).longValue()).isEqualTo(JOB);
        assertThat(row.get("ACTOR_USERNAME")).isEqualTo(aName);

        // 감사: 대상 캡처·작업·인시던트, 상세 {action, note}
        List<AuditLog> logs = audits(ACTION_AUDIT, aName);
        assertThat(logs).hasSize(4);
        AuditLog lock = logs.stream().filter(l -> l.getDetailJson().contains("lock_account")).findFirst().orElseThrow();
        assertThat(lock.getTargetCaptureId()).isEqualTo(LIVE);
        assertThat(lock.getTargetJobId()).isEqualTo(JOB);
        assertThat(lock.getTargetIncidentId()).isEqualTo(id(LIVE, 2));
        JsonNode d = objectMapper.readTree(lock.getDetailJson());
        assertThat(d.get("action").asText()).isEqualTo("lock_account");
        assertThat(d.get("note").asText()).isEqualTo("j.kim 계정 잠금 요청, 10.0.0.5에서 로그인");
        AuditLog block = logs.stream().filter(l -> l.getDetailJson().contains("block_ip")).findFirst().orElseThrow();
        assertThat(objectMapper.readTree(block.getDetailJson()).get("note").isNull()).isTrue();
    }

    /* ───────────── 조회자: 종류·기록자·시각만 ───────────── */

    @Test
    void viewerGetsActionActorAndTimeButNoNote() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        MockHttpSession viewer = login(UserRole.VIEWER, LIVE);
        String aName = names.get(analyst);
        record(analyst, JOB, 2, "lock_account", "secret-memo j.kim 계정 잠금").andExpect(status().isOk());
        record(analyst, JOB, 2, "none", "secret-memo 조치하지 않은 사유").andExpect(status().isOk());

        MvcResult r = mockMvc.perform(get("/api/incidents/" + JOB + "/rank/2").session(viewer)).andExpect(status().isOk()).andReturn();
        String body = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(body).doesNotContain("secret-memo", "j.kim", "조치하지 않은 사유");
        JsonNode detail = objectMapper.readTree(body);
        assertThat(detail.get("canRecordResponse").asBoolean()).isFalse();
        JsonNode list = detail.get("responseActions");
        assertThat(list).hasSize(2);
        for (JsonNode item : list) {
            assertThat(item.path("note").isNull() || item.path("note").isMissingNode()).isTrue();
            assertThat(item.get("actorDisplay").asText()).contains(aName);
            assertThat(item.get("recordedAt").asText()).isNotBlank();
        }
        assertThat(list.get(0).get("action").asText()).isEqualTo("none");
        assertThat(list.get(1).get("action").asText()).isEqualTo("lock_account");
        // 분석가는 메모를 본다
        JsonNode forAnalyst = getJson(analyst, "/api/incidents/" + JOB + "/rank/2");
        assertThat(forAnalyst.get("responseActions").get(1).get("note").asText()).isEqualTo("secret-memo j.kim 계정 잠금");
    }

    /* ───────────── 정탐 종결 규칙 ───────────── */

    @Test
    void closingAsTruePositiveNeedsAtLeastOneResponseAction() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, LIVE);
        String aName = names.get(analyst);

        // 분석 중 + 정탐 + 기록 0건: 409 RESPONSE_ACTION_REQUIRED. zeek_AD 쪽 상태·이력은 그대로이고 전이 감사도 없다.
        JsonNode blocked = json(transition(analyst, JOB, 2, "closed", "true_positive", "정탐 확정")
                .andExpect(status().isConflict()).andReturn());
        assertThat(blocked.get("succeeded").asBoolean()).isFalse();
        assertThat(blocked.get("code").asText()).isEqualTo("RESPONSE_ACTION_REQUIRED");
        assertThat(blocked.get("message").asText()).isEqualTo(REQUIRED_MESSAGE);
        assertThat(statusOf(2)).isEqualTo("investigating|null");
        assertThat(historyCount(2)).isZero();
        assertThat(audits("INCIDENT_STATUS_TRANSITION", aName)).isEmpty();

        // 기존 검증(사유·판정)이 먼저다
        assertThat(json(transition(analyst, JOB, 2, "closed", "true_positive", "   ").andExpect(status().isBadRequest()).andReturn())
                .get("code").asText()).isEqualTo("INVALID_REQUEST");
        assertThat(json(transition(analyst, JOB, 2, "closed", "unknown", "사유").andExpect(status().isBadRequest()).andReturn())
                .get("code").asText()).isEqualTo("INVALID_REQUEST");

        // 다른 인시던트의 기록은 인정하지 않는다
        record(analyst, JOB, 4, "block_ip", null).andExpect(status().isOk());
        assertThat(json(transition(analyst, JOB, 2, "closed", "true_positive", "정탐 확정").andExpect(status().isConflict()).andReturn())
                .get("code").asText()).isEqualTo("RESPONSE_ACTION_REQUIRED");

        // "조치 없음"을 사유와 함께 기록하면 종결된다
        record(analyst, JOB, 2, "none", "실습 트래픽으로 확인돼 차단하지 않음").andExpect(status().isOk());
        JsonNode closed = json(transition(analyst, JOB, 2, "closed", "true_positive", "정탐 확정").andExpect(status().isOk()).andReturn());
        assertThat(closed.get("succeeded").asBoolean()).isTrue();
        assertThat(statusOf(2)).isEqualTo("closed|true_positive");
        assertThat(historyCount(2)).isEqualTo(1);
        assertThat(audits("INCIDENT_STATUS_TRANSITION", aName)).hasSize(1);

        // 오탐·정상 종결은 기록 없이 된다
        transition(analyst, JOB, 5, "closed", "false_positive", "오탐").andExpect(status().isOk());
        assertThat(statusOf(5)).isEqualTo("closed|false_positive");
        transition(analyst, JOB, 6, "closed", "benign", "정상").andExpect(status().isOk());
        assertThat(statusOf(6)).isEqualTo("closed|benign");

        // 분석 중이 아니면 이 규칙을 적용하지 않는다: 신규에서 바로 종결, 이미 종결은 지금처럼 전이 오류(CONFLICT)
        assertThat(json(transition(analyst, JOB, 1, "closed", "true_positive", "건너뛰기").andExpect(status().isConflict()).andReturn())
                .get("code").asText()).isEqualTo("CONFLICT");
        assertThat(json(transition(analyst, JOB, 3, "closed", "true_positive", "다시 종결").andExpect(status().isConflict()).andReturn())
                .get("code").asText()).isEqualTo("CONFLICT");
        // 착수(investigating) 전이는 그대로다
        transition(analyst, JOB, 1, "investigating", null, "착수").andExpect(status().isOk());
        assertThat(statusOf(1)).isEqualTo("investigating|null");
    }

    /* ───────────── 도우미 ───────────── */

    /** 조치 표는 고칠 수 없어 트리거를 잠시 빼고 지운다(시험 DB 정리 전용). */
    private void clearResponseActions() {
        JdbcTemplate a = app();
        a.execute("DROP TRIGGER IF EXISTS trg_incident_response_actions_immutable");
        a.update("DELETE FROM incident_response_actions");
        a.execute("CREATE TRIGGER trg_incident_response_actions_immutable BEFORE UPDATE, DELETE ON incident_response_actions "
                + "FOR EACH ROW CALL \"com.zeekad.dashboard.audit.H2ResponseActionImmutableTrigger\"");
    }

    private ResultActions record(MockHttpSession s, long jobId, int rank, String action, String note) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("action", action);
        body.put("note", note);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/response-actions", body);
    }

    private ResultActions transition(MockHttpSession s, long jobId, int rank, String to, String resolution, String reason)
            throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("toStatus", to);
        body.put("resolution", resolution);
        body.put("reason", reason);
        return postJson(s, "/api/incidents/" + jobId + "/rank/" + rank + "/transition", body);
    }

    private ResultActions postJson(MockHttpSession s, String url, Map<String, String> body) throws Exception {
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
        var req = post(url).session(s).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (csrf != null) {
            req = req.cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        }
        return mockMvc.perform(req);
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t56_u" + (++userSeq) + "_" + System.nanoTime() % 100000;
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
        return s;
    }

    private List<AuditLog> audits(String actionType, String actor) {
        return auditLogMapper.findFiltered(actionType, actor, 50);
    }

    private int count() {
        Integer n = app().queryForObject("SELECT COUNT(*) FROM incident_response_actions", Integer.class);
        return n == null ? 0 : n;
    }

    private String statusOf(int rank) {
        return jdbc().queryForObject("SELECT zeekad_status || '|' || COALESCE(zeekad_resolution, 'null') FROM dashboard.raw_incident_status "
                + "WHERE incident_id = ?", String.class, id(LIVE, rank));
    }

    private int historyCount(int rank) {
        Integer n = jdbc().queryForObject("SELECT COUNT(*) FROM dashboard.raw_incident_status_history WHERE incident_id = ?",
                Integer.class, id(LIVE, rank));
        return n == null ? 0 : n;
    }

    static String id(String capture, int rank) {
        return capture + "|10.56.0." + rank + "|originator|t56";
    }

    private void incident(long jobId, String capture, int rank) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-25T00:50:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-25T00:55:00Z', 'hbos', NULL, 10, NULL)",
                jobId, capture, rank, id(capture, rank), "10.56.0." + rank);
    }

    private void setStatus(long jobId, String capture, int rank, String status, String resolution) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-25T01:10:00Z', 't56')", jobId, id(capture, rank), status, resolution);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private JsonNode json(MvcResult r) throws Exception {
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
