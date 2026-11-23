package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.IncidentRefMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.IncidentRefService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T40 알림 묶음 건너가기: 상세 slackThreadGroups의 headIsSelf·headIncidentNo·memberCount(허용 캡처마다),
 * 머리를 볼 수 없는 묶음의 restricted-N 표지(응답 본문 전체에 머리 식별자 없음), 원문 열쇠로 묶기,
 * 번호 동기화 없음, 큐 thread 조건(목록·띠·새 건수·이전·다음·자산·담당·착수 지연), 403·IDOR 감사·400, 조회자 마스킹.
 *
 * 시험 자료(job 98010~98019, 캡처 lab-t40a 허용, lab-t40h 숨김):
 *  - lab-t40a 옛 작업 98010: G(옛 작업에만 있음 = 최신 큐에 없음, 번호 행 없음)
 *  - lab-t40a 최신 작업 98011: A1(머리) A2 A3(A1의 답글, A3은 부모 앞뒤 공백), A4(숨김 머리 H2의 답글), A6(G의 답글),
 *    A7·A8(가린 꼴이 같은 서로 다른 머리), A9(A7·A8 양쪽 답글)
 *  - lab-t40h 98012: H1(A1의 답글, 허용 밖 구성원), H2(머리)
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t40_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t40_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t40_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T40SlackThreadIntegrationTest {

    static final String CAP_A = "lab-t40a";
    static final String HIDDEN = "lab-t40h";
    static final Pattern IPV4 = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private IncidentRefService refService;
    @MockitoSpyBean private IncidentRefMapper refMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;
    private String tag;

    @BeforeEach
    void setUp() throws Exception {
        tag = "t40s" + (++seq);
        job(98010, CAP_A, "2026-11-20T08:00:00Z");
        incident(98010, CAP_A, 1, "10.40.9.1");
        job(98011, CAP_A, "2026-11-20T10:00:00Z");
        String[] aIps = {"10.40.1.1", "10.40.1.2", "10.40.1.3", "10.40.2.4", "10.40.3.6", "10.40.7.1", "10.40.7.2", "10.40.7.9"};
        for (int i = 0; i < aIps.length; i++) {
            incident(98011, CAP_A, i + 1, aIps[i]);
        }
        job(98012, HIDDEN, "2026-11-20T10:00:00Z");
        incident(98012, HIDDEN, 1, "10.40.1.5");
        incident(98012, HIDDEN, 2, "10.40.2.1");

        String a1 = id(CAP_A, "10.40.1.1");
        String h2 = id(HIDDEN, "10.40.2.1");
        String g = id(CAP_A, "10.40.9.1");
        String a7 = id(CAP_A, "10.40.7.1");
        String a8 = id(CAP_A, "10.40.7.2");
        slack(98011, a1, null, 0);
        slack(98011, a1, a1, 1);
        slack(98011, id(CAP_A, "10.40.1.2"), a1, 2);
        slack(98011, id(CAP_A, "10.40.1.3"), "  " + a1 + " ", 3);
        slack(98012, id(HIDDEN, "10.40.1.5"), a1, 4);
        slack(98012, h2, null, 5);
        slack(98011, id(CAP_A, "10.40.2.4"), h2, 6);
        slack(98011, id(CAP_A, "10.40.3.6"), g, 7);
        slack(98011, a7, null, 8);
        slack(98011, a8, null, 9);
        slack(98011, id(CAP_A, "10.40.7.9"), a7, 10);
        slack(98011, id(CAP_A, "10.40.7.9"), a8, 11);
        refService.syncAll();
        Mockito.clearInvocations(refMapper);
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 98010 AND 98019";
        z.update("DELETE FROM dashboard.raw_slack_deliveries WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        Mockito.reset(refMapper);
    }

    /* ───────────── 상세 ───────────── */

    @Test
    void detailCarriesHeadNumberAndMemberCountPerAllowedCaptures() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        MockHttpSession all = login(UserRole.ANALYST, "lab-t40*");
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        long a1No = no(id(CAP_A, "10.40.1.1"));

        // 붙은 인시던트(A2): 머리 번호와 허용 캡처 안 구성원 수(숨김 H1 제외)
        JsonNode g = singleGroup(getJson(a, "/api/incidents/98011/rank/2"));
        assertThat(g.get("headIsSelf").asBoolean()).isFalse();
        assertThat(g.get("headIncidentNo").asLong()).isEqualTo(a1No);
        assertThat(g.get("memberCount").asLong()).isEqualTo(3);
        assertThat(singleGroup(getJson(all, "/api/incidents/98011/rank/2")).get("memberCount").asLong()).isEqualTo(4);
        JsonNode vg = singleGroup(getJson(v, "/api/incidents/98011/rank/2"));
        assertThat(vg.get("headIncidentNo").asLong()).isEqualTo(a1No);
        assertThat(vg.get("memberCount").asLong()).isEqualTo(3);

        // 머리 인시던트(A1): 자기 자신, 번호도 같이
        JsonNode self = singleGroup(getJson(a, "/api/incidents/98011/rank/1"));
        assertThat(self.get("headIsSelf").asBoolean()).isTrue();
        assertThat(self.get("headIncidentNo").asLong()).isEqualTo(a1No);
        assertThat(self.get("memberCount").asLong()).isEqualTo(3);
        assertThat(self.get("deliveries")).hasSize(2);

        // 부모 앞뒤 공백(A3)도 같은 묶음
        JsonNode a3 = singleGroup(getJson(a, "/api/incidents/98011/rank/3"));
        assertThat(a3.get("headIncidentNo").asLong()).isEqualTo(a1No);

        // memberCount = 같은 사용자의 큐 thread total
        for (MockHttpSession s : List.of(a, all, v)) {
            long member = singleGroup(getJson(s, "/api/incidents/98011/rank/2")).get("memberCount").asLong();
            long total = getJson(s, "/api/incidents/queue?period=all&thread=" + a1No).get("total").asLong();
            assertThat(total).isEqualTo(member);
        }
    }

    @Test
    void restrictedHeadIsNotExposedAnywhereInTheResponse() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        String h2 = id(HIDDEN, "10.40.2.1");
        long h2No = no(h2);
        for (MockHttpSession s : List.of(a, v)) {
            String body = getBody(s, "/api/incidents/98011/rank/4");
            JsonNode d = objectMapper.readTree(body);
            JsonNode g = singleGroup(d);
            assertThat(g.get("headIsSelf").asBoolean()).isFalse();
            assertThat(g.get("headIncidentNo").isNull()).isTrue();
            assertThat(g.get("memberCount").asLong()).isZero();
            assertThat(g.get("threadKey").asText()).isEqualTo("restricted-1");
            assertThat(g.at("/deliveries/0/threadParent").asText()).isEqualTo("restricted-1");
            assertThat(g.at("/deliveries/0/threadRoleLabel").asText()).isEqualTo("타 인시던트 후속 알림");
            assertThat(d.at("/detail/slackDeliveries/0/threadParent").asText()).isEqualTo("restricted-1");
            assertThat(d.at("/detail/slackDeliveries/0/threadKey").asText()).isEqualTo("restricted-1");
            JsonNode payload = objectMapper.readTree(g.at("/deliveries/0/payloadJson").asText());
            assertThat(payload.get("zeekad_thread_parent").asText()).isEqualTo("restricted-1");
            // 응답 본문 전체: 숨김 캡처 ID·머리 incident_id(가린 꼴 포함)·머리 번호 값이 없다
            assertThat(body).doesNotContain(HIDDEN).doesNotContain("10.40.2.1").doesNotContain(h2);
            assertThat(Pattern.compile("[:\\[,]\\s*" + h2No + "\\s*[,\\]}]").matcher(body).find()).as("head no").isFalse();
        }
    }

    @Test
    void headWithoutRefRowIsRestrictedAndDetailNeverSyncsNumbers() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        String g = id(CAP_A, "10.40.9.1");
        assertThat(countRefs(g)).isZero();
        Mockito.clearInvocations(refMapper);
        String body = getBody(a, "/api/incidents/98011/rank/5");
        JsonNode grp = singleGroup(objectMapper.readTree(body));
        assertThat(grp.get("headIncidentNo").isNull()).isTrue();
        assertThat(grp.get("memberCount").asLong()).isZero();
        assertThat(grp.get("threadKey").asText()).isEqualTo("restricted-1");
        assertThat(body).doesNotContain(g).doesNotContain("10.40.9.1");
        // 번호 동기화(쓰기)를 일으키지 않았다: 머리의 번호 행이 여전히 없고 넣기 호출도 없다
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());
        assertThat(countRefs(g)).isZero();
    }

    @Test
    void groupsSplitByRawKeySoViewerAndAnalystSeeSameGroups() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        JsonNode ag = getJson(a, "/api/incidents/98011/rank/8").at("/detail/slackThreadGroups");
        String vBody = getBody(v, "/api/incidents/98011/rank/8");
        JsonNode vg = objectMapper.readTree(vBody).at("/detail/slackThreadGroups");
        assertThat(ag).hasSize(2);
        assertThat(vg).hasSize(2);
        for (int i = 0; i < 2; i++) {
            assertThat(vg.get(i).get("deliveries").size()).isEqualTo(ag.get(i).get("deliveries").size());
        }
        // 조회자에게는 가린 꼴이 같다(묶음은 그래도 둘)
        assertThat(vg.get(0).get("threadKey").asText()).isEqualTo(vg.get(1).get("threadKey").asText());
        assertThat(vg.get(0).get("headIncidentNo").asLong()).isEqualTo(no(id(CAP_A, "10.40.7.1")));
        assertThat(vg.get(1).get("headIncidentNo").asLong()).isEqualTo(no(id(CAP_A, "10.40.7.2")));
        assertThat(vg.get(0).get("memberCount").asLong()).isEqualTo(2);
        assertThat(IPV4.matcher(vBody).find()).as("viewer detail unmasked ip").isFalse();
    }

    /* ───────────── 큐 thread ───────────── */

    @Test
    void queueThreadFiltersAllPathsWithinAllowedCaptures() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        long a1No = no(id(CAP_A, "10.40.1.1"));
        String base = "/api/incidents/queue?period=all&size=100&thread=" + a1No;
        String body = getBody(a, base);
        JsonNode q = objectMapper.readTree(body);
        assertThat(q.get("total").asLong()).isEqualTo(3);
        Set<String> hosts = new HashSet<>();
        for (JsonNode it : q.get("items")) {
            hosts.add(it.get("hostIp").asText());
        }
        assertThat(hosts).containsExactlyInAnyOrder("10.40.1.1", "10.40.1.2", "10.40.1.3");
        assertThat(body).doesNotContain(HIDDEN);
        // 띠 합계
        assertThat(q.at("/summary/total").asLong()).isEqualTo(3);
        // 새 건수(기간 없이 since 이후)
        JsonNode nc = getJson(a, "/api/incidents/queue/new-count?since=2026-01-01T00:00:00Z&thread=" + a1No);
        assertThat(nc.get("count").asLong()).isEqualTo(3);
        // 이전·다음: 묶음 안에서만
        JsonNode first = q.get("items").get(0);
        JsonNode nb = getJson(a, "/api/incidents/queue/neighbors?jobId=" + first.get("jobId").asLong()
                + "&queueRank=" + first.get("queueRank").asInt() + "&period=all&thread=" + a1No);
        assertThat(nb.get("total").asLong()).isEqualTo(3);
        assertThat(nb.get("position").asInt()).isEqualTo(1);
        assertThat(nb.at("/next/queueRank").asInt()).isEqualTo(q.get("items").get(1).get("queueRank").asInt());
        // 묶음 밖 인시던트의 이전·다음: 위치 없음
        JsonNode out = getJson(a, "/api/incidents/queue/neighbors?jobId=98011&queueRank=6&period=all&thread=" + a1No);
        assertThat(out.get("position").isNull()).isTrue();
        assertThat(out.get("total").asLong()).isEqualTo(3);

        // 다른 조건과 함께: 자산 검색
        JsonNode withAsset = getJson(a, base + "&asset=10.40.1.2");
        assertThat(withAsset.get("total").asLong()).isEqualTo(1);
        JsonNode assetNc = getJson(a, "/api/incidents/queue/new-count?since=2026-01-01T00:00:00Z&asset=10.40.1&thread=" + a1No);
        assertThat(assetNc.get("count").asLong()).isEqualTo(3);
        // 착수 지연 띠: 묶음 안의 지연 행 수와 같다
        long overdueRows = 0;
        for (JsonNode it : q.get("items")) {
            if (it.get("ackOverdue").asBoolean()) overdueRows++;
        }
        assertThat(getJson(a, base + "&overdue=true").get("total").asLong()).isEqualTo(overdueRows);
        assertThat(q.at("/summary/overdue").asLong()).isEqualTo(overdueRows);
        // 담당 조건: 묶음 안 하나를 맡으면 me = 1, none = 2
        assign(a, 98011, 2, names.get(a)).andExpect(status().isOk());
        assertThat(getJson(a, base + "&assignee=me").get("total").asLong()).isEqualTo(1);
        assertThat(getJson(a, base + "&assignee=none").get("total").asLong()).isEqualTo(2);

        // 허용 밖까지 보는 사용자: 숨김 구성원 포함 4건
        MockHttpSession all = login(UserRole.ANALYST, "lab-t40*");
        assertThat(getJson(all, base).get("total").asLong()).isEqualTo(4);
        // 머리가 아닌 번호: 그 인시던트 하나
        assertThat(getJson(a, "/api/incidents/queue?period=all&thread=" + no(id(CAP_A, "10.40.1.2"))).get("total").asLong())
                .isEqualTo(1);
        // 조회자 큐: 가리지 않은 IPv4 없음
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        String vBody = getBody(v, base);
        assertThat(objectMapper.readTree(vBody).get("total").asLong()).isEqualTo(3);
        assertThat(IPV4.matcher(vBody).find()).isFalse();
    }

    @Test
    void queueThreadRejectsWithSame403AndDistinctAuditReasons() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, CAP_A);
        String user = names.get(a);
        long hiddenNo = no(id(HIDDEN, "10.40.2.1"));
        long maxNo = app().queryForObject("SELECT MAX(incident_no) FROM incident_refs", Long.class);
        String b1 = mockMvc.perform(get("/api/incidents/queue?period=all&thread=" + hiddenNo).session(a))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String b2 = mockMvc.perform(get("/api/incidents/queue?period=all&thread=" + (maxNo + 1000)).session(a))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(b1).isEqualTo(b2);
        mockMvc.perform(get("/api/incidents/queue/new-count?since=2026-01-01T00:00:00Z&thread=" + hiddenNo).session(a))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/queue/neighbors?jobId=98011&queueRank=1&thread=" + hiddenNo).session(a))
                .andExpect(status().isForbidden());

        List<AuditLog> logs = auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10);
        assertThat(logs).hasSize(4);
        List<String> reasons = new ArrayList<>();
        for (AuditLog l : logs) {
            JsonNode detail = objectMapper.readTree(l.getDetailJson());
            reasons.add(detail.get("reason").asText());
            assertThat(detail.has("requestedIncidentNo")).isTrue();
        }
        assertThat(new HashSet<>(reasons)).containsExactlyInAnyOrder("thread_no_capture_denied", "thread_no_not_found");

        // 형식 오류는 400, 감사 없음
        for (String bad : List.of("abc", "0", "-1", "1.5", "99999999999999999999")) {
            mockMvc.perform(get("/api/incidents/queue?period=all&thread=" + bad).session(a))
                    .andExpect(status().isBadRequest());
        }
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(4);

        // 허용 캡처 안이지만 최신 큐에 없는 번호: 빈 결과
        String ghost = CAP_A + "|10.40.8.8|originator|" + tag;
        app().update("INSERT INTO incident_refs (incident_id, capture_id, detected_at, created_at) VALUES (?, ?, NULL, CURRENT_TIMESTAMP)",
                ghost, CAP_A);
        JsonNode empty = getJson(a, "/api/incidents/queue?period=all&thread=" + no(ghost));
        assertThat(empty.get("total").asLong()).isZero();
    }

    /* ───────────── 도우미 ───────────── */

    private static JsonNode singleGroup(JsonNode detailResponse) {
        JsonNode groups = detailResponse.at("/detail/slackThreadGroups");
        assertThat(groups).hasSize(1);
        return groups.get(0);
    }

    private long no(String incidentId) {
        Long n = app().queryForObject("SELECT incident_no FROM incident_refs WHERE incident_id = ?", Long.class, incidentId);
        assertThat(n).as(incidentId).isNotNull();
        return n;
    }

    private int countRefs(String incidentId) {
        return app().queryForObject("SELECT COUNT(*) FROM incident_refs WHERE incident_id = ?", Integer.class, incidentId);
    }

    private String id(String capture, String ip) {
        return capture + "|" + ip + "|originator|" + tag;
    }

    private void job(long jobId, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20T00:00:00Z', "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                jobId, capture, finished);
    }

    private void incident(long jobId, String capture, int rank, String ip) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-19T20:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-19T20:05:00Z', 'hbos', NULL, ?, NULL)",
                jobId, capture, rank, id(capture, ip), ip, 100 - rank);
    }

    /** 페이로드 맨 위에도 zeekad_thread_parent를 둔다(T39 new-shapes.md 모양) */
    private void slack(long jobId, String incidentId, String parent, int minute) throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("text", "t40 알림 " + minute);
        if (parent != null) {
            payload.put("zeekad_thread_parent", parent.trim());
        }
        jdbc().update("INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version, "
                        + "zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at, "
                        + "zeekad_thread_parent, zeekad_reply_broadcast) VALUES (?, ?, 'incident', 'incident.v2', 'dry_run', 'recorded', "
                        + "? FORMAT JSON, NULL, NULL, NULL, DATEADD('MINUTE', ?, TIMESTAMP WITH TIME ZONE '2026-11-20 10:00:00Z'), ?, FALSE)",
                jobId, incidentId, objectMapper.writeValueAsString(payload), minute, parent);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private final Map<MockHttpSession, String> names = new HashMap<>();

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t40_u" + (++seq) + "_" + System.nanoTime() % 100000;
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

    private org.springframework.test.web.servlet.ResultActions assign(MockHttpSession s, long jobId, int rank,
                                                                      String assignee) throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("assignee", assignee);
        body.put("expected", null);
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
        var req = post("/api/incidents/" + jobId + "/rank/" + rank + "/assignment").session(s)
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body));
        if (csrf != null) {
            req = req.cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue());
        }
        return mockMvc.perform(req);
    }

    private String getBody(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        return objectMapper.readTree(getBody(session, url));
    }
}
