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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T27 인시던트 번호: V3(H2)·추가만, 첫 동기화 순서(빈 DB), 새 작업에도 번호 그대로, 새 인시던트는 다음 번호,
 * 옛 작업에만 있는 인시던트는 행만, 동시 동기화 중복 없음, 한쪽 캡처만 허용된 사용자가 먼저 읽어도 탐지 순서,
 * 실패 뒤 30초 제한·실패해도 큐 성공, 번호 API(위치·403 감사 사유·400·VIEWER), 응답의 incidentNo, SPA 경로.
 * 이 시험은 자기만의 앱 DB·zeekad DB(H2 메모리, 이름이 다름)를 써서 빈 앱 DB의 시작 동기화를 본다.
 * 시험용 zeekad 행은 job 97000~97099(캡처 lab-t27*)이고 시험마다 지운다. incident_refs는 추가만이라 지우지 않는다.
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t27_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t27_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t27_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T27IncidentNoIntegrationTest {

    static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    static final String CAP_A = "lab-t27a";
    static final String CAP_B = "lab-t27b";
    static final String HIDDEN = "lab-t27h";
    static final Pattern IPV4 = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

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
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private IncidentRefService refService;
    @Autowired private MutableTestClock clock;
    @MockitoSpyBean private IncidentRefMapper refMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;
    private String tag;

    @BeforeEach
    void setUp() {
        // 앞 시험의 실패 뒤 30초 제한을 넘긴다
        clock.set(clock.instant().plusSeconds(120));
        tag = "t27s" + (++seq);
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 97000 AND 97099";
        z.update("DELETE FROM dashboard.raw_analyst_review_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        Mockito.reset(refMapper);
    }

    /* ───────────── V3·첫 동기화 ───────────── */

    @Test
    void v3CreatesAppendOnlyIncidentRefs() {
        JdbcTemplate a = app();
        assertThat(a.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version = '3' AND success = TRUE",
                Integer.class)).isEqualTo(1);
        assertThat(a.queryForObject("SELECT COUNT(*) FROM incident_refs", Integer.class)).isPositive();
        assertThatThrownBy(() -> a.update("UPDATE incident_refs SET capture_id = 'x'"))
                .rootCause().hasMessageContaining("append-only");
        assertThatThrownBy(() -> a.update("DELETE FROM incident_refs"))
                .rootCause().hasMessageContaining("append-only");
    }

    @Test
    void startupSyncOnEmptyDbNumbersLatestQueueInDetectionOrder() {
        // 독립 SQL: 최신 큐(시험이 넣은 lab-t27* 제외)를 탐지 시각(NULL 마지막)·캡처·incident_id 순으로
        List<String> expected = jdbc().queryForList(
                "SELECT lq.incident_id FROM dashboard.latest_incident_queue lq "
                        + "LEFT JOIN (SELECT q.capture_id, q.incident_id, MIN(j.finished_at) AS d FROM dashboard.incident_queue q "
                        + "JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL "
                        + "GROUP BY q.capture_id, q.incident_id) fs ON fs.capture_id = lq.capture_id AND fs.incident_id = lq.incident_id "
                        + "WHERE lq.capture_id NOT LIKE 'lab-t27%' "
                        + "ORDER BY fs.d ASC NULLS LAST, lq.capture_id ASC, lq.incident_id ASC", String.class);
        assertThat(expected).hasSizeGreaterThan(5);
        List<Map<String, Object>> refs = app().queryForList("SELECT incident_no, incident_id FROM incident_refs ORDER BY incident_no");
        List<String> numbered = new ArrayList<>();
        long maxSample = 0;
        long minOther = Long.MAX_VALUE;
        Set<String> sample = new HashSet<>(expected);
        for (Map<String, Object> r : refs) {
            String id = (String) r.get("incident_id");
            long no = ((Number) r.get("incident_no")).longValue();
            if (sample.contains(id)) {
                numbered.add(id);
                maxSample = Math.max(maxSample, no);
            } else {
                minOther = Math.min(minOther, no);
            }
        }
        // 첫 묶음(시작 동기화)이 최신 큐 전부를 1절 순서로 매겼고, 다른 시험이 더한 번호는 모두 그 뒤다
        assertThat(numbered).containsExactlyElementsOf(expected);
        assertThat(maxSample).isLessThan(minOther);
        assertThat(refService.syncAll().succeeded()).isTrue();
    }

    @Test
    void batchOrderPutsNullDetectionLastThenCaptureThenIncidentId() {
        job(97000, CAP_B, "2026-11-20T10:00:00Z");
        job(97001, CAP_A, "2026-11-20T10:00:00Z");
        job(97002, "lab-t27n", null);   // 성공했지만 완료 시각이 없음 → 탐지 시각 NULL → 마지막
        incident(97000, CAP_B, 1, "10.77.0.2");
        incident(97001, CAP_A, 1, "10.77.0.9");
        incident(97001, CAP_A, 2, "10.77.0.1");
        incident(97002, "lab-t27n", 1, "10.77.0.5");
        refService.syncAll();
        long a1 = no(id(CAP_A, "10.77.0.1"));
        long a9 = no(id(CAP_A, "10.77.0.9"));
        long b2 = no(id(CAP_B, "10.77.0.2"));
        long n5 = no(id("lab-t27n", "10.77.0.5"));
        assertThat(a1).isLessThan(a9);   // 같은 탐지 시각·캡처 → incident_id
        assertThat(a9).isLessThan(b2);   // 같은 탐지 시각 → capture_id
        assertThat(b2).isLessThan(n5);   // NULL 마지막
    }

    /* ───────────── 바뀌지 않음·다음 번호·행만 ───────────── */

    @Test
    void numberStaysWhenNewJobReranksAndNewIncidentGetsNextNumber() throws Exception {
        job(97010, CAP_A, "2026-11-20T10:00:00Z");
        incident(97010, CAP_A, 1, "10.77.1.1");
        incident(97010, CAP_A, 2, "10.77.1.2");
        refService.syncAll();
        long x = no(id(CAP_A, "10.77.1.1"));
        long y = no(id(CAP_A, "10.77.1.2"));

        // 새 작업: 순위가 바뀌고 새 인시던트 하나
        job(97011, CAP_A, "2026-11-20T11:00:00Z");
        incident(97011, CAP_A, 1, "10.77.1.2");
        incident(97011, CAP_A, 2, "10.77.1.1");
        incident(97011, CAP_A, 3, "10.77.1.3");
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100");
        Map<String, Long> byRank = new HashMap<>();
        for (JsonNode it : q.get("items")) {
            byRank.put(it.get("hostIp").asText(), it.get("incidentNo").asLong());
        }
        assertThat(byRank.get("10.77.1.1")).isEqualTo(x);
        assertThat(byRank.get("10.77.1.2")).isEqualTo(y);
        assertThat(byRank.get("10.77.1.3")).isGreaterThan(Math.max(x, y));
        // 위치는 새 작업
        JsonNode loc = getJson(s, "/api/incidents/no/" + x);
        assertThat(loc.get("jobId").asLong()).isEqualTo(97011);
        assertThat(loc.get("queueRank").asInt()).isEqualTo(2);
        assertThat(loc.get("latest").asBoolean()).isTrue();
        assertThat(count(id(CAP_A, "10.77.1.1"))).isEqualTo(1);
    }

    @Test
    void oldJobOnlyIncidentGetsRowOnlyNumberAndLocatesWithLatestFalse() throws Exception {
        // 동기화 전에 작업이 두 번 돌아, W는 옛 작업에만 있다
        job(97020, CAP_A, "2026-11-20T10:00:00Z");
        incident(97020, CAP_A, 1, "10.77.2.1");
        incident(97020, CAP_A, 2, "10.77.2.9");     // W
        job(97021, CAP_A, "2026-11-20T11:00:00Z");
        incident(97021, CAP_A, 1, "10.77.2.1");
        String w = id(CAP_A, "10.77.2.9");
        refService.syncAll();
        assertThat(count(w)).isZero();               // 최신 큐에 없으니 전체 동기화는 매기지 않는다

        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        JsonNode d = getJson(s, "/api/incidents/97020/rank/2");   // 옛 주소의 상세
        long wNo = d.get("incidentNo").asLong();
        assertThat(wNo).isPositive();
        assertThat(count(w)).isEqualTo(1);
        JsonNode loc = getJson(s, "/api/incidents/no/" + wNo);
        assertThat(loc.get("jobId").asLong()).isEqualTo(97020);
        assertThat(loc.get("queueRank").asInt()).isEqualTo(2);
        assertThat(loc.get("latest").asBoolean()).isFalse();
    }

    @Test
    void concurrentSyncsDoNotDuplicate() throws Exception {
        job(97030, CAP_A, "2026-11-20T10:00:00Z");
        for (int i = 1; i <= 20; i++) {
            incident(97030, CAP_A, i, "10.77.3." + i);
        }
        List<String> ids = new ArrayList<>();
        for (int i = 1; i <= 20; i++) {
            ids.add(id(CAP_A, "10.77.3." + i));
        }
        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            boolean full = t % 2 == 0;
            fs.add(pool.submit((Callable<Object>) () -> {
                start.await();
                return full ? refService.syncAll() : refService.numbersFor(ids);
            }));
        }
        start.countDown();
        for (Future<?> f : fs) {
            f.get();
        }
        pool.shutdown();
        for (String id : ids) {
            assertThat(count(id)).as(id).isEqualTo(1);
        }
        assertThat(new HashSet<>(refService.numbersFor(ids).values())).hasSize(20);
    }

    @Test
    void scopedReaderTriggersFullSyncSoNumbersFollowDetectionOrder() throws Exception {
        refService.syncAll();
        // 동기화 직후 두 캡처에 새 인시던트. B가 먼저 탐지됐다
        job(97040, CAP_B, "2026-11-20T09:00:00Z");
        incident(97040, CAP_B, 1, "10.77.4.2");
        job(97041, CAP_A, "2026-11-20T10:00:00Z");
        incident(97041, CAP_A, 1, "10.77.4.1");
        // A만 허용된 사용자가 먼저 읽는다
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100&captureId=" + CAP_A);
        assertThat(q.get("items").get(0).get("incidentNo").isNumber()).isTrue();
        assertThat(no(id(CAP_B, "10.77.4.2"))).isLessThan(no(id(CAP_A, "10.77.4.1")));
    }

    /* ───────────── 실패 ───────────── */

    @Test
    void failedSyncBacksOff30SecondsAndQueueStillSucceedsWithNullNumber() throws Exception {
        job(97050, CAP_A, "2026-11-20T10:00:00Z");
        incident(97050, CAP_A, 1, "10.77.5.1");
        Mockito.doThrow(new org.springframework.dao.DataAccessResourceFailureException("down"))
                .when(refMapper).insertIfAbsent(anyString(), anyString(), any(), any());
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100");
        assertThat(q.get("items").get(0).get("incidentNo").isNull()).isTrue();
        Mockito.verify(refMapper, Mockito.atLeastOnce()).insertIfAbsent(anyString(), anyString(), any(), any());

        // 30초 안: 다시 매기지 않는다(상세·이웃·번호 없는 행도 null), 읽기는 성공
        Mockito.clearInvocations(refMapper);
        clock.set(clock.instant().plusSeconds(29));
        JsonNode q2 = getJson(s, "/api/incidents/queue?period=all&size=100");
        assertThat(q2.get("items").get(0).get("incidentNo").isNull()).isTrue();
        JsonNode d = getJson(s, "/api/incidents/97050/rank/1");
        assertThat(d.get("incidentNo").isNull()).isTrue();
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());

        // 30초가 지나면 다시 매긴다
        Mockito.reset(refMapper);
        clock.set(clock.instant().plusSeconds(2));
        JsonNode q3 = getJson(s, "/api/incidents/queue?period=all&size=100");
        assertThat(q3.get("items").get(0).get("incidentNo").isNumber()).isTrue();
    }

    @Test
    void batchIsOneTransactionSoAFailureMidwayInsertsNothing() {
        job(97090, CAP_A, "2026-11-20T10:00:00Z");
        for (int i = 1; i <= 4; i++) {
            incident(97090, CAP_A, i, "10.77.9." + i);
        }
        // 실제 삽입은 같은 트랜잭션의 JdbcTemplate로 하고(스파이 프록시는 실제 메서드를 부를 수 없다), 셋째 행에서 실패시킨다
        int[] calls = {0};
        Mockito.doAnswer(inv -> {
            if (++calls[0] == 3) {
                throw new org.springframework.dao.DataAccessResourceFailureException("mid-batch");
            }
            return app().update("INSERT INTO incident_refs (incident_id, capture_id, detected_at, created_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    (String) inv.getArgument(0), (String) inv.getArgument(1), inv.getArgument(2), inv.getArgument(3));
        }).when(refMapper).insertIfAbsent(anyString(), anyString(), any(), any());
        assertThat(refService.syncAll().succeeded()).isFalse();
        for (int i = 1; i <= 4; i++) {
            assertThat(count(id(CAP_A, "10.77.9." + i))).as("rank " + i).isZero();
        }
        // 다음 동기화(제한과 상관없는 syncAll)는 네 행 모두 순서대로 넣는다
        Mockito.reset(refMapper);
        assertThat(refService.syncAll().succeeded()).isTrue();
        assertThat(no(id(CAP_A, "10.77.9.1"))).isLessThan(no(id(CAP_A, "10.77.9.4")));
    }

    @Test
    void readsDoNotWaitLongerThanReadWaitForASlowSync() throws Exception {
        job(97095, CAP_A, "2026-11-20T10:00:00Z");
        for (int i = 1; i <= 20; i++) {
            incident(97095, CAP_A, i, "10.77.95." + i);
        }
        // 느린 동기화: 한 행에 0.5초(20행 = 10초)
        Mockito.doAnswer(inv -> {
            Thread.sleep(500);
            return 0;
        }).when(refMapper).insertIfAbsent(anyString(), anyString(), any(), any());
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<?> sync = pool.submit(() -> refService.syncAll());
        Thread.sleep(300);
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        long t0 = System.nanoTime();
        JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100&captureId=" + CAP_A);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertThat(ms).isLessThan(IncidentRefService.READ_WAIT.toMillis() + 3000);
        assertThat(q.get("items").get(0).get("incidentNo").isNull()).isTrue();
        sync.get();
        pool.shutdown();
    }

    /* ───────────── 번호 API ───────────── */

    @Test
    void locateApiRejectsWithSame403AndDistinctAuditReasons() throws Exception {
        job(97060, CAP_A, "2026-11-20T10:00:00Z");
        incident(97060, CAP_A, 1, "10.77.6.1");
        job(97061, HIDDEN, "2026-11-20T10:00:00Z");
        incident(97061, HIDDEN, 1, "10.77.6.2");
        refService.syncAll();
        long hiddenNo = no(id(HIDDEN, "10.77.6.2"));
        long maxNo = app().queryForObject("SELECT MAX(incident_no) FROM incident_refs", Long.class);
        // zeekad에 없는 인시던트(번호만 있음): 허용 캡처로 직접 넣는다
        app().update("INSERT INTO incident_refs (incident_id, capture_id, detected_at, created_at) VALUES (?, ?, NULL, CURRENT_TIMESTAMP)",
                CAP_A + "|10.77.6.99|originator|" + tag, CAP_A);
        long ghostNo = no(CAP_A + "|10.77.6.99|originator|" + tag);

        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        String user = names.get(s);
        String b1 = mockMvc.perform(get("/api/incidents/no/" + hiddenNo).session(s))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String b2 = mockMvc.perform(get("/api/incidents/no/" + (maxNo + 1000)).session(s))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String b3 = mockMvc.perform(get("/api/incidents/no/" + ghostNo).session(s))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(b1).isEqualTo(b2).isEqualTo(b3);

        List<AuditLog> logs = auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10);
        assertThat(logs).hasSize(3);
        Set<String> reasons = new HashSet<>();
        for (AuditLog l : logs) {
            JsonNode detail = objectMapper.readTree(l.getDetailJson());
            reasons.add(detail.get("reason").asText());
            assertThat(detail.has("requestedIncidentNo")).isTrue();
        }
        assertThat(reasons).containsExactlyInAnyOrder(
                "incident_no_capture_denied", "incident_no_not_found", "incident_no_not_in_zeekad");

        // 형식 오류는 400, 감사 없음
        for (String bad : List.of("abc", "0", "-1", "99999999999999999999", "1.5")) {
            JsonNode r = json(mockMvc.perform(get("/api/incidents/no/" + bad).session(s))
                    .andExpect(status().isBadRequest()).andReturn());
            assertThat(r.get("code").asText()).as(bad).isEqualTo("INVALID_REQUEST");
        }
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(3);
        // 비로그인 API는 401
        mockMvc.perform(get("/api/incidents/no/" + hiddenNo)).andExpect(status().isUnauthorized());
    }

    @Test
    void viewerLocatesAllowedNumberWithoutUnmaskedIp() throws Exception {
        job(97070, CAP_A, "2026-11-20T10:00:00Z");
        incident(97070, CAP_A, 1, "10.77.7.1");
        refService.syncAll();
        long n = no(id(CAP_A, "10.77.7.1"));
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        MvcResult r = mockMvc.perform(get("/api/incidents/no/" + n).session(v)).andExpect(status().isOk()).andReturn();
        String body = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(IPV4.matcher(body).find()).isFalse();
        JsonNode loc = objectMapper.readTree(body);
        assertThat(loc.get("incidentNo").asLong()).isEqualTo(n);
        assertThat(loc.get("jobId").asLong()).isEqualTo(97070);
        // VIEWER 상세에도 번호가 있다(incident_id는 가려져 있다)
        JsonNode d = getJson(v, "/api/incidents/97070/rank/1");
        assertThat(d.get("incidentNo").asLong()).isEqualTo(n);
        assertThat(d.at("/detail/incident/incidentId").asText()).doesNotContain("10.77.7.1");
    }

    /* ───────────── 응답의 incidentNo ───────────── */

    @Test
    void queueNeighborsDetailAndReviewsCarryIncidentNo() throws Exception {
        // 에스컬레이션은 옛 작업(97079)에만 있는 인시던트에 걸려 있다(목록 행은 행만 매기기로 번호를 받는다)
        job(97079, CAP_A, "2026-11-20T09:00:00Z");
        incident(97079, CAP_A, 1, "10.77.8.9");
        review(97079, CAP_A, 1, "10.77.8.9");
        job(97080, CAP_A, "2026-11-20T10:00:00Z");
        incident(97080, CAP_A, 1, "10.77.8.1");
        incident(97080, CAP_A, 2, "10.77.8.2");
        incident(97080, CAP_A, 3, "10.77.8.3");
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100&captureId=" + CAP_A + "&sort=start");
        Set<Long> nos = new HashSet<>();
        for (JsonNode it : q.get("items")) {
            assertThat(it.get("incidentNo").isNumber()).isTrue();
            nos.add(it.get("incidentNo").asLong());
        }
        assertThat(nos).hasSize(q.get("items").size());

        JsonNode middle = q.get("items").get(1);
        JsonNode nb = getJson(s, "/api/incidents/queue/neighbors?jobId=" + middle.get("jobId").asLong()
                + "&queueRank=" + middle.get("queueRank").asInt() + "&period=all&captureId=" + CAP_A + "&sort=start");
        assertThat(nb.at("/current/incidentNo").asLong()).isEqualTo(middle.get("incidentNo").asLong());
        assertThat(nb.at("/prev/incidentNo").asLong()).isEqualTo(q.get("items").get(0).get("incidentNo").asLong());
        assertThat(nb.at("/next/incidentNo").asLong()).isEqualTo(q.get("items").get(2).get("incidentNo").asLong());

        JsonNode d = getJson(s, "/api/incidents/97080/rank/2");
        assertThat(d.get("incidentNo").asLong()).isEqualTo(no(id(CAP_A, "10.77.8.2")));

        JsonNode reviews = getJson(s, "/api/reviews?captureId=" + CAP_A);
        assertThat(reviews.get("reviews")).hasSize(1);
        assertThat(reviews.get("reviews").get(0).get("incidentNo").asLong()).isEqualTo(no(id(CAP_A, "10.77.8.9")));
    }

    /* ───────────── 화면 경로 ───────────── */

    @Test
    void spaRoutesForNumberAddressAndShellRules() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, CAP_A);
        mockMvc.perform(get("/incidents/1042").session(s)).andExpect(status().isOk()).andExpect(forwardedUrl("/index.html"));
        mockMvc.perform(get("/incidents/44/rank/3").session(s)).andExpect(status().isOk()).andExpect(forwardedUrl("/index.html"));
        mockMvc.perform(get("/incidents/abc").session(s)).andExpect(status().isNotFound());
        // 비로그인 화면 경로: 셸 200(데이터 없음, no-store), API는 401, 모르는 경로는 지금처럼 로그인 리다이렉트
        mockMvc.perform(get("/incidents/1042")).andExpect(status().isOk()).andExpect(forwardedUrl("/index.html"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Cache-Control", "no-store"));
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head("/incidents/1042"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/incidents/queue")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/nope")).andExpect(status().is3xxRedirection());
        // 인증된 VIEWER의 /admin/users는 지금처럼 403
        MockHttpSession v = login(UserRole.VIEWER, CAP_A);
        mockMvc.perform(get("/admin/users").session(v)).andExpect(status().isForbidden());
    }

    /* ───────────── 도우미 ───────────── */

    private long no(String incidentId) {
        Long n = app().queryForObject("SELECT incident_no FROM incident_refs WHERE incident_id = ?", Long.class, incidentId);
        assertThat(n).as(incidentId).isNotNull();
        return n;
    }

    private int count(String incidentId) {
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

    private void review(long jobId, String capture, int rank, String ip) {
        jdbc().update("INSERT INTO dashboard.raw_analyst_review_queue (job_id, incident_id, queue_rank, host_ip, zeekad_role, "
                        + "zeekad_review_reason, requested_at, zeekad_review_resume_failed) "
                        + "VALUES (?, ?, ?, ?, 'originator', 't27 검토', TIMESTAMP WITH TIME ZONE '2026-11-20T10:05:00Z', FALSE)",
                jobId, id(capture, ip), rank, ip);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private final Map<MockHttpSession, String> names = new HashMap<>();

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t27_u" + (++seq) + "_" + System.nanoTime() % 100000;
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

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private JsonNode json(MvcResult r) throws Exception {
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
