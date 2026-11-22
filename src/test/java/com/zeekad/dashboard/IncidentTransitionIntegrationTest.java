package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.IncidentTransitionRequest;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.model.zeekad.IncidentStatusHistory;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.apache.ibatis.session.SqlSessionFactory;
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
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentTransitionIntegrationTest {

    private static final long TEST_JOB_ID = 301L;
    private static final long MULTI_JOB_A = 311L;
    private static final long MULTI_JOB_B = 312L;
    private static final String TEST_CAPTURE_ID = "cic17-trans-test";
    private static final String MULTI_CAPTURE_ID = "lab-20261117";
    private static final String INC_1 = "cic17-trans-test|192.168.50.10|originator|1700003001";
    private static final String INC_2 = "cic17-trans-test|192.168.50.20|originator|1700003002";
    private static final String INC_3 = "cic17-trans-test|192.168.50.30|responder|1700003003";
    private static final String MULTI_INC = "lab-20261117|10.30.0.10|originator|1763400000";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private ZeekadReadMapper zeekadReadMapper;

    @Autowired
    private ZeekadWriteMapper zeekadWriteMapper;

    @Autowired
    @Qualifier("zeekadWriteSqlSessionFactory")
    private SqlSessionFactory zeekadWriteSqlSessionFactory;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    private JdbcTemplate zeekadJdbc;

    @BeforeEach
    void seedTransitionFixtures() {
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanupFixtures();

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs
                (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-17 01:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-17 01:05:00Z', NULL, 3)
                """, TEST_JOB_ID, TEST_CAPTURE_ID);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue
                (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
                 event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES
                (?, ?, 'zeekad-fusion/1', 1, ?, '192.168.50.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 00:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 01:00:00Z',
                 'iforest', NULL, 120, NULL),
                (?, ?, 'zeekad-fusion/1', 2, ?, '192.168.50.20', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 00:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 01:00:00Z',
                 'autoencoder', NULL, 80, NULL),
                (?, ?, 'zeekad-fusion/1', 3, ?, '192.168.50.30', 'responder',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 00:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 01:00:00Z',
                 'hbos', NULL, 55, NULL)
                """,
                TEST_JOB_ID, TEST_CAPTURE_ID, INC_1,
                TEST_JOB_ID, TEST_CAPTURE_ID, INC_2,
                TEST_JOB_ID, TEST_CAPTURE_ID, INC_3);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_status_history
                (job_id, incident_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at)
                VALUES (?, ?, NULL, 'open', NULL, 'external_bot', '자동 큐 등록',
                        TIMESTAMP WITH TIME ZONE '2026-11-17 01:05:00Z')
                """, TEST_JOB_ID, INC_1);
    }

    @AfterEach
    void cleanupFixtures() {
        if (zeekadJdbc == null) {
            zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        }
        zeekadJdbc.update(
                "DELETE FROM dashboard.raw_incident_status_history WHERE incident_id IN (?, ?, ?, ?) OR job_id IN (?, ?, ?)",
                INC_1, INC_2, INC_3, MULTI_INC, TEST_JOB_ID, MULTI_JOB_A, MULTI_JOB_B);
        zeekadJdbc.update(
                "DELETE FROM dashboard.raw_incident_status WHERE incident_id IN (?, ?, ?, ?) OR job_id IN (?, ?, ?)",
                INC_1, INC_2, INC_3, MULTI_INC, TEST_JOB_ID, MULTI_JOB_A, MULTI_JOB_B);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id IN (?, ?, ?)",
                TEST_JOB_ID, MULTI_JOB_A, MULTI_JOB_B);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id IN (?, ?, ?)",
                TEST_JOB_ID, MULTI_JOB_A, MULTI_JOB_B);
    }

    @Test
    void databaseIdProviderResolvesH2AndForwardTransitionsEnforceRulesActorAndAuditLog() throws Exception {
        assertThat(zeekadWriteSqlSessionFactory.getConfiguration().getDatabaseId()).isEqualTo("h2");

        String analyst = "trans_analyst_1";
        userAdminService.createUser(analyst, "박분석", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // 1. 건너뛰기 (open -> closed) 409 CONFLICT 거부 확인 (rank 2)
        mockMvc.perform(post("/api/incidents/{jobId}/rank/2/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("closed", "benign", "건너뛰기 시도"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.succeeded").value(false))
                .andExpect(jsonPath("$.code").value("CONFLICT"));

        assertThat(zeekadReadMapper.findIncidentStatus(INC_2)).isNull();

        // 2. open -> investigating 정방향 전이 (위조 actor 필드 무시 검증 포함)
        String spoofedPayload = objectMapper.writeValueAsString(Map.of(
                "toStatus", "investigating",
                "actor", "spoofed_admin",
                "p_actor", "spoofed_admin",
                "resolution", "benign",
                "reason", "초기 이상 징후 조사 시작"
        ));
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(spoofedPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andExpect(jsonPath("$.code").value("OK"));

        IncidentStatus afterStep1 = zeekadReadMapper.findIncidentStatus(INC_1);
        assertThat(afterStep1).isNotNull();
        assertThat(afterStep1.getZeekadStatus()).isEqualTo("investigating");
        assertThat(afterStep1.getZeekadResolution()).isNull();
        assertThat(afterStep1.getUpdatedBy()).isEqualTo(analyst);

        // 상세 API에서 investigating 상태, nextAllowedStatus=closed, display_name (actor) 및 미등록 actor 표기 확인
        mockMvc.perform(get("/api/incidents/{jobId}/rank/1", TEST_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.currentStatus").value("investigating"))
                .andExpect(jsonPath("$.detail.nextAllowedStatus").value("closed"))
                .andExpect(content().string(containsString("박분석 (trans_analyst_1)")))
                .andExpect(content().string(containsString("external_bot")))
                .andExpect(content().string(not(containsString("spoofed_admin"))));

        // 3. 이미 investigating 상태에서 investigating 재요청 -> 409 CONFLICT + 새로고침 안내
        MvcResult conflictResult = mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "중복 전이 시도"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.succeeded").value(false))
                .andExpect(jsonPath("$.code").value("CONFLICT"))
                .andExpect(jsonPath("$.message").value(containsString("새로고침")))
                .andReturn();
        String conflictMessage = objectMapper.readTree(
                conflictResult.getResponse().getContentAsString(StandardCharsets.UTF_8)).path("message").asText();
        assertThat(conflictMessage.split("새로고침", -1)).hasSize(2);

        // 4. closed 시 잘못된 결론 / 사유 공백 -> 400 INVALID_REQUEST 거부
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("closed", "unknown_value", "잘못된 결론"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("closed", "true_positive", "   "))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        // 5. investigating -> closed 정방향 완료
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("closed", "true_positive", "Kerberos 티켓 탈취 정탐 확정"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true));

        IncidentStatus afterStep2 = zeekadReadMapper.findIncidentStatus(INC_1);
        assertThat(afterStep2.getZeekadStatus()).isEqualTo("closed");
        assertThat(afterStep2.getZeekadResolution()).isEqualTo("true_positive");

        // 종료 후 상세 API에서는 nextAllowedStatus가 null
        mockMvc.perform(get("/api/incidents/{jobId}/rank/1", TEST_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.currentStatus").value("closed"))
                .andExpect(jsonPath("$.detail.nextAllowedStatus").doesNotExist());

        // 6. closed -> investigating 역방향 시도 -> 409 CONFLICT 거부
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "되돌리기 시도"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CONFLICT"));

        // 감사 로그 INCIDENT_STATUS_TRANSITION 2건 확인
        List<AuditLog> logs = auditLogMapper.findFiltered(
                AuditActionType.INCIDENT_STATUS_TRANSITION.name(), analyst, 20);
        assertThat(logs).hasSize(2);
    }

    @Test
    void concurrentTransitionsAllowOnlyOneWinnerAndNotifyLoserWithRefreshPrompt() throws Exception {
        String analystA = "conc_analyst_a";
        String analystB = "conc_analyst_b";
        userAdminService.createUser(analystA, "분석가A", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(analystB, "분석가B", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession sessionA = loginAs(analystA, "Pass1234!");
        MockHttpSession sessionB = loginAs(analystB, "Pass1234!");

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Callable<MvcResult>> tasks = List.of(
                    () -> {
                        ready.countDown();
                        start.await(5, TimeUnit.SECONDS);
                        return mockMvc.perform(post("/api/incidents/{jobId}/rank/3/transition", TEST_JOB_ID)
                                        .session(sessionA)
                                        .with(xsrf())
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(
                                                new IncidentTransitionRequest("investigating", null, "동시 요청 A"))))
                                .andReturn();
                    },
                    () -> {
                        ready.countDown();
                        start.await(5, TimeUnit.SECONDS);
                        return mockMvc.perform(post("/api/incidents/{jobId}/rank/3/transition", TEST_JOB_ID)
                                        .session(sessionB)
                                        .with(xsrf())
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(
                                                new IncidentTransitionRequest("investigating", null, "동시 요청 B"))))
                                .andReturn();
                    }
            );
            List<Future<MvcResult>> futures = new ArrayList<>();
            for (Callable<MvcResult> task : tasks) {
                futures.add(pool.submit(task));
            }
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            int successCount = 0;
            int conflictCount = 0;
            String errorMsg = null;
            for (Future<MvcResult> f : futures) {
                MvcResult res = f.get(10, TimeUnit.SECONDS);
                JsonNode json = objectMapper.readTree(res.getResponse().getContentAsString());
                if (res.getResponse().getStatus() == 200 && json.get("succeeded").asBoolean()) {
                    successCount++;
                } else if (res.getResponse().getStatus() == 409) {
                    conflictCount++;
                    errorMsg = json.get("message").asText();
                }
            }

            assertThat(successCount).isEqualTo(1);
            assertThat(conflictCount).isEqualTo(1);
            assertThat(errorMsg).contains("새로고침");
            assertThat(errorMsg).doesNotContain("java.lang.", "org.h2.", "SELECT ");

            List<IncidentStatusHistory> history = zeekadReadMapper.findIncidentStatusHistory(INC_3);
            assertThat(history).hasSize(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void nonExistentIncidentProducesSqlState02000() {
        assertThatThrownBy(() -> zeekadWriteMapper.transitionIncident(
                TEST_JOB_ID, "non-existent-incident", "investigating", "analyst1", "사유", null))
                .satisfies(ex -> {
                    Throwable cur = ex;
                    SQLException found = null;
                    while (cur != null) {
                        if (cur instanceof SQLException sqlEx && "02000".equals(sqlEx.getSQLState())) {
                            found = sqlEx;
                            break;
                        }
                        cur = cur.getCause();
                    }
                    assertThat((Throwable) found).isNotNull();
                    assertThat(found.getSQLState()).isEqualTo("02000");
                });
    }

    @Test
    void incidentStatusPersistsAcrossJobsAndCombinesHistoryByIncidentId() throws Exception {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs
                (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES
                (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-17 10:00:00Z',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 10:01:00Z', NULL, 1),
                (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-17 10:05:00Z',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 10:06:00Z', NULL, 2)
                """, MULTI_JOB_A, MULTI_CAPTURE_ID, MULTI_JOB_B, MULTI_CAPTURE_ID);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue
                (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
                 event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES
                (?, ?, 'zeekad-fusion/1', 1, ?, '10.30.0.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 09:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 10:00:00Z',
                 'iforest', NULL, 50, NULL),
                (?, ?, 'zeekad-fusion/1', 1, 'lab-20261117|10.30.0.99|responder|1763400100', '10.30.0.99', 'responder',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 10:00:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 10:05:00Z',
                 'hbos', NULL, 10, NULL),
                (?, ?, 'zeekad-fusion/1', 2, ?, '10.30.0.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-17 09:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 10:05:00Z',
                 'iforest', NULL, 90, NULL)
                """, MULTI_JOB_A, MULTI_CAPTURE_ID, MULTI_INC, MULTI_JOB_B, MULTI_CAPTURE_ID, MULTI_JOB_B, MULTI_CAPTURE_ID, MULTI_INC);

        String labAnalyst = "lab_trans_analyst";
        userAdminService.createUser(labAnalyst, "실습분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(labAnalyst, "Pass1234!");

        // 작업 A(311)에서 open -> investigating 전이
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", MULTI_JOB_A)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "작업 A에서 조사 착수"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true));

        // 최신 작업 B(312)에서도 investigating 승계 확인
        mockMvc.perform(get("/api/incidents/{jobId}/rank/2", MULTI_JOB_B).session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.currentStatus").value("investigating"))
                .andExpect(jsonPath("$.detail.nextAllowedStatus").value("closed"))
                .andExpect(jsonPath("$.detail.statusHistory[0].jobId").value(MULTI_JOB_A));

        // 최신 작업 B(312)에서 investigating -> closed 전이
        mockMvc.perform(post("/api/incidents/{jobId}/rank/2/transition", MULTI_JOB_B)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("closed", "false_positive", "작업 B에서 오탐 종결"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true));

        IncidentStatus finalStatus = zeekadReadMapper.findIncidentStatus(MULTI_INC);
        assertThat(finalStatus).isNotNull();
        assertThat(finalStatus.getJobId()).isEqualTo(MULTI_JOB_B);
        assertThat(finalStatus.getZeekadStatus()).isEqualTo("closed");
        assertThat(finalStatus.getZeekadResolution()).isEqualTo("false_positive");

        List<IncidentStatusHistory> combinedHistory = zeekadReadMapper.findIncidentStatusHistory(MULTI_INC);
        assertThat(combinedHistory).hasSize(2);
        assertThat(combinedHistory).extracting(IncidentStatusHistory::getJobId)
                .containsExactlyInAnyOrder(MULTI_JOB_A, MULTI_JOB_B);

        // 상세 API에서도 작업 A와 작업 B 이력이 모두 합산 반환됨
        mockMvc.perform(get("/api/incidents/{jobId}/rank/2", MULTI_JOB_B).session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.currentStatus").value("closed"))
                .andExpect(jsonPath("$.detail.statusHistory.length()").value(2))
                .andExpect(content().string(containsString("작업 A에서 조사 착수")))
                .andExpect(content().string(containsString("작업 B에서 오탐 종결")));

        // 종료 후 과거 작업 A에서 재전이 시 409 CONFLICT 거부
        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/transition", MULTI_JOB_A)
                        .session(session)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "과거 작업 재전이 시도"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CONFLICT"));
    }

    @Test
    void t33ReasonOver500CodePointsIsRejectedWithoutTransitionOrAudit() throws Exception {
        String analyst = "trans_len_analyst";
        userAdminService.createUser(analyst, "길이분석", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");
        // 코드 포인트 기준(보조 평면 문자 501개), 앞뒤 공백은 세지 않는다
        String over = " " + "😀".repeat(501) + " ";
        mockMvc.perform(post("/api/incidents/{jobId}/rank/2/transition", TEST_JOB_ID).session(session).with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new IncidentTransitionRequest("investigating", null, over))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.succeeded").value(false))
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.message").value("상태 변경 사유는 500자까지 입력할 수 있습니다."));
        // DB 함수가 불리지 않았다(상태 행 없음)·감사 없음
        assertThat(zeekadReadMapper.findIncidentStatus(INC_2)).isNull();
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_STATUS_TRANSITION.name(), analyst, 20)).isEmpty();

        String limit = " " + "가".repeat(499) + "😀" + " ";
        mockMvc.perform(post("/api/incidents/{jobId}/rank/2/transition", TEST_JOB_ID).session(session).with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new IncidentTransitionRequest("investigating", null, limit))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true));
        assertThat(zeekadReadMapper.findIncidentStatus(INC_2).getZeekadStatus()).isEqualTo("investigating");
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_STATUS_TRANSITION.name(), analyst, 20)).hasSize(1);
    }

    private RequestPostProcessor xsrf() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        Cookie csrfCookie = res.getResponse().getCookie("XSRF-TOKEN");
        return req -> {
            req.setCookies(csrfCookie);
            req.addHeader("X-XSRF-TOKEN", csrfCookie.getValue());
            return req;
        };
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
