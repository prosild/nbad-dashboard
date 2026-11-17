package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.model.zeekad.IncidentStatusHistory;
import com.zeekad.dashboard.service.UserAdminService;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentTransitionIntegrationTest {

    private static final long TEST_JOB_ID = 301L;
    private static final String TEST_CAPTURE_ID = "cic17-trans-test";
    private static final String INC_1 = "cic17-trans-test|192.168.50.10|originator|1700003001";
    private static final String INC_2 = "cic17-trans-test|192.168.50.20|originator|1700003002";
    private static final String INC_3 = "cic17-trans-test|192.168.50.30|responder|1700003003";

    @Autowired
    private MockMvc mockMvc;

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

        // 미등록 actor 표기 검증을 위해 rank 1에 사전 이력 1건(external_bot) 추가
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
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_status_history WHERE job_id = ?", TEST_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_status WHERE job_id = ?", TEST_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", TEST_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", TEST_JOB_ID);
    }

    @Test
    void databaseIdProviderResolvesH2AndForwardTransitionsEnforceRulesActorAndAuditLog() throws Exception {
        assertThat(zeekadWriteSqlSessionFactory.getConfiguration().getDatabaseId()).isEqualTo("h2");

        String analyst = "trans_analyst_1";
        userAdminService.createUser(analyst, "박분석", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // 1. 건너뛰기 (open -> closed) 거부 확인 (rank 2)
        mockMvc.perform(post("/incidents/{jobId}/rank/2/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "closed")
                        .param("resolution", "benign")
                        .param("reason", "건너뛰기 시도"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/incidents/" + TEST_JOB_ID + "/rank/2"))
                .andExpect(flash().attributeExists("transitionError"));

        assertThat(zeekadReadMapper.findIncidentStatus(TEST_JOB_ID, INC_2)).isNull();

        // 2. open -> investigating 정방향 전이 (위조 actor 파라미터 무시 검증 포함)
        mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "investigating")
                        .param("actor", "spoofed_admin")
                        .param("p_actor", "spoofed_admin")
                        .param("resolution", "benign")
                        .param("reason", "초기 이상 징후 조사 시작"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/incidents/" + TEST_JOB_ID + "/rank/1"))
                .andExpect(flash().attributeExists("transitionSuccess"));

        IncidentStatus afterStep1 = zeekadReadMapper.findIncidentStatus(TEST_JOB_ID, INC_1);
        assertThat(afterStep1).isNotNull();
        assertThat(afterStep1.getZeekadStatus()).isEqualTo("investigating");
        assertThat(afterStep1.getZeekadResolution()).isNull();
        assertThat(afterStep1.getUpdatedBy()).isEqualTo(analyst);

        // 상세 화면에서 investigating 상태, closed 폼 노출, display_name (actor) 및 미등록 actor 표기 확인
        mockMvc.perform(get("/incidents/{jobId}/rank/1", TEST_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("현재 상태: investigating")))
                .andExpect(content().string(containsString("박분석 (trans_analyst_1)")))
                .andExpect(content().string(containsString("external_bot")))
                .andExpect(content().string(not(containsString("spoofed_admin"))))
                .andExpect(content().string(containsString("사건 종료 (closed)")));

        // 3. 이미 investigating 상태에서 investigating 재요청 -> SQLSTATE 22023 충돌 안내
        MvcResult dupResult = mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "investigating")
                        .param("reason", "중복 전이 시도"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("transitionError"))
                .andReturn();
        assertThat(dupResult.getFlashMap().get("transitionError").toString()).contains("새로고침");

        // 4. closed 시 결론 누락 / 잘못된 결론 / 사유 공백 거부
        mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "closed")
                        .param("resolution", "unknown_value")
                        .param("reason", "잘못된 결론"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("transitionError"));

        mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "closed")
                        .param("resolution", "true_positive")
                        .param("reason", "   "))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("transitionError"));

        // 5. investigating -> closed 정방향 완료
        mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "closed")
                        .param("resolution", "true_positive")
                        .param("reason", "Kerberos 티켓 탈취 정탐 확정"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("transitionSuccess"));

        IncidentStatus afterStep2 = zeekadReadMapper.findIncidentStatus(TEST_JOB_ID, INC_1);
        assertThat(afterStep2.getZeekadStatus()).isEqualTo("closed");
        assertThat(afterStep2.getZeekadResolution()).isEqualTo("true_positive");

        // 종료 후 상세 화면에서는 상태 변경 폼이 숨겨짐
        mockMvc.perform(get("/incidents/{jobId}/rank/1", TEST_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("이미 종료(closed)된 사건입니다")))
                .andExpect(content().string(not(containsString("/transition"))));

        // 6. closed -> investigating 역방향 시도 거부
        mockMvc.perform(post("/incidents/{jobId}/rank/1/transition", TEST_JOB_ID)
                        .session(session)
                        .with(csrf())
                        .param("toStatus", "investigating")
                        .param("reason", "되돌리기 시도"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("transitionError"));

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
                        return mockMvc.perform(post("/incidents/{jobId}/rank/3/transition", TEST_JOB_ID)
                                        .session(sessionA)
                                        .with(csrf())
                                        .param("toStatus", "investigating")
                                        .param("reason", "동시 요청 A"))
                                .andExpect(status().is3xxRedirection())
                                .andReturn();
                    },
                    () -> {
                        ready.countDown();
                        start.await(5, TimeUnit.SECONDS);
                        return mockMvc.perform(post("/incidents/{jobId}/rank/3/transition", TEST_JOB_ID)
                                        .session(sessionB)
                                        .with(csrf())
                                        .param("toStatus", "investigating")
                                        .param("reason", "동시 요청 B"))
                                .andExpect(status().is3xxRedirection())
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
            int errorCount = 0;
            String errorMsg = null;
            for (Future<MvcResult> f : futures) {
                MvcResult res = f.get(10, TimeUnit.SECONDS);
                if (res.getFlashMap().containsKey("transitionSuccess")) {
                    successCount++;
                } else if (res.getFlashMap().containsKey("transitionError")) {
                    errorCount++;
                    errorMsg = String.valueOf(res.getFlashMap().get("transitionError"));
                }
            }

            assertThat(successCount).isEqualTo(1);
            assertThat(errorCount).isEqualTo(1);
            assertThat(errorMsg).contains("새로고침");
            assertThat(errorMsg).doesNotContain("java.lang.", "org.h2.", "SELECT ");

            List<IncidentStatusHistory> history = zeekadReadMapper.findIncidentStatusHistory(TEST_JOB_ID, INC_3);
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

    private MockHttpSession loginAs(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
