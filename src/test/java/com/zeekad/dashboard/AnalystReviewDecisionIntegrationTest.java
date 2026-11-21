package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.IncidentReviewDecisionRequest;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.ReviewDecideRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.security.TotpService;
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
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
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
class AnalystReviewDecisionIntegrationTest {

    private static final long JOB_OLD = 701L;
    private static final long JOB_LATEST = 702L;
    private static final long JOB_OTHER_CAPTURE = 703L;
    private static final String CAPTURE_CIC = "cic17-rev-test";
    private static final String CAPTURE_SYN = "syn1-rev-test";
    private static final String INC_1 = "cic17-rev-test|192.168.80.10|originator|1763520000";
    private static final String INC_2 = "cic17-rev-test|192.168.80.20|responder|1763520300";
    private static final String INC_CONC = "cic17-rev-test|192.168.80.30|originator|1763520600";
    private static final String INC_OTHER = "syn1-rev-test|10.88.0.10|originator|1763520900";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private ZeekadReadMapper zeekadReadMapper;

    @Autowired
    private ZeekadWriteMapper zeekadWriteMapper;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    private JdbcTemplate zeekadJdbc;

    @BeforeEach
    void seedFixtures() {
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanupFixtures();

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs
                (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES
                (?, ?, 'zeekad-fusion/3', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-19 03:00:00Z',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:02:00Z', NULL, 1),
                (?, ?, 'zeekad-fusion/3', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-19 03:05:00Z',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:07:00Z', NULL, 3),
                (?, ?, 'zeekad-fusion/3', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-19 03:10:00Z',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:12:00Z', NULL, 1)
                """, JOB_OLD, CAPTURE_CIC, JOB_LATEST, CAPTURE_CIC, JOB_OTHER_CAPTURE, CAPTURE_SYN);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue
                (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
                 event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES
                (?, ?, 'zeekad-fusion/3', 1, ?, '192.168.80.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 02:20:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:00:00Z',
                 'iforest', NULL, 100, NULL),
                (?, ?, 'zeekad-fusion/3', 1, ?, '192.168.80.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 02:20:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:05:00Z',
                 'iforest', NULL, 160, NULL),
                (?, ?, 'zeekad-fusion/3', 2, ?, '192.168.80.20', 'responder',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 02:30:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:05:00Z',
                 'autoencoder', NULL, 80, NULL),
                (?, ?, 'zeekad-fusion/3', 3, ?, '192.168.80.30', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 02:40:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:05:00Z',
                 'hbos', NULL, 55, NULL),
                (?, ?, 'zeekad-fusion/3', 1, ?, '10.88.0.10', 'originator',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 02:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-19 03:10:00Z',
                 'iforest', NULL, 40, NULL)
                """,
                JOB_OLD, CAPTURE_CIC, INC_1,
                JOB_LATEST, CAPTURE_CIC, INC_1,
                JOB_LATEST, CAPTURE_CIC, INC_2,
                JOB_LATEST, CAPTURE_CIC, INC_CONC,
                JOB_OTHER_CAPTURE, CAPTURE_SYN, INC_OTHER);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_reports (
                    job_id, incident_id, zeekad_report_kind, zeekad_report_version, zeekad_input_version,
                    zeekad_report, zeekad_verification_passed, zeekad_verification_reason, zeekad_verification_problems,
                    llm_model_requested, llm_model_version, llm_seconds, llm_input_tokens, llm_output_tokens, llm_thinking_tokens,
                    llm_error, zeekad_attack_candidates, zeekad_source_run, created_at, zeekad_facts, zeekad_pseudonyms
                ) VALUES
                (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary": "old"}' FORMAT JSON,
                 TRUE, 'ok', '[]' FORMAT JSON, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]' FORMAT JSON,
                 'run-701', TIMESTAMP WITH TIME ZONE '2026-11-19 03:03:00Z', '[]' FORMAT JSON, '{}' FORMAT JSON),
                (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary": "latest-1"}' FORMAT JSON,
                 TRUE, 'ok', '[]' FORMAT JSON, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]' FORMAT JSON,
                 'run-702', TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:00Z', '[]' FORMAT JSON, '{}' FORMAT JSON),
                (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary": "latest-2"}' FORMAT JSON,
                 TRUE, 'ok', '[]' FORMAT JSON, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]' FORMAT JSON,
                 'run-702', TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:10Z', '[]' FORMAT JSON, '{}' FORMAT JSON),
                (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary": "latest-3"}' FORMAT JSON,
                 TRUE, 'ok', '[]' FORMAT JSON, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]' FORMAT JSON,
                 'run-702', TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:20Z', '[]' FORMAT JSON, '{}' FORMAT JSON),
                (?, ?, 'template', 'template.v1', 'evidence.v1', '{"observation_summary": "other"}' FORMAT JSON,
                 TRUE, 'ok', '[]' FORMAT JSON, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]' FORMAT JSON,
                 'run-703', TIMESTAMP WITH TIME ZONE '2026-11-19 03:13:00Z', '[]' FORMAT JSON, '{}' FORMAT JSON)
                """,
                JOB_OLD, INC_1,
                JOB_LATEST, INC_1,
                JOB_LATEST, INC_2,
                JOB_LATEST, INC_CONC,
                JOB_OTHER_CAPTURE, INC_OTHER);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_analyst_review_queue (
                    job_id, incident_id, queue_rank, host_ip, zeekad_role, zeekad_review_reason,
                    requested_at, zeekad_review_action, analyst, decided_at,
                    zeekad_review_resumed_at, zeekad_review_resume_failed
                ) VALUES
                (?, ?, 1, '192.168.80.10', 'originator', '구 작업 중복 요청 - 노출 금지',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:03:30Z', NULL, NULL, NULL, NULL, FALSE),
                (?, ?, 1, '192.168.80.10', 'originator', '최신 보고 작업(702) 검토 대기 1',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:30Z', NULL, NULL, NULL, NULL, FALSE),
                (?, ?, 2, '192.168.80.20', 'responder', '최신 보고 작업(702) 검토 대기 2',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:40Z', NULL, NULL, NULL, NULL, FALSE),
                (?, ?, 3, '192.168.80.30', 'originator', '동시 결정 충돌 검증 대상',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:08:50Z', NULL, NULL, NULL, NULL, FALSE),
                (?, ?, 1, '10.88.0.10', 'originator', '타 캡처 검토 대기',
                 TIMESTAMP WITH TIME ZONE '2026-11-19 03:13:30Z', NULL, NULL, NULL, NULL, FALSE)
                """,
                JOB_OLD, INC_1,
                JOB_LATEST, INC_1,
                JOB_LATEST, INC_2,
                JOB_LATEST, INC_CONC,
                JOB_OTHER_CAPTURE, INC_OTHER);
    }

    @AfterEach
    void cleanupFixtures() {
        if (zeekadJdbc == null) {
            zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        }
        zeekadJdbc.update("DELETE FROM dashboard.raw_analyst_review_queue WHERE job_id IN (?, ?, ?)",
                JOB_OLD, JOB_LATEST, JOB_OTHER_CAPTURE);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE job_id IN (?, ?, ?)",
                JOB_OLD, JOB_LATEST, JOB_OTHER_CAPTURE);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id IN (?, ?, ?)",
                JOB_OLD, JOB_LATEST, JOB_OTHER_CAPTURE);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id IN (?, ?, ?)",
                JOB_OLD, JOB_LATEST, JOB_OTHER_CAPTURE);
    }

    @Test
    void viewerAndUnauthorizedCaptureDecisionsReturn403WithIdorAuditLogs() throws Exception {
        String viewer = "rev_viewer_1";
        String analyst = "rev_idor_analyst_1";
        userAdminService.createUser(viewer, "검토조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(analyst, "검토IDOR분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");
        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");

        // VIEWER는 /api/reviews 에서 canDecideReview=false 이고 직접 POST 호출 시 403
        mockMvc.perform(get("/api/reviews").param("captureId", CAPTURE_CIC).session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDecideReview").value(false));

        mockMvc.perform(post("/api/reviews/decide")
                        .session(viewerSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ReviewDecideRequest(JOB_LATEST, INC_1, "confirm", null))))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/review-decision", JOB_LATEST)
                        .session(viewerSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentReviewDecisionRequest("confirm", null))))
                .andExpect(status().isForbidden());

        // ANALYST가 미허용 캡처(syn1-rev-test) 결정 시도 -> 403 + ACCESS_DENIED_IDOR 감사 로그
        mockMvc.perform(post("/api/reviews/decide")
                        .session(analystSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ReviewDecideRequest(JOB_OTHER_CAPTURE, INC_OTHER, "confirm", null))))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/incidents/{jobId}/rank/1/review-decision", JOB_OTHER_CAPTURE)
                        .session(analystSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentReviewDecisionRequest("dismiss", null))))
                .andExpect(status().isForbidden());

        List<AuditLog> idorLogs = auditLogMapper.findFiltered(
                AuditActionType.ACCESS_DENIED_IDOR.name(), analyst, 10);
        assertThat(idorLogs).hasSize(2);
    }

    @Test
    void analystFromReviewsAndAdminFromDetailDecideReviewsForceActorRecordAuditAndReflectResumeStates() throws Exception {
        String analyst = "rev_analyst_1";
        String adminUser = "rev_admin_1";
        userAdminService.createUser(analyst, "김검토", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(adminUser, "박관리", "AdminPass!88", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");

        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");

        // 1. /api/reviews 에서 중복 구 작업(701)은 숨겨지고 최신 reportJobId(702)만 노출됨
        mockMvc.perform(get("/api/reviews").param("captureId", CAPTURE_CIC).session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("최신 보고 작업(702) 검토 대기 1")))
                .andExpect(content().string(not(containsString("구 작업 중복 요청"))));

        // 2. ANALYST가 /api/reviews/decide 로 confirm 결정 (위조 analyst/p_analyst 무시 확인)
        String spoofedPayload = objectMapper.writeValueAsString(Map.of(
                "jobId", JOB_LATEST,
                "incidentId", INC_1,
                "action", "confirm",
                "note", "정밀 조사 필요",
                "analyst", "spoofed_admin",
                "p_analyst", "spoofed_admin"
        ));
        mockMvc.perform(post("/api/reviews/decide")
                        .session(analystSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(spoofedPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andExpect(jsonPath("$.code").value("OK"))
                // T21: 계약대로(반영되면 상태가 바뀐다), 시간 약속 없이
                .andExpect(jsonPath("$.message").value("검토 결정을 '승인'으로 저장했습니다. 파이프라인이 반영하면 인시던트가 분석 중으로 바뀝니다."));

        AnalystReviewItem decided1 = zeekadReadMapper.findAnalystReviewByJobAndIncident(JOB_LATEST, INC_1);
        assertThat(decided1).isNotNull();
        assertThat(decided1.getZeekadReviewAction()).isEqualTo("confirm");
        assertThat(decided1.getAnalyst()).isEqualTo(analyst);
        assertThat(decided1.getDecidedAt()).isNotNull();
        assertThat(decided1.getZeekadReviewResumedAt()).isNull();
        assertThat(decided1.isResumeFailed()).isFalse();
        assertThat(decided1.getResumeStatusLabel()).isEqualTo("반영 중");

        // /api/reviews 에서 '반영 중' 및 '김검토 (rev_analyst_1)' 표시, 위조 이름 미노출 확인
        mockMvc.perform(get("/api/reviews").param("captureId", CAPTURE_CIC).session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("반영 중")))
                .andExpect(content().string(containsString("김검토 (" + analyst + ")")))
                .andExpect(content().string(not(containsString("spoofed_admin"))));

        // 3. 이미 결정된 항목 재결정 시도 -> 409 CONFLICT + 새로고침 안내
        MvcResult conflictResult = mockMvc.perform(post("/api/reviews/decide")
                        .session(analystSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ReviewDecideRequest(JOB_LATEST, INC_1, "dismiss", null))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.succeeded").value(false))
                .andExpect(jsonPath("$.code").value("CONFLICT"))
                .andExpect(jsonPath("$.message").value(containsString("새로고침")))
                .andReturn();
        String conflictMessage = objectMapper.readTree(
                conflictResult.getResponse().getContentAsString(StandardCharsets.UTF_8)).path("message").asText();
        assertThat(conflictMessage.split("새로고침", -1)).hasSize(2);

        // 4. 잘못된 action 값 -> 400 INVALID_REQUEST 거부
        mockMvc.perform(post("/api/reviews/decide")
                        .session(analystSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ReviewDecideRequest(JOB_LATEST, INC_2, "invalid_action", null))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        // 5. ADMIN(TOTP 완료)이 사건 상세(/api/incidents/702/rank/2/review-decision)에서 dismiss 결정
        DashboardUser admin = userMapper.findByUsername(adminUser);
        MockHttpSession adminSession = loginAs(adminUser, "AdminPass!88");
        String code = totpService.generateCode(admin.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(adminSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/incidents/{jobId}/rank/2/review-decision", JOB_LATEST)
                        .session(adminSession)
                        .with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentReviewDecisionRequest("dismiss", "정상 백업 트래픽 확인"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.succeeded").value(true))
                .andExpect(jsonPath("$.message").value("검토 결정을 '오탐 종결'로 저장했습니다. 파이프라인이 반영하면 인시던트가 종결(오탐)됩니다."));

        mockMvc.perform(get("/api/incidents/{jobId}/rank/2", JOB_LATEST).session(adminSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.analystReview.reviewAction").value("dismiss"))
                .andExpect(jsonPath("$.detail.analystReview.resumeStatusLabel").value("반영 중"))
                .andExpect(jsonPath("$.detail.analystReview.analystDisplay").value("박관리 (" + adminUser + ")"))
                .andExpect(jsonPath("$.detail.analystReview.canDecide").value(false));

        // 6. 파이프라인 재개 반영 완료('반영됨') 및 실패('반영 실패(관리자 확인 필요)') 상태 응답 검증
        zeekadJdbc.update("""
                UPDATE dashboard.raw_analyst_review_queue
                SET zeekad_review_resumed_at = TIMESTAMP WITH TIME ZONE '2026-11-19 03:09:30Z',
                    zeekad_review_resume_failed = FALSE
                WHERE job_id = ? AND incident_id = ?
                """, JOB_LATEST, INC_1);
        zeekadJdbc.update("""
                UPDATE dashboard.raw_analyst_review_queue
                SET zeekad_review_resumed_at = NULL,
                    zeekad_review_resume_failed = TRUE
                WHERE job_id = ? AND incident_id = ?
                """, JOB_LATEST, INC_2);

        mockMvc.perform(get("/api/incidents/{jobId}/rank/1", JOB_LATEST).session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.analystReview.resumeStatusLabel").value("반영됨"));
        mockMvc.perform(get("/api/incidents/{jobId}/rank/2", JOB_LATEST).session(adminSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.analystReview.resumeStatusLabel").value("반영 실패(관리자 확인 필요)"));

        // 7. 감사 로그 ANALYST_REVIEW_DECISION 검증
        List<AuditLog> analystAudit = auditLogMapper.findFiltered(
                AuditActionType.ANALYST_REVIEW_DECISION.name(), analyst, 10);
        assertThat(analystAudit).hasSize(1);
        assertThat(analystAudit.get(0).getTargetJobId()).isEqualTo(JOB_LATEST);
        assertThat(analystAudit.get(0).getTargetIncidentId()).isEqualTo(INC_1);

        List<AuditLog> adminAudit = auditLogMapper.findFiltered(
                AuditActionType.ANALYST_REVIEW_DECISION.name(), adminUser, 10);
        assertThat(adminAudit).hasSize(1);
        assertThat(adminAudit.get(0).getTargetIncidentId()).isEqualTo(INC_2);
    }

    @Test
    void concurrentReviewDecisionsAllowOnlyOneWinnerAndNonExistentProducesSqlState02000() throws Exception {
        String analystA = "rev_conc_a";
        String analystB = "rev_conc_b";
        userAdminService.createUser(analystA, "동시분석가A", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(analystB, "동시분석가B", "Pass1234!", UserRole.ANALYST,
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
                        return mockMvc.perform(post("/api/reviews/decide")
                                        .session(sessionA)
                                        .with(xsrf())
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(
                                                new ReviewDecideRequest(JOB_LATEST, INC_CONC, "confirm", null))))
                                .andReturn();
                    },
                    () -> {
                        ready.countDown();
                        start.await(5, TimeUnit.SECONDS);
                        return mockMvc.perform(post("/api/reviews/decide")
                                        .session(sessionB)
                                        .with(xsrf())
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(
                                                new ReviewDecideRequest(JOB_LATEST, INC_CONC, "dismiss", null))))
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
        } finally {
            pool.shutdownNow();
        }

        // 존재하지 않는 검토 항목 -> SQLSTATE 02000
        assertThatThrownBy(() -> zeekadWriteMapper.decideReview(
                JOB_LATEST, "non-existent-review-incident", "confirm", "analyst1", null))
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
