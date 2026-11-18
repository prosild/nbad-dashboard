package com.zeekad.dashboard;

import com.sun.net.httpserver.HttpServer;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import org.junit.jupiter.api.AfterAll;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentDetailAndSecurityIntegrationTest {

    private static final long XSS_JOB_ID = 401L;
    private static final String XSS_CAPTURE_ID = "cic17-xss-test";
    private static final String XSS_INC_ID = "cic17-xss-test|192.168.77.10|originator|1700004001";

    private static HttpServer evidenceServer;
    private static final AtomicBoolean evidenceServerShouldFail = new AtomicBoolean(false);
    private static final java.util.concurrent.atomic.AtomicReference<String> lastEvidencePath =
            new java.util.concurrent.atomic.AtomicReference<>();

    @DynamicPropertySource
    static void registerEvidenceApiUrl(DynamicPropertyRegistry registry) throws IOException {
        evidenceServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        evidenceServer.createContext("/api/v1/jobs/", exchange -> {
            lastEvidencePath.set(exchange.getRequestURI().getPath());
            if (evidenceServerShouldFail.get()) {
                byte[] err = "{\"detail\":\"backend unavailable\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(500, err.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(err);
                }
                return;
            }
            String payload = """
                    {
                      "evidence": {
                        "connection_count": 412,
                        "orig_bytes": 98304,
                        "resp_bytes": 524288,
                        "transport_counts": {"tcp": 390, "udp": 22},
                        "conn_state_counts": {"SF": 300, "S0": 112},
                        "peers": {"top": [{"ip": "203.0.113.45", "count": 210}]},
                        "ports": {"top": [{"port": 88, "count": 195}]},
                        "dns": 12, "http": 4, "tls": 18, "ssh": 0, "ftp": 0,
                        "smb": 11, "kerberos": 195, "dce_rpc": 3, "ntlm": 2,
                        "representative_connections": [
                          {"orig_h": "192.168.10.50", "resp_h": "203.0.113.45", "resp_p": 88, "proto": "tcp"}
                        ],
                        "limitations": ["수집 구간 10.20.30.99 일부 패킷 손실"]
                      }
                    }
                    """;
            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        evidenceServer.start();
        int port = evidenceServer.getAddress().getPort();
        registry.add("dashboard.evidence-api.url", () -> "http://127.0.0.1:" + port);
    }

    @AfterAll
    static void stopEvidenceServer() {
        if (evidenceServer != null) {
            evidenceServer.stop(0);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    private JdbcTemplate zeekadJdbc;

    @BeforeEach
    void setUp() {
        evidenceServerShouldFail.set(false);
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanupXssFixture();
    }

    @AfterEach
    void tearDown() {
        evidenceServerShouldFail.set(false);
        cleanupXssFixture();
    }

    private void cleanupXssFixture() {
        if (zeekadJdbc == null) {
            return;
        }
        zeekadJdbc.update("DELETE FROM dashboard.raw_slack_deliveries WHERE job_id = ?", XSS_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_send_decisions WHERE job_id = ?", XSS_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE job_id = ?", XSS_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_asset_names WHERE capture_id = ?", XSS_CAPTURE_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_model_scores WHERE job_id = ?", XSS_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", XSS_JOB_ID);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", XSS_JOB_ID);
    }

    @Test
    void analystAndAdminSeeFullDetailWithEvidenceModelsReportsDecisionsSlackAndFallback() throws Exception {
        String analyst = "detail_analyst_1";
        userAdminService.createUser(analyst, "상세분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");

        // 1. job 101 rank 1 (LLM 보고서 + 만장일치 전송 판단 + Slack dry_run + evidence.v1 정상)
        MvcResult rank1Res = mockMvc.perform(get("/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(content().string(containsString("192.168.10.50")))
                .andExpect(content().string(containsString("4 / 6")))
                .andExpect(content().string(containsString("3 / 6")))
                .andExpect(content().string(not(containsString("0.91")))) // max_score 직접 비교/노출 금지
                .andExpect(content().string(containsString("admin")))
                .andExpect(content().string(containsString("svc_ad_sync")))
                .andExpect(content().string(containsString("source_log")))
                .andExpect(content().string(containsString("412")))
                .andExpect(content().string(containsString("203.0.113.45")))
                .andExpect(content().string(containsString("dce_rpc")))
                .andExpect(content().string(containsString("gemini-2.5-pro-001")))
                .andExpect(content().string(containsString("H(192.168.10.50)에서 X1(203.0.113.45)로")))
                .andExpect(content().string(containsString("<details class=\"fact-details\">")))
                .andExpect(content().string(containsString("F1 (connection_count)")))
                .andExpect(content().string(containsString("T1558")))
                .andExpect(content().string(containsString("공격 정답이 아닌 가설")))
                .andExpect(content().string(containsString("선택 확률")))
                .andExpect(content().string(not(containsString("정확도"))))
                .andExpect(content().string(not(containsString("신뢰도 %"))))
                .andExpect(content().string(containsString("기록만(dry-run)")))
                .andReturn();
        String rank1Html = rank1Res.getResponse().getContentAsString();
        assertThat(rank1Html).doesNotContain("<script>");

        // INCIDENT_VIEW_UNMASKED 감사 로그 확인
        List<AuditLog> unmaskedLogs = auditLogMapper.findFiltered(
                AuditActionType.INCIDENT_VIEW_UNMASKED.name(), analyst, 10);
        assertThat(unmaskedLogs).hasSize(1);
        assertThat(unmaskedLogs.get(0).getTargetJobId()).isEqualTo(101L);

        // 2. job 101 rank 2 (템플릿 보고서 null 안전 + 세 의견 불일치 + 이력 display_name)
        mockMvc.perform(get("/incidents/101/rank/2").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("template.v1")))
                .andExpect(content().string(containsString("H(10.20.30.40)의 SMB 응답 트래픽 증가")))
                .andExpect(content().string(containsString("의견 불일치")))
                .andExpect(content().string(containsString("선택 확률")))
                .andExpect(content().string(not(containsString("정확도"))))
                .andExpect(content().string(not(containsString("보고서 전송 권고"))));

        // 3. job 101 rank 3 (보고서 없음)
        mockMvc.perform(get("/incidents/101/rank/3").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("보고서 없음")));

        // 4. FastAPI 장애 시 폴백 배너 + DB 뷰 정보 정상 표시
        evidenceServerShouldFail.set(true);
        mockMvc.perform(get("/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("근거 API 연결 불가(DB 뷰 정보만 표시)")))
                .andExpect(content().string(containsString("H(192.168.10.50)에서 X1(203.0.113.45)로")))
                .andExpect(content().string(containsString("gemini-2.5-pro")));

        // 5. ADMIN(TOTP 완료)도 상세 조회 시 INCIDENT_VIEW_UNMASKED 기록 확인
        String adminUser = "detail_admin_1";
        userAdminService.createUser(adminUser, "상세관리자", "AdminPass!99", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser admin = userMapper.findByUsername(adminUser);
        MockHttpSession adminSession = loginAs(adminUser, "AdminPass!99");
        String totpCode = totpService.generateCode(admin.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/login/totp/setup")
                        .session(adminSession)
                        .with(csrf())
                        .param("code", totpCode))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/incidents/201/rank/1").session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.99.88.77")));
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), adminUser, 10))
                .hasSize(1);
    }

    @Test
    void viewerIsMaskedCompletelyAndBlockedFromTransitionAndUnauthorizedCapturesWithIdorAudit() throws Exception {
        String viewer = "detail_viewer_1";
        userAdminService.createUser(viewer, "상세조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");

        // VIEWER 상세 조회: 모든 IP 및 계정명 마스킹 확인
        MvcResult viewerRes = mockMvc.perform(get("/incidents/101/rank/1").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("192.168.*.*")))
                .andExpect(content().string(containsString("203.0.*.*")))
                .andExpect(content().string(containsString("10.20.*.*")))
                .andExpect(content().string(containsString("a***")))
                .andExpect(content().string(containsString("s***")))
                .andExpect(content().string(containsString("H(192.168.*.*)에서 X1(203.0.*.*)로")))
                .andExpect(content().string(not(containsString("192.168.10.50"))))
                .andExpect(content().string(not(containsString("203.0.113.45"))))
                .andExpect(content().string(not(containsString("10.20.30.99"))))
                .andExpect(content().string(not(containsString("svc_ad_sync"))))
                .andExpect(content().string(not(containsString("/transition"))))
                .andReturn();
        assertThat(viewerRes.getResponse().getContentAsString()).doesNotContain(">admin<");

        // VIEWER는 INCIDENT_VIEW_UNMASKED 로그가 남지 않아야 함
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), viewer, 10))
                .isEmpty();

        // VIEWER가 허용된 캡처의 상태 변경 POST 시도 -> 403 Forbidden
        mockMvc.perform(post("/incidents/101/rank/1/transition")
                        .session(viewerSession)
                        .with(csrf())
                        .param("toStatus", "investigating")
                        .param("reason", "권한 없는 변경 시도"))
                .andExpect(status().isForbidden());

        // 미허용 캡처(job 201, syn1-tue) 상세 조회 및 상태 변경 시도 -> 403 + ACCESS_DENIED_IDOR
        mockMvc.perform(get("/incidents/201/rank/1").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/incidents/201/rank/1/transition")
                        .session(viewerSession)
                        .with(csrf())
                        .param("toStatus", "investigating")
                        .param("reason", "타 캡처 변경 시도"))
                .andExpect(status().isForbidden());

        // 존재하지 않는 queueRank / jobId 접근 -> 403 + ACCESS_DENIED_IDOR
        mockMvc.perform(get("/incidents/101/rank/999").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/incidents/999999/rank/1").session(viewerSession))
                .andExpect(status().isForbidden());

        List<AuditLog> idorLogs = auditLogMapper.findFiltered(
                AuditActionType.ACCESS_DENIED_IDOR.name(), viewer, 20);
        assertThat(idorLogs).hasSize(4);
    }

    @Test
    void untrustedReportAndLogInputsAreHtmlEscapedWithSinglePassPseudonymAnnotation() throws Exception {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs
                (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-17 02:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-17 02:04:00Z', NULL, 1)
                """, XSS_JOB_ID, XSS_CAPTURE_ID);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue
                (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role,
                 event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES (?, ?, 'zeekad-fusion/1', 1, ?, '192.168.77.10', 'originator',
                        TIMESTAMP WITH TIME ZONE '2026-11-17 01:50:00Z', TIMESTAMP WITH TIME ZONE '2026-11-17 02:00:00Z',
                        'iforest', NULL, 99, ARRAY['<script>alert("host")</script>'])
                """, XSS_JOB_ID, XSS_CAPTURE_ID, XSS_INC_ID);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_asset_names
                (capture_id, host_ip, kerberos_user, ntlm_user, source_log, observation_count, first_seen, last_seen)
                VALUES (?, '192.168.77.10', '<img src=x onerror=alert("krb")>', '<svg onload=alert("ntlm")>',
                        'kerberos', 3, TIMESTAMP WITH TIME ZONE '2026-11-17 01:51:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-17 01:59:00Z')
                """, XSS_CAPTURE_ID);

        String xssReportJson = """
                {
                  "observation_summary": "<script>alert(1)</script> H가 X1로 HTTP 요청 전송",
                  "claims": [
                    {"claim": "<img src=x onerror=alert(2)> H의 비정상 HTTP 호출", "fact_ids": ["F99"]}
                  ],
                  "possible_explanations": [
                    {"explanation": "<!-- injected --> X1에서 H로 역접속 가능성", "fact_ids": ["F99"], "attack_ids": ["T1071"]}
                  ],
                  "send_recommendation": {
                    "choice": "send",
                    "reason": "H와 X1 간 위험 행위 <script>bad()</script>",
                    "fact_ids": ["F99"]
                  },
                  "limitations": ["<b onmouseover=alert(3)>한계</b>"],
                  "follow_up": ["X1 로그 확인 <script>alert(4)</script>"]
                }
                """;
        String xssFactsJson = """
                [{"id": "F99", "name": "http_uri", "value": "<script>alert('fact')</script> /login"}]
                """;

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_reports (
                    job_id, incident_id, zeekad_report_kind, zeekad_report_version, zeekad_input_version,
                    zeekad_report, zeekad_verification_passed, zeekad_verification_reason, zeekad_verification_problems,
                    llm_model_requested, llm_model_version, llm_seconds, llm_input_tokens, llm_output_tokens, llm_thinking_tokens,
                    llm_error, zeekad_attack_candidates, zeekad_source_run, created_at, zeekad_facts, zeekad_pseudonyms
                ) VALUES (
                    ?, ?, 'llm', 'llm-report.v1', 'evidence.v1',
                    ? FORMAT JSON, FALSE, 'failed_check <script>r()</script>', '["<img src=x onerror=alert(5)>"]' FORMAT JSON,
                    'gemini-2.5-pro', 'gemini-2.5-pro-002', 1.2, 500, 200, 100,
                    NULL, '[{"attack_id": "T1071", "name": "Application Layer Protocol", "tactics": ["Command and Control"]}]' FORMAT JSON,
                    'run-xss', TIMESTAMP WITH TIME ZONE '2026-11-17 02:05:00Z',
                    ? FORMAT JSON,
                    '{"H": "192.168.77.10", "X1": "203.0.113.99"}' FORMAT JSON
                )
                """, XSS_JOB_ID, XSS_INC_ID, xssReportJson, xssFactsJson);

        String analyst = "xss_analyst_1";
        userAdminService.createUser(analyst, "보안분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        MvcResult result = mockMvc.perform(get("/incidents/{jobId}/rank/1", XSS_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("H(192.168.77.10)가 X1(203.0.113.99)로 HTTP 요청 전송")))
                .andExpect(content().string(containsString("&lt;script&gt;alert(1)&lt;/script&gt;")))
                .andExpect(content().string(containsString("&lt;img src=x onerror=alert(2)&gt;")))
                .andExpect(content().string(containsString("&lt;svg onload=alert(&quot;ntlm&quot;)&gt;")))
                .andExpect(content().string(containsString("&lt;script&gt;alert(&quot;host&quot;)&lt;/script&gt;")))
                .andExpect(content().string(containsString("검증 실패")))
                .andReturn();

        String html = result.getResponse().getContentAsString();
        assertThat(html).doesNotContain("<script>");
        assertThat(html).doesNotContain("<img src=x");
        assertThat(html).doesNotContain("<svg onload=");
        assertThat(html).doesNotContain("<!-- injected -->");
        assertThat(html).doesNotContain("style=\"");
    }

    @Test
    void labMultiJobDetailJoinsByReportJobIdAndShowsNoReportWhenNull() throws Exception {
        String labAnalyst = "lab_detail_analyst";
        userAdminService.createUser(labAnalyst, "실습상세분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(labAnalyst, "Pass1234!");

        // 1. job 502 rank 1 (zeekad_report_job_id == null -> 보고서 없음, 판단 없음, Slack 없음)
        mockMvc.perform(get("/incidents/502/rank/1").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.0.25")))
                .andExpect(content().string(containsString("1 / 3")))
                .andExpect(content().string(containsString("보고서 없음")))
                .andExpect(content().string(containsString("전송 판단 기록 없음")))
                .andExpect(content().string(containsString("Slack 전송 기록 없음")));
        assertThat(lastEvidencePath.get()).isEqualTo("/api/v1/jobs/502/incidents/1");

        // 2. job 502 rank 2 (큐·모델점수·근거 API는 502, 보고서·판단·Slack은 501, 상태·이력은 incident_id 기준)
        mockMvc.perform(get("/incidents/502/rank/2").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("job #502")))
                .andExpect(content().string(containsString("보고 작업 job #501")))
                .andExpect(content().string(containsString("5 / 6")))
                .andExpect(content().string(containsString("4 / 6")))
                .andExpect(content().string(containsString("실습망 H(10.20.0.15)에서 I1(10.20.0.99)로 비정상 인증 시도")))
                .andExpect(content().string(containsString("F1 (lab_conn_count)")))
                .andExpect(content().string(containsString("최종 판단: 전송")))
                .andExpect(content().string(containsString("기록만(dry-run)")))
                .andExpect(content().string(containsString("현재 상태: investigating")))
                .andExpect(content().string(containsString("실습망 초기 조사 시작")))
                .andExpect(content().string(containsString("job #501")));
        assertThat(lastEvidencePath.get()).isEqualTo("/api/v1/jobs/502/incidents/2");
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
