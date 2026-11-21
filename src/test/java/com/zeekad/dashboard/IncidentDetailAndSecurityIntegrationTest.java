package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.dto.IncidentTransitionRequest;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
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
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
    /** null이 아니면 가짜 근거 서버가 이 본문을 200으로 준다(실제 표본·근거 없음 응답 시험용). */
    private static final java.util.concurrent.atomic.AtomicReference<String> evidenceServerBodyOverride =
            new java.util.concurrent.atomic.AtomicReference<>();
    /** portfolio-verify.ps1의 IPv4 검사와 같은 패턴(네 옥텟이 모두 숫자). */
    private static final Pattern UNMASKED_IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");

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
            // T16: 옛 가짜 키(orig_bytes·transport_counts·ports·limitations 등)를 zeek_AD evidence.v1 실제 키로 바꿨다.
            String payload = evidenceServerBodyOverride.get() != null ? evidenceServerBodyOverride.get() : """
                    {
                      "evidence": {
                        "version": "evidence.v1",
                        "host": {"ip": "192.168.10.50"},
                        "zeekad_role": "originator",
                        "connection_count": 412,
                        "network": {
                          "bytes": {"sent": 98304, "received": 524288},
                          "transport": {"tcp": 390, "udp": 22},
                          "protocol": {"krb": 195, "dns": 12},
                          "zeekad_payload_bytes_inflated": 0
                        },
                        "zeek_conn_state": {"SF": 300, "S0": 112},
                        "peers": {"unique": 1, "top": [{"ip": "203.0.113.45", "connections": 210}]},
                        "destination_ports": {"unique": 1, "top": [{"port": 88, "transport": "tcp", "connections": 195}]},
                        "protocol_logs": {
                          "dns": {"queries": 12, "nxdomain": 0, "max_query_length": 30},
                          "kerberos": {"requests": 195, "failures": 0},
                          "dce_rpc": {"calls": 3, "top_operations": [{"operation": "NetrShareEnum", "connections": 3}]}
                        },
                        "representative_connections": [
                          {"source": {"ip": "192.168.10.50", "port": 50000}, "destination": {"ip": "203.0.113.45", "port": 88}}
                        ],
                        "limits": ["수집 구간 10.20.30.99 일부 패킷 손실"]
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
    private ObjectMapper objectMapper;

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
        evidenceServerBodyOverride.set(null);
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanupXssFixture();
    }

    @AfterEach
    void tearDown() {
        evidenceServerShouldFail.set(false);
        evidenceServerBodyOverride.set(null);
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
        MvcResult rank1Res = mockMvc.perform(get("/api/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(jsonPath("$.maskedView").value(false))
                .andExpect(jsonPath("$.canDecideReview").value(true))
                .andExpect(jsonPath("$.detail.incident.hostIp").value("192.168.10.50"))
                .andExpect(jsonPath("$.detail.modelScores[0].windowRatioLabel").value("3 / 6"))
                .andExpect(jsonPath("$.detail.modelScores[1].windowRatioLabel").value("4 / 6"))
                .andExpect(content().string(not(containsString("0.91")))) // max_score 직접 비교/노출 금지
                .andExpect(content().string(containsString("admin")))
                .andExpect(content().string(containsString("svc_ad_sync")))
                .andExpect(content().string(containsString("source_log")))
                .andExpect(jsonPath("$.detail.evidence.connectionCount").value(412))
                .andExpect(content().string(containsString("203.0.113.45")))
                .andExpect(content().string(containsString("dce_rpc")))
                .andExpect(jsonPath("$.detail.report.llmModelVersion").value("gemini-2.5-pro-001"))
                .andExpect(content().string(containsString("H(192.168.10.50)에서 X1(203.0.113.45)로")))
                .andExpect(content().string(containsString("T1558")))
                .andExpect(jsonPath("$.detail.sendDecision.decisionModelConfidence").value(0.84))
                .andExpect(content().string(not(containsString("정확도"))))
                .andExpect(content().string(not(containsString("신뢰도 %"))))
                .andExpect(jsonPath("$.detail.slackDeliveries[0].dryRunOrRecorded").value(true))
                .andExpect(jsonPath("$.detail.slackDeliveries[0].threadRoleLabel").value("최초 알림"))
                .andExpect(jsonPath("$.detail.slackDeliveries[1].threadRoleLabel").value("후속 알림"))
                .andExpect(jsonPath("$.detail.slackDeliveries[1].replyBroadcast").value(true))
                .andExpect(jsonPath("$.detail.analystReview.present").value(true))
                .andExpect(jsonPath("$.detail.analystReview.resumeStatusLabel").value("반영됨"))
                .andReturn();
        assertThat(rank1Res.getResponse().getContentAsString()).doesNotContain("<script>");

        // INCIDENT_VIEW_UNMASKED 감사 로그 확인
        List<AuditLog> unmaskedLogs = auditLogMapper.findFiltered(
                AuditActionType.INCIDENT_VIEW_UNMASKED.name(), analyst, 10);
        assertThat(unmaskedLogs).hasSize(1);
        assertThat(unmaskedLogs.get(0).getTargetJobId()).isEqualTo(101L);

        // 2. job 101 rank 2 (템플릿 보고서 null 안전 + 세 의견 불일치 + 이력 display_name)
        mockMvc.perform(get("/api/incidents/101/rank/2").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.report.reportVersion").value("template.v1"))
                .andExpect(content().string(containsString("H(10.20.30.40)의 SMB 응답 트래픽 증가")))
                .andExpect(jsonPath("$.detail.sendDecision.opinionMismatch").value(true))
                .andExpect(jsonPath("$.detail.report.sendRecommendation").doesNotExist());

        // 3. job 101 rank 3 (보고서 없음)
        mockMvc.perform(get("/api/incidents/101/rank/3").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.report.present").value(false));

        // 4. FastAPI 장애 시 폴백 배너 + DB 뷰 정보 정상 반환
        evidenceServerShouldFail.set(true);
        mockMvc.perform(get("/api/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(false))
                .andExpect(jsonPath("$.detail.evidence.statusMessage").value("상세 증적을 불러오지 못했습니다. 기본 정보만 표시합니다."))
                .andExpect(content().string(containsString("H(192.168.10.50)에서 X1(203.0.113.45)로")))
                .andExpect(content().string(containsString("gemini-2.5-pro")));

        // 5. ADMIN(TOTP 완료)도 상세 조회 시 INCIDENT_VIEW_UNMASKED 기록 확인
        String adminUser = "detail_admin_1";
        userAdminService.createUser(adminUser, "상세관리자", "AdminPass!99", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser admin = userMapper.findByUsername(adminUser);
        MockHttpSession adminSession = loginAs(adminUser, "AdminPass!99");
        String totpCode = totpService.generateCode(admin.getTotpSecret(), clock.instant());
        Cookie csrfCookie = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(adminSession)
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(totpCode))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/incidents/201/rank/1").session(adminSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.hostIp").value("10.99.88.77"));
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
        MvcResult viewerRes = mockMvc.perform(get("/api/incidents/101/rank/1").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(true))
                .andExpect(jsonPath("$.canDecideReview").value(false))
                .andExpect(jsonPath("$.detail.canTransition").value(false))
                .andExpect(jsonPath("$.detail.analystReview.canDecide").value(false))
                .andExpect(content().string(containsString("192.168.*.*")))
                .andExpect(content().string(containsString("203.0.*.*")))
                .andExpect(content().string(containsString("10.20.*.*")))
                .andExpect(jsonPath("$.detail.assetNames[0].kerberosUser").value("a***"))
                .andExpect(jsonPath("$.detail.assetNames[0].ntlmUser").value("s***"))
                .andExpect(content().string(containsString("H(192.168.*.*)에서 X1(203.0.*.*)로")))
                .andExpect(content().string(not(containsString("192.168.10.50"))))
                .andExpect(content().string(not(containsString("203.0.113.45"))))
                .andExpect(content().string(not(containsString("10.20.30.99"))))
                .andExpect(content().string(not(containsString("svc_ad_sync"))))
                .andReturn();
        assertThat(viewerRes.getResponse().getContentAsString()).doesNotContain("\"admin\"");

        // VIEWER가 다른 사건의 thread_parent에 포함된 원문 IP도 마스킹되는지 확인 (101/rank/2 -> 타 인시던트 후속 알림)
        mockMvc.perform(get("/api/incidents/101/rank/2").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.slackDeliveries[0].threadRoleLabel").value("타 인시던트 후속 알림"))
                .andExpect(content().string(containsString("192.168.*.*")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));

        // VIEWER는 INCIDENT_VIEW_UNMASKED 로그가 남지 않아야 함
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), viewer, 10))
                .isEmpty();

        // VIEWER가 허용된 캡처의 상태 변경 POST 시도 -> 403 Forbidden
        Cookie csrfCookie = fetchCsrfCookie();
        mockMvc.perform(post("/api/incidents/101/rank/1/transition")
                        .session(viewerSession)
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "권한 없는 변경 시도"))))
                .andExpect(status().isForbidden());

        // 미허용 캡처(job 201, syn1-tue) 상세 조회 및 상태 변경 시도 -> 403 + ACCESS_DENIED_IDOR
        mockMvc.perform(get("/api/incidents/201/rank/1").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/incidents/201/rank/1/transition")
                        .session(viewerSession)
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new IncidentTransitionRequest("investigating", null, "타 캡처 변경 시도"))))
                .andExpect(status().isForbidden());

        // 존재하지 않는 queueRank / jobId 접근 -> 403 + ACCESS_DENIED_IDOR
        mockMvc.perform(get("/api/incidents/101/rank/999").session(viewerSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/999999/rank/1").session(viewerSession))
                .andExpect(status().isForbidden());

        List<AuditLog> idorLogs = auditLogMapper.findFiltered(
                AuditActionType.ACCESS_DENIED_IDOR.name(), viewer, 20);
        assertThat(idorLogs).hasSize(4);
    }

    @Test
    void realEvidenceSampleIsStructuredForAnalystAndFullyMaskedButFilledForViewer() throws Exception {
        evidenceServerBodyOverride.set(EvidenceApiClientTest.readSample());

        String analyst = "evidence_sample_analyst";
        userAdminService.createUser(analyst, "근거분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");
        mockMvc.perform(get("/api/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(true))
                .andExpect(jsonPath("$.detail.evidence.bytesSent").value(1791339786L))
                .andExpect(jsonPath("$.detail.evidence.topPeers[0].ip").value("172.16.0.1"))
                .andExpect(jsonPath("$.detail.evidence.representativeConnections[0].source.ip").value("172.16.0.1"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.ip").value("192.168.10.50"));

        String viewer = "evidence_sample_viewer";
        userAdminService.createUser(viewer, "근거조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");
        MvcResult viewerRes = mockMvc.perform(get("/api/incidents/101/rank/1").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(true))
                .andExpect(jsonPath("$.detail.evidence.available").value(true))
                .andExpect(jsonPath("$.detail.evidence.connectionCount").value(155261))
                .andExpect(jsonPath("$.detail.evidence.bytesSent").value(1791339786L))
                .andExpect(jsonPath("$.detail.evidence.bytesReceived").value(123985880))
                .andExpect(jsonPath("$.detail.evidence.payloadBytesInflated").value(724))
                .andExpect(jsonPath("$.detail.evidence.transportCounts.tcp").value(155221))
                .andExpect(jsonPath("$.detail.evidence.serviceProtocolCounts.http").value(147460))
                .andExpect(jsonPath("$.detail.evidence.connStateCounts.RSTO").value(91898))
                .andExpect(jsonPath("$.detail.evidence.uniquePeers").value(12))
                .andExpect(jsonPath("$.detail.evidence.uniquePorts").value(27))
                .andExpect(jsonPath("$.detail.evidence.topPorts[2].transport").value("udp"))
                .andExpect(jsonPath("$.detail.evidence.topPeers[0].ip").value("172.16.*.*"))
                .andExpect(jsonPath("$.detail.evidence.topPeers[0].connections").value(155111))
                .andExpect(jsonPath("$.detail.evidence.representativeConnections.length()").value(10))
                .andExpect(jsonPath("$.detail.evidence.representativeConnections[0].source.ip").value("172.16.*.*"))
                .andExpect(jsonPath("$.detail.evidence.protocolLogs.length()").value(9))
                .andExpect(jsonPath("$.detail.evidence.protocolLogs[0].protocol").value("dns"))
                .andExpect(jsonPath("$.detail.evidence.protocolLogs[0].metrics.queries").value(80))
                .andExpect(jsonPath("$.detail.evidence.protocolLogs[?(@.protocol == 'dce_rpc')].metrics.top_operations[0].operation")
                        .value("NetrShareEnum"))
                .andExpect(jsonPath("$.detail.evidence.limits.length()").value(4))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.version").value("evidence.v1"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.ip").value("192.168.*.*"))
                .andReturn();
        assertThat(UNMASKED_IPV4.matcher(viewerRes.getResponse().getContentAsString()).find())
                .as("VIEWER 상세 응답에 가려지지 않은 IPv4")
                .isFalse();
    }

    @Test
    void evidenceLimitsWithIpv4AreMaskedForViewerAndRawForAnalyst() throws Exception {
        // 표본의 limits에는 IPv4가 없어 기본 가짜 응답(limits에 10.20.30.99 문장)으로 시험한다.
        String analyst = "evidence_limits_analyst";
        userAdminService.createUser(analyst, "한계분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(analyst, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.limits[0]").value("수집 구간 10.20.30.99 일부 패킷 손실"));

        String viewer = "evidence_limits_viewer";
        userAdminService.createUser(viewer, "한계조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(viewer, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.limits[0]").value("수집 구간 10.20.*.* 일부 패킷 손실"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.ip").value("192.168.*.*"));
    }

    @Test
    void nullOrMissingEvidenceShowsNoEvidenceWithoutLeakingTopLevelFields() throws Exception {
        String topLevel = """
                "zeekad_job_id": 101,
                "zeekad_rank": 1,
                "host": {"ip": "198.51.100.77", "name": ["LEAK-HOST-NAME$"]},
                "zeekad_role": "originator",
                "detection": {"zeekad_picked_by": "leak_detection_marker", "models": []},
                "zeekad_asset_observations": [
                  {"zeekad_name_kind": "kerberos_user", "zeekad_name": "leak_krb_user", "zeekad_source_log": "kerberos.log"}
                ],
                "connection_count": 999
                """;
        String viewer = "evidence_none_viewer";
        userAdminService.createUser(viewer, "근거없음조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");

        for (String body : List.of("{" + topLevel + ", \"evidence\": null}", "{" + topLevel + "}")) {
            evidenceServerBodyOverride.set(body);
            MvcResult res = mockMvc.perform(get("/api/incidents/101/rank/1").session(viewerSession))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.detail.evidence.available").value(false))
                    .andExpect(jsonPath("$.detail.evidence.statusMessage").value(EvidenceData.NO_EVIDENCE_MESSAGE))
                    .andExpect(jsonPath("$.detail.evidence.connectionCount").doesNotExist())
                    .andExpect(jsonPath("$.detail.evidence.additionalFields").isEmpty())
                    .andReturn();
            String content = res.getResponse().getContentAsString();
            assertThat(content)
                    .doesNotContain("leak_detection_marker")
                    .doesNotContain("leak_krb_user")
                    .doesNotContain("LEAK-HOST-NAME$")
                    .doesNotContain("198.51.100.77")
                    .doesNotContain("198.51.*.*");
            assertThat(UNMASKED_IPV4.matcher(content).find()).as("VIEWER 응답에 가려지지 않은 IPv4").isFalse();
        }
        assertThat(EvidenceData.NO_EVIDENCE_MESSAGE).isNotEqualTo(EvidenceData.FALLBACK_MESSAGE);
    }

    @Test
    void untrustedReportAndLogInputsSerializeSafelyAsJsonWithNoSniffAndSinglePassPseudonyms() throws Exception {
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

        MvcResult result = mockMvc.perform(get("/api/incidents/{jobId}/rank/1", XSS_JOB_ID).session(session))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", containsString("application/json")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(jsonPath("$.detail.report.verificationPassed").value(false))
                .andReturn();

        JsonNode root = objectMapper.readTree(result.getResponse().getContentAsString());
        JsonNode detail = root.get("detail");
        assertThat(detail.get("incident").get("hostName").get(0).asText())
                .isEqualTo("<script>alert(\"host\")</script>");
        assertThat(detail.get("assetNames").get(0).get("ntlmUser").asText())
                .isEqualTo("<svg onload=alert(\"ntlm\")>");
        assertThat(detail.get("report").get("observationSummary").asText())
                .isEqualTo("<script>alert(1)</script> H(192.168.77.10)가 X1(203.0.113.99)로 HTTP 요청 전송");
    }

    @Test
    void labMultiJobDetailJoinsByReportJobIdAndShowsNoReportWhenNull() throws Exception {
        String labAnalyst = "lab_detail_analyst";
        userAdminService.createUser(labAnalyst, "실습상세분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(labAnalyst, "Pass1234!");

        // 1. job 502 rank 1 (zeekad_report_job_id == null -> 보고서 없음, 판단 없음, Slack 없음)
        mockMvc.perform(get("/api/incidents/502/rank/1").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.hostIp").value("10.20.0.25"))
                .andExpect(jsonPath("$.detail.modelScores[0].windowRatioLabel").value("1 / 3"))
                .andExpect(jsonPath("$.detail.report.present").value(false))
                .andExpect(jsonPath("$.detail.sendDecision.present").value(false))
                .andExpect(jsonPath("$.detail.slackDeliveries.length()").value(0));
        assertThat(lastEvidencePath.get()).isEqualTo("/api/v1/jobs/502/incidents/1");

        // 2. job 502 rank 2 (큐·모델점수·근거 API는 502, 보고서·판단·Slack은 501, 상태·이력은 incident_id 기준)
        mockMvc.perform(get("/api/incidents/502/rank/2").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.jobId").value(502))
                .andExpect(jsonPath("$.detail.incident.zeekadReportJobId").value(501))
                .andExpect(jsonPath("$.detail.modelScores[0].windowRatioLabel").value("4 / 6"))
                .andExpect(jsonPath("$.detail.modelScores[1].windowRatioLabel").value("5 / 6"))
                .andExpect(content().string(containsString("실습망 H(10.20.0.15)에서 I1(10.20.0.99)로 비정상 인증 시도")))
                .andExpect(jsonPath("$.detail.sendDecision.wouldSend").value(true))
                .andExpect(jsonPath("$.detail.slackDeliveries[0].dryRunOrRecorded").value(true))
                .andExpect(jsonPath("$.detail.currentStatus").value("investigating"))
                .andExpect(jsonPath("$.detail.statusHistory[0].jobId").value(501))
                .andExpect(jsonPath("$.detail.statusHistory[0].reason").value("실습망 초기 조사 시작"));
        assertThat(lastEvidencePath.get()).isEqualTo("/api/v1/jobs/502/incidents/2");
    }

    @Test
    void fusionV3Over30MinutesAndSlackLookupWithoutReportJobIdReturnCorrectJson() throws Exception {
        String labAnalyst = "fusion_detail_analyst";
        userAdminService.createUser(labAnalyst, "결합분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(labAnalyst, "Pass1234!");

        // 1. zeekad-fusion/3 45분 사건 + 보고서 재생성(602) 뒤에도 처음 작업(601) Slack 기록 조회
        mockMvc.perform(get("/api/incidents/602/rank/1").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.bundleId").value("zeekad-fusion/3"))
                .andExpect(jsonPath("$.detail.incident.zeekadReportJobId").value(602))
                .andExpect(content().string(containsString("2026-11-19T01:00")))
                .andExpect(content().string(containsString("2026-11-19T01:45")))
                .andExpect(content().string(containsString("결합 v2 경보: 10.40.0.10 -> 10.40.0.99")))
                .andExpect(jsonPath("$.detail.slackDeliveries[0].jobId").value(601));

        // 2. reportJobId == null 이더라도 incident_id 단독으로 Slack 기록 조회
        String noReportIncident = "lab-20261118|10.20.0.25|responder|1763424300";
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_slack_deliveries (
                    job_id, incident_id, zeekad_message_kind, zeekad_message_version, zeekad_delivery_mode,
                    zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at,
                    zeekad_thread_parent, zeekad_reply_broadcast
                ) VALUES (
                    502, ?, 'status', 'status.v1', 'dry_run', 'recorded',
                    '{"channel": "#lab-alerts", "text": "보고서 없는 사건 상태 Slack 알림: 10.20.0.25"}' FORMAT JSON,
                    NULL, NULL, NULL, TIMESTAMP WITH TIME ZONE '2026-11-18 00:12:00Z',
                    NULL, FALSE
                )
                """, noReportIncident);
        try {
            mockMvc.perform(get("/api/incidents/502/rank/1").session(session))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.detail.report.present").value(false))
                    .andExpect(content().string(containsString("보고서 없는 사건 상태 Slack 알림: 10.20.0.25")));
        } finally {
            zeekadJdbc.update("DELETE FROM dashboard.raw_slack_deliveries WHERE incident_id = ?", noReportIncident);
        }
    }

    /** T21: 증적 추가 필드 host 하위 키 허용 목록. VIEWER에는 마스킹된 ip만, ANALYST에는 원문 그대로 셋 다. */
    @Test
    void evidenceHostSubkeysAreAllowListedForViewerOnly() throws Exception {
        evidenceServerBodyOverride.set("""
                {
                  "evidence": {
                    "version": "evidence.v1",
                    "host": {"ip": "192.168.10.50", "name": ["T21-LEAK-NAME.corp.local"], "hostname": "T21-LEAK-HOSTNAME"},
                    "connection_count": 412
                  }
                }
                """);
        String analyst = "t21_host_analyst";
        userAdminService.createUser(analyst, "호스트분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(analyst, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.ip").value("192.168.10.50"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.name[0]").value("T21-LEAK-NAME.corp.local"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.hostname").value("T21-LEAK-HOSTNAME"));

        String viewer = "t21_host_viewer";
        userAdminService.createUser(viewer, "호스트조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MvcResult res = mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(viewer, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.ip").value("192.168.*.*"))
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.name").doesNotExist())
                .andExpect(jsonPath("$.detail.evidence.additionalFields.host.hostname").doesNotExist())
                .andReturn();
        JsonNode host = objectMapper.readTree(res.getResponse().getContentAsString())
                .at("/detail/evidence/additionalFields/host");
        assertThat(host.size()).isEqualTo(1);
        assertThat(res.getResponse().getContentAsString())
                .doesNotContain("T21-LEAK-NAME")
                .doesNotContain("T21-LEAK-HOSTNAME");
    }

    /** T21: 상태 이력 사유(결정 반영 때 들어간 검토 메모 포함)는 VIEWER에게 IPv4가 가려지고, 분석가에게는 원문이다. */
    @Test
    void statusHistoryReasonIsMaskedForViewer() throws Exception {
        String analyst = "t21_hist_analyst";
        userAdminService.createUser(analyst, "이력분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(analyst, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.currentStatus").value("investigating"))
                .andExpect(jsonPath("$.detail.statusHistory[0].toStatus").value("investigating"))
                .andExpect(jsonPath("$.detail.statusHistory[0].reason")
                        .value("192.168.10.50 도메인 컨트롤러 Kerberos 티켓 요청 급증 확인, 조사 진행"));

        String viewer = "t21_hist_viewer";
        userAdminService.createUser(viewer, "이력조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MvcResult res = mockMvc.perform(get("/api/incidents/101/rank/1").session(loginAs(viewer, "Pass1234!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.statusHistory[0].reason")
                        .value("192.168.*.* 도메인 컨트롤러 Kerberos 티켓 요청 급증 확인, 조사 진행"))
                .andReturn();
        assertThat(UNMASKED_IPV4.matcher(res.getResponse().getContentAsString()).find())
                .as("VIEWER 상세 응답에 가려지지 않은 IPv4")
                .isFalse();
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        Cookie csrfCookie = fetchCsrfCookie();
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
