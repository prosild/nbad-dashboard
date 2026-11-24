package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.MaskingService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T42: 근거 조회 API가 깨진 응답을 줘도 상세는 200이고 증적만 "불러오지 못함"이다.
 * 리포트·발송 판단·Slack·이력은 그대로 나오고, 조회자 응답에 가리지 않은 IPv4가 없으며,
 * 근거 API 응답 본문(표지 글)이 로그와 응답 어디에도 없다.
 *
 * <p>가짜 근거 서버는 소켓에 바이트를 그대로 쓴다(HTTP가 아닌 바이트·깨진 상태 줄을 만들기 위해서다).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class T42EvidenceBrokenResponseIntegrationTest {

    /** portfolio-verify.ps1의 IPv4 검사와 같은 패턴(네 옥텟이 모두 숫자). */
    private static final Pattern UNMASKED_IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");
    private static final String ECHO = "ECHO";

    /** ECHO면 받은 요청을 그대로 되돌려 준다. 그 밖이면 이 바이트를 그대로 쓰고 연결을 닫는다. */
    private static final AtomicReference<String> rawResponse = new AtomicReference<>();
    private static ServerSocket evidenceSocket;
    private static Thread acceptThread;

    @DynamicPropertySource
    static void registerEvidenceApiUrl(DynamicPropertyRegistry registry) throws IOException {
        evidenceSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        acceptThread = new Thread(T42EvidenceBrokenResponseIntegrationTest::acceptLoop, "t42-evidence-stub");
        acceptThread.setDaemon(true);
        acceptThread.start();
        int port = evidenceSocket.getLocalPort();
        registry.add("dashboard.evidence-api.url", () -> "http://127.0.0.1:" + port);
    }

    private static void acceptLoop() {
        while (!evidenceSocket.isClosed()) {
            try (Socket socket = evidenceSocket.accept()) {
                byte[] request = readRequestHead(socket.getInputStream());
                OutputStream out = socket.getOutputStream();
                String mode = rawResponse.get();
                if (mode == null || ECHO.equals(mode)) {
                    out.write(request);
                } else {
                    out.write(mode.getBytes(StandardCharsets.UTF_8));
                }
                out.flush();
            } catch (IOException ignored) {
                // 소켓을 닫으면 accept가 끝난다.
            }
        }
    }

    private static byte[] readRequestHead(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int matched = 0;
        byte[] end = {'\r', '\n', '\r', '\n'};
        int b;
        while ((b = in.read()) != -1) {
            buf.write(b);
            matched = (b == end[matched]) ? matched + 1 : (b == '\r' ? 1 : 0);
            if (matched == end.length) {
                break;
            }
        }
        return buf.toByteArray();
    }

    private static String http(int status, String reason, String contentType, String body) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + bytes.length + "\r\n"
                + "Connection: close\r\n\r\n" + body;
    }

    @AfterAll
    static void stopEvidenceServer() throws IOException {
        if (evidenceSocket != null) {
            evidenceSocket.close();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @MockitoSpyBean
    private MaskingService maskingService;

    private static boolean usersCreated;
    private MockHttpSession analystSession;
    private MockHttpSession viewerSession;

    @BeforeEach
    void setUp() throws Exception {
        rawResponse.set(null);
        if (!usersCreated) {
            userAdminService.createUser("t42_ev_analyst", "T42분석가", "Pass1234!", UserRole.ANALYST,
                    "cic17-*", "seed", "ADMIN", "127.0.0.1");
            userAdminService.createUser("t42_ev_viewer", "T42조회자", "Pass1234!", UserRole.VIEWER,
                    "cic17-*", "seed", "ADMIN", "127.0.0.1");
            usersCreated = true;
        }
        analystSession = loginAs("t42_ev_analyst");
        viewerSession = loginAs("t42_ev_viewer");
    }

    @AfterEach
    void tearDown() {
        rawResponse.set(null);
    }

    @Test
    void brokenHttpAndMalformedBodiesKeepDetail200WithEvidenceOnlyUnavailable(CapturedOutput output) throws Exception {
        List<String> cases = List.of(
                // (가) HTTP가 아닌 바이트: 받은 요청을 그대로 되돌려 준다(상태 줄이 "GET /api/..."라 상태 -1).
                ECHO,
                // 상태 줄 자리에 표지 글.
                "HTTP/1.1 MARKER_STATUS_LINE oops\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                "MARKER_STATUS_LINE garbage without any http framing\r\n\r\n",
                // 4xx·5xx 본문.
                http(404, "Not Found", "application/json", "{\"detail\":\"MARKER_4XX_BODY evidence-api.internal\"}"),
                http(503, "Service Unavailable", "text/plain", "MARKER_5XX_BODY upstream.internal:5432"),
                // JSON이 아닌 본문(첫 낱말이 표지).
                http(200, "OK", "application/json", "MARKER_NONJSON_FIRST and more text"),
                // (나) 모양이 다른 JSON(값 자리에 표지).
                http(200, "OK", "application/json",
                        "{\"evidence\":{\"connection_count\":7,\"peers\":{\"top\":[\"MARKER_SHAPE_VALUE\"]}}}"),
                http(200, "OK", "application/json",
                        "{\"evidence\":{\"connection_count\":7,\"representative_connections\":[\"MARKER_SHAPE_VALUE\"]}}")
        );
        for (String raw : cases) {
            rawResponse.set(raw);
            for (MockHttpSession session : List.of(analystSession, viewerSession)) {
                String body = assertDetailOkWithEvidenceUnavailable(session);
                assertNoMarkers(body);
                if (session == viewerSession) {
                    assertThat(UNMASKED_IPV4.matcher(body).find()).as("VIEWER 응답에 가려지지 않은 IPv4").isFalse();
                }
            }
        }
        assertNoMarkers(output.getAll());
        assertThat(output.getAll()).contains("폴백 반환");
    }

    @Test
    void assemblyFailureAfterParsingFallsBackWithoutPartialValues(CapturedOutput output) throws Exception {
        // 클라이언트 풀이는 통과하는 JSON. 조립(마스킹)에서 예외가 나는 꼴은 지금 코드에서 찾지 못해
        // 마스킹 단계가 예외를 내게 한다(예외 글에 표지를 둬 로그에 예외 글이 없는지도 본다).
        rawResponse.set(http(200, "OK", "application/json", """
                {"evidence":{"connection_count":4242,
                  "peers":{"unique":1,"top":[{"ip":"198.18.42.42","connections":3}]},
                  "protocol_logs":{"dns":{"queries":1}},
                  "representative_connections":[{"source":{"ip":"198.18.42.42"}}],
                  "limits":["198.18.42.42"], "extra_marker":"MARKER_ASSEMBLY_VALUE"}}
                """));
        Mockito.doThrow(new IllegalStateException("MARKER_ASSEMBLY_MESSAGE"))
                .when(maskingService).maskEvidence(ArgumentMatchers.any(), ArgumentMatchers.any());

        for (MockHttpSession session : List.of(analystSession, viewerSession)) {
            String body = assertDetailOkWithEvidenceUnavailable(session);
            assertThat(body)
                    .doesNotContain("4242")
                    .doesNotContain("198.18.42.42")
                    .doesNotContain("198.18.*.*")
                    .doesNotContain("MARKER_ASSEMBLY_VALUE")
                    .doesNotContain("MARKER_ASSEMBLY_MESSAGE");
            if (session == viewerSession) {
                assertThat(UNMASKED_IPV4.matcher(body).find()).as("VIEWER 응답에 가려지지 않은 IPv4").isFalse();
            }
        }
        assertThat(output.getAll())
                .doesNotContain("MARKER_ASSEMBLY_MESSAGE")
                .doesNotContain("MARKER_ASSEMBLY_VALUE")
                .contains("증적 조립 실패(폴백 반환): java.lang.IllegalStateException");
    }

    @Test
    void oddButParsableShapesDoNotBreakAssemblyAndStayMaskedForViewer() throws Exception {
        // 인계가 예로 든 꼴(대표 연결 행의 값이 객체, protocol_logs 값이 배열)은 지금 코드에서 예외가 나지 않는다.
        // 상세는 200이고 증적은 정상으로 나오며 조회자에게는 가려진다.
        rawResponse.set(http(200, "OK", "application/json", """
                {"evidence":{"connection_count":5,
                  "representative_connections":[{"source":{"ip":{"nested":"198.18.7.7"}},"destination":[["198.18.7.8"]]}],
                  "protocol_logs":{"dns":["198.18.7.9"],"weird":[{"x":"198.18.7.10"}],"http":"198.18.7.11"},
                  "peers":{"top":[{"ip":["198.18.7.12"]}]},
                  "host":["198.18.7.13"], "limits":{"a":"198.18.7.14"}}}
                """));
        mockMvc.perform(get("/api/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(true))
                .andExpect(jsonPath("$.detail.evidence.connectionCount").value(5));
        MvcResult res = mockMvc.perform(get("/api/incidents/101/rank/1").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(true))
                .andReturn();
        String body = res.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(UNMASKED_IPV4.matcher(body).find()).as("VIEWER 응답에 가려지지 않은 IPv4").isFalse();
    }

    @Test
    void normalEvidenceResponseIsUnchangedAndWritesNoFallbackLog(CapturedOutput output) throws Exception {
        rawResponse.set(http(200, "OK", "application/json", EvidenceApiClientTest.readSample()));
        mockMvc.perform(get("/api/incidents/101/rank/1").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(true))
                .andExpect(jsonPath("$.detail.evidence.connectionCount").value(155261));
        assertThat(output.getAll()).doesNotContain("폴백 반환");
    }

    private String assertDetailOkWithEvidenceUnavailable(MockHttpSession session) throws Exception {
        ResultActions actions = mockMvc.perform(get("/api/incidents/101/rank/1").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.evidence.available").value(false))
                .andExpect(jsonPath("$.detail.evidence.statusMessage").value(EvidenceData.FALLBACK_MESSAGE))
                .andExpect(jsonPath("$.detail.evidence.connectionCount").doesNotExist())
                .andExpect(jsonPath("$.detail.evidence.topPeers").isEmpty())
                .andExpect(jsonPath("$.detail.evidence.protocolLogs").isEmpty())
                .andExpect(jsonPath("$.detail.evidence.representativeConnections").isEmpty())
                .andExpect(jsonPath("$.detail.evidence.limits").isEmpty())
                .andExpect(jsonPath("$.detail.evidence.additionalFields").isEmpty())
                // 상세의 다른 부분은 그대로 나온다.
                .andExpect(jsonPath("$.detail.incident").exists())
                .andExpect(jsonPath("$.detail.report.present").value(true))
                .andExpect(jsonPath("$.detail.report.llmModelVersion").value("gemini-2.5-pro-001"))
                .andExpect(jsonPath("$.detail.sendDecision").exists())
                .andExpect(jsonPath("$.detail.slackDeliveries[0]").exists())
                .andExpect(jsonPath("$.detail.statusHistory").isArray());
        return actions.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static void assertNoMarkers(String text) {
        assertThat(text)
                .doesNotContain("MARKER_STATUS_LINE")
                .doesNotContain("MARKER_4XX_BODY")
                .doesNotContain("MARKER_5XX_BODY")
                .doesNotContain("MARKER_NONJSON_FIRST")
                .doesNotContain("MARKER_SHAPE_VALUE")
                .doesNotContain("evidence-api.internal")
                .doesNotContain("upstream.internal");
    }

    private MockHttpSession loginAs(String username) throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        Cookie csrfCookie = csrf.getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
