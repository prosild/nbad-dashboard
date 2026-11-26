package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.T63Attacks;
import com.zeekad.dashboard.testsupport.T63JsonScan;
import com.zeekad.dashboard.testsupport.T63JsonScan.Entry;
import com.zeekad.dashboard.testsupport.T63JsonScan.Kind;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.zeekad.dashboard.testsupport.T63Attacks.ATTACKS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T63: 서버가 내보내는 바깥 글자열을 신뢰하지 않는 입력으로 다루는지 "모든 응답의 모든 글자 값"으로 본다(모의 환경: H2 + MockMvc + 근거 API 흉내).
 *
 * <p>공격 문장 16종(zeek_AD tests/test_prompt_injection.py)과 보이지 않는 글자를 호스트 이름, 관측 계정 세 칸, extraAttributes,
 * 보고서 글 칸, 근거의 글자 잎(로컬 HTTP 서버), Slack 페이로드 글, 사람이 쓴 메모·사유, 표시 이름, 감사 로그에 넣고
 * 큐(목록·이웃·새 건수), 옛 목록 API, 상세, 같은 호스트 인시던트, 호스트 위험도, 현황판, 운영 현황, 에스컬레이션 목록, 감사 로그를
 * 분석가·조회자(감사 로그는 관리자)로 받아 스트리밍 파서로 모든 키와 글자 값을 훑는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class T63UntrustedTextIntegrationTest {

    static final String CAP = "t63-inj";
    static final long JOB_FAILED_OLD = 62999L;
    static final long JOB_FAILED = 63000L;
    static final long JOB = 63001L;
    /** 1~16: 공격 문장 i번, 17: 가림 반례·쪼갠 주소·계정, 18: 검색 대상 */
    static final int ATTACK_ROWS = 16;
    static final int MASK_ROW = 17;
    static final int SEARCH_ROW = 18;
    static final String PASSWORD = "Pass1234!";
    static final String ADMIN_SECRET = "JBSWY3DPEHPK3PXP";

    /** 조회자 응답에 가려지지 않은 IPv4(네 옥텟이 모두 숫자)가 없어야 한다(T42와 같은 패턴) */
    static final Pattern UNMASKED_IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");

    private static HttpServer evidenceServer;
    private static String evidenceBody = "{}";

    @DynamicPropertySource
    static void evidenceApi(DynamicPropertyRegistry registry) throws IOException {
        evidenceServer = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        evidenceServer.createContext("/", exchange -> {
            byte[] bytes = evidenceBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        evidenceServer.start();
        int port = evidenceServer.getAddress().getPort();
        registry.add("dashboard.evidence-api.url", () -> "http://127.0.0.1:" + port);
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
    private TotpService totpService;
    @Autowired
    private Clock clock;
    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    private JdbcTemplate zeekadJdbc;
    private MockHttpSession analyst;
    private MockHttpSession viewer;
    private MockHttpSession admin;

    static String incidentId(int i) {
        return CAP + "|10.63.0." + i + "|originator|" + (1700000000 + i);
    }

    static String hostIp(int i) {
        return "10.63.0." + i;
    }

    static String attack(int i) {
        return ATTACKS.get(i - 1);
    }

    /** 표시 이름(trim 뒤 150자 이하) */
    static final String EVIL_A = "t63_evil_a";
    static final String EVIL_B = "t63_evil_b";
    static final String EVIL_A_DISPLAY = T63Attacks.CONTROL;
    static final String EVIL_B_DISPLAY = ATTACKS.get(14) + " ㅤᅟ";

    @BeforeAll
    void seed() throws Exception {
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanupZeekadRows();
        evidenceBody = evidenceJson();

        createUserOnce("t63_analyst", "T63분석가", UserRole.ANALYST, "t63-*");
        createUserOnce("t63_viewer", "T63조회자", UserRole.VIEWER, "t63-*");
        createUserOnce(EVIL_A, EVIL_A_DISPLAY, UserRole.ANALYST, "t63-*");
        createUserOnce(EVIL_B, EVIL_B_DISPLAY, UserRole.ANALYST, "t63-*");
        DashboardUser adminUser = createUserOnce("t63_admin", "T63관리자", UserRole.ADMIN, "*");
        userMapper.updateTotpState(adminUser.getId(), ADMIN_SECRET, true, OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));

        insertJobs();
        for (int i = 1; i <= SEARCH_ROW; i++) {
            insertQueueRow(i);
        }
        for (int i = 1; i <= ATTACK_ROWS; i++) {
            insertAssetRow(i, attack(i), attack(i), attack(i));
            insertReport(i);
            insertSendDecision(i);
            insertSlack(i);
            insertStatus(i);
            insertReview(i);
        }
        insertAssetRow(MASK_ROW, "‮admin", "😀bob", "10.0​.0.1");

        analyst = login("t63_analyst");
        viewer = login("t63_viewer");
        admin = loginAdmin("t63_admin");

        // 사람이 쓴 글·표시 이름: 담당 지정(표시 이름), 대응 조치 메모(500자 상한 안의 문장만)
        MockHttpSession evilA = login(EVIL_A);
        for (int i = 1; i <= 3; i++) {
            postJson(evilA, "/api/incidents/" + JOB + "/rank/" + i + "/assignment",
                    Map.of("assignee", EVIL_B));
        }
        for (int i = 1; i <= ATTACK_ROWS; i++) {
            if (attack(i).codePointCount(0, attack(i).length()) > 500) {
                continue;
            }
            postJson(evilA, "/api/incidents/" + JOB + "/rank/" + i + "/response-actions",
                    Map.of("action", "other", "note", attack(i)));
        }

        // 감사 로그: 없는 사용자 이름으로 로그인 실패(행위자 = 바깥 입력), 허용 밖 캡처 요청(대상 캡처 = 바깥 입력)
        for (String a : ATTACKS) {
            loginFails(a);
        }
        for (String extra : T63Attacks.EXTRA_HIDDEN) {
            loginFails(extra);
        }
        for (int i = 1; i <= ATTACK_ROWS; i++) {
            mockMvc.perform(get("/api/incidents/queue").param("captureId", "zz-" + attack(i)).session(viewer))
                    .andExpect(status().isForbidden());
        }
    }

    @AfterAll
    void cleanup() {
        if (zeekadJdbc != null) {
            cleanupZeekadRows();
        }
        if (evidenceServer != null) {
            evidenceServer.stop(0);
        }
    }

    private void cleanupZeekadRows() {
        for (String table : List.of("raw_incident_queue", "raw_asset_names", "raw_slack_summaries")) {
            zeekadJdbc.update("DELETE FROM dashboard." + table + " WHERE capture_id = ?", CAP);
        }
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id IN (?, ?, ?)", JOB_FAILED_OLD, JOB_FAILED, JOB);
        for (String table : List.of("raw_incident_reports", "raw_send_decisions", "raw_slack_deliveries",
                "raw_incident_status", "raw_incident_status_history", "raw_analyst_review_queue",
                "raw_incident_model_scores")) {
            zeekadJdbc.update("DELETE FROM dashboard." + table + " WHERE incident_id LIKE ?", CAP + "|%");
        }
    }

    /* ───────────────────────── 시험 ───────────────────────── */

    /** 응답 이름 → (분석가 본문, 조회자 본문). 감사 로그는 관리자 본문만 */
    private Map<String, String[]> fetchAll() throws Exception {
        Map<String, String[]> out = new LinkedHashMap<>();
        out.put("queue", both(get("/api/incidents/queue").param("captureId", CAP).param("period", "all").param("size", "100")));
        out.put("neighbors", both(get("/api/incidents/queue/neighbors").param("jobId", String.valueOf(JOB))
                .param("queueRank", "2").param("captureId", CAP).param("period", "all")));
        out.put("new-count", both(get("/api/incidents/queue/new-count").param("captureId", CAP)
                .param("since", "2000-01-01T00:00:00Z")));
        out.put("legacy-list", both(get("/api/incidents").param("captureId", CAP)));
        for (int i = 1; i <= SEARCH_ROW; i++) {
            out.put("detail-" + i, both(get("/api/incidents/" + JOB + "/rank/" + i)));
        }
        out.put("related-host", both(get("/api/incidents/" + JOB + "/rank/1/related-host-incidents")));
        out.put("hosts", both(get("/api/hosts").param("captureId", CAP).param("period", "all")));
        out.put("overview", both(get("/api/dashboard/overview").param("captureId", CAP).param("period", "all")));
        out.put("operations", both(get("/api/operations").param("captureId", CAP)));
        out.put("reviews", both(get("/api/reviews").param("captureId", CAP)));
        out.put("audit-logs", new String[]{lenientBody(admin, get("/api/admin/audit-logs").param("limit", "500"), "관리자"), null});
        out.put("audit-logs-search", new String[]{lenientBody(admin, get("/api/admin/audit-logs")
                .param("actorUsername", "‮normal").param("limit", "50"), "관리자"), null});
        return out;
    }

    /**
     * T63 전부터 조회자에게 가리지 않는 칸(가림 누락. 옛 목록 API의 작업 목록과 상세의 job은 maskScoringJob을 거치지 않는다).
     * 가림을 넓히는 변경이라 이 작업에서 고치지 않고 설계자에게 올렸다(보고서). 숨은 문자 없음·상한 판정은 그대로 받는다.
     */
    private static final List<String> NOT_MASKED_BEFORE_T63 = List.of(".selectedJob.error", ".captureJobs[].error",
            ".detail.job.error");

    /** 이름·글이 실린 응답(분석가는 표지가 있어야, 조회자는 제거 표시가 있어야 한다) */
    private static final List<String> CARRIES_NAMES = List.of("queue", "legacy-list", "detail-1", "detail-11",
            "detail-17", "hosts", "overview", "operations", "reviews", "audit-logs");

    @Test
    void everyStringInEveryResponseFollowsThePolicyForAnalystAndViewer() throws Exception {
        fetchProblems.clear();
        Map<String, String[]> responses = fetchAll();
        List<String> problems = new ArrayList<>(fetchProblems);
        for (Map.Entry<String, String[]> r : responses.entrySet()) {
            String name = r.getKey();
            String analystBody = r.getValue()[0];
            String viewerBody = r.getValue()[1];
            checkCommon(name + "/분석가", analystBody, problems);
            if (CARRIES_NAMES.contains(name)) {
                if (!analystBody.contains("[U+")) {
                    problems.add(name + "/분석가: 숨은 문자의 표지 [U+XXXX]가 하나도 없다");
                }
            }
            if (viewerBody != null) {
                checkCommon(name + "/조회자", viewerBody, problems);
                checkViewer(name, viewerBody, problems);
            }
        }
        // 4,039자 문장: 이름 256, 값 1,000, 글 4,000에서 잘린다
        String queueAnalyst = responses.get("queue")[0];
        expectTruncated(queueAnalyst, "hostName", 256, problems, "queue/분석가");
        String detail12 = responses.get("detail-12")[0];
        expectTruncated(detail12, "observationSummary", 4000, problems, "detail-12/분석가");
        expectTruncated(detail12, "name", 1000, problems, "detail-12/분석가(사실 이름)");
        expectTruncated(responses.get("detail-12")[1], "hostName", 256, problems, "detail-12/조회자");

        assertThat(problems)
                .as("정책을 벗어난 값 %d개:%n%s", problems.size(), summarize(problems))
                .isEmpty();
    }

    @Test
    void identifierFieldsStayRawForAnalystAndCurrentlyMaskedForViewer() throws Exception {
        String queueAnalyst = body(analyst, get("/api/incidents/queue").param("captureId", CAP).param("period", "all").param("size", "100"));
        String queueViewer = body(viewer, get("/api/incidents/queue").param("captureId", CAP).param("period", "all").param("size", "100"));
        List<String> problems = new ArrayList<>();
        Map<String, List<String>> a = valuesByField(queueAnalyst);
        Map<String, List<String>> v = valuesByField(queueViewer);
        for (int i = 1; i <= SEARCH_ROW; i++) {
            expectContains(a, "incidentId", incidentId(i), problems, "분석가 incidentId");
            expectContains(a, "hostIp", hostIp(i), problems, "분석가 hostIp");
            expectContains(v, "incidentId", CAP + "|10.63.*.*|originator|" + (1700000000 + i), problems, "조회자 incidentId");
        }
        expectContains(v, "hostIp", "10.63.*.*", problems, "조회자 hostIp");
        for (Map<String, List<String>> m : List.of(a, v)) {
            expectAllEqual(m, "captureId", CAP, problems);
            expectAllEqual(m, "zeekadPickedBy", "iforest", problems);
            expectAllEqual(m, "zeekadRole", "originator", problems);
        }
        String detailAnalyst = body(analyst, get("/api/incidents/" + JOB + "/rank/1"));
        Map<String, List<String>> d = valuesByField(detailAnalyst);
        expectContains(d, "sourceRun", "run-t63-1", problems, "분석가 sourceRun");
        expectContains(d, "attackId", "T1046", problems, "분석가 attackId");
        expectContains(d, "id", "F1", problems, "분석가 사실 ID");
        expectContains(d, "threadKey", incidentId(1), problems, "분석가 threadKey");
        assertThat(problems).as(String.join("\n", problems)).isEmpty();
    }

    @Test
    void viewerMaskingIsNotWeakerForCounterexamplesSplitAddressesAndAccounts() throws Exception {
        String queueViewer = body(viewer, get("/api/incidents/queue").param("captureId", CAP).param("period", "all").param("size", "100"));
        List<String> hostNames = valuesByField(queueViewer).getOrDefault("hostName", List.of());
        // 원문 가림이 잡는 반례(지운 뒤에는 다섯 마디·앞에 숫자.가 붙어 가림을 비켜 간다)
        assertThat(hostNames).contains("10.0.*.*.5 [보이지 않는 문자 1개 제거]", "7.10.0.*.* [보이지 않는 문자 1개 제거]");
        // 쪼갠 주소: 지운 뒤 가림이 잡는다
        assertThat(hostNames).contains("10.0.*.* [보이지 않는 문자 1개 제거]");
        String detailViewer = body(viewer, get("/api/incidents/" + JOB + "/rank/" + MASK_ROW));
        Map<String, List<String>> fields = valuesByField(detailViewer);
        assertThat(fields.get("kerberosUser")).containsExactly("a*** [보이지 않는 문자 1개 제거]");
        assertThat(fields.get("ntlmUser")).containsExactly("***");
        assertThat(fields.get("zeekad_name")).containsExactly("1*** [보이지 않는 문자 1개 제거]");
        for (String s : T63JsonScan.scan(detailViewer).stream().map(Entry::text).toList()) {
            assertThat(UNMASKED_IPV4.matcher(T63JsonScan.visible(s)).find()).as("조회자 값 %s", s).isFalse();
        }
    }

    /* ───────────────────────── 판정 ───────────────────────── */

    private void checkCommon(String label, String body, List<String> problems) {
        for (Entry e : T63JsonScan.scan(body)) {
            if (e.container()) {
                continue; // 글 안 JSON의 바깥 글: 안쪽 키·값을 따로 훑는다(직렬화된 글은 자르지 않는다)
            }
            Kind kind = T63JsonScan.kindOf(e);
            boolean multiline = kind == Kind.TEXT && !e.key();
            List<String> hidden = T63JsonScan.hidden(e.text(), multiline);
            if (!hidden.isEmpty()) {
                problems.add(label + " " + e.path() + (e.key() ? "(키)" : "") + ": 숨은 문자 " + hidden);
            }
            int length = T63JsonScan.bodyLength(e.text());
            if (length > kind.cap) {
                problems.add(label + " " + e.path() + (e.key() ? "(키)" : "") + ": " + kind + " 상한 " + kind.cap
                        + "을 넘는 " + length + "자");
            }
        }
    }

    private void checkViewer(String name, String body, List<String> problems) {
        if (body.contains("[U+")) {
            problems.add(name + "/조회자: 표지 [U+가 있다");
        }
        if (CARRIES_NAMES.contains(name) && T63JsonScan.scan(body).stream().noneMatch(e -> T63JsonScan.hasRemovalNote(e.text()))) {
            problems.add(name + "/조회자: 제거 표시가 하나도 없다");
        }
        for (Entry e : T63JsonScan.scan(body)) {
            if (NOT_MASKED_BEFORE_T63.stream().anyMatch(e.path()::endsWith)) {
                continue;
            }
            if (UNMASKED_IPV4.matcher(T63JsonScan.visible(e.text())).find()) {
                problems.add(name + "/조회자 " + e.path() + ": 가려지지 않은 IPv4가 보인다");
            }
        }
    }

    private static void expectTruncated(String body, String field, int cap, List<String> problems, String label) {
        boolean found = T63JsonScan.scan(body).stream()
                .anyMatch(e -> !e.key() && field.equals(e.field()) && T63JsonScan.hasTruncationNote(e.text())
                        && T63JsonScan.bodyLength(e.text()) <= cap && T63JsonScan.bodyLength(e.text()) > cap - 12);
        if (!found) {
            problems.add(label + ": " + field + "에 " + cap + "자에서 자른 값(…(N자 생략))이 없다");
        }
    }

    private static Map<String, List<String>> valuesByField(String body) {
        return T63JsonScan.scan(body).stream().filter(e -> !e.key() && e.field() != null)
                .collect(Collectors.groupingBy(Entry::field, LinkedHashMap::new,
                        Collectors.mapping(Entry::text, Collectors.toList())));
    }

    private static void expectContains(Map<String, List<String>> m, String field, String value, List<String> problems,
                                       String label) {
        if (!m.getOrDefault(field, List.of()).contains(value)) {
            problems.add(label + ": " + field + "에 " + value + "가 없다");
        }
    }

    private static void expectAllEqual(Map<String, List<String>> m, String field, String value, List<String> problems) {
        List<String> values = m.getOrDefault(field, List.of());
        if (values.isEmpty() || values.stream().anyMatch(v -> !value.equals(v))) {
            problems.add(field + "가 모두 " + value + "가 아니다: " + values.stream().distinct().limit(3).toList());
        }
    }

    private static String summarize(List<String> problems) {
        Map<String, Long> byResponse = problems.stream()
                .collect(Collectors.groupingBy(p -> p.split(" ", 2)[0].replaceAll(":$", ""), LinkedHashMap::new,
                        Collectors.counting()));
        StringBuilder sb = new StringBuilder("응답별 수: ").append(byResponse).append('\n');
        problems.stream().limit(60).forEach(p -> sb.append("  - ").append(p.length() > 300 ? p.substring(0, 300) + "…" : p).append('\n'));
        return sb.toString();
    }

    /* ───────────────────────── 요청 ───────────────────────── */

    /** 상태가 200이 아니거나 직렬화가 깨진 응답(고치기 전: 짝 없는 서러게이트 등). 판정 목록에 함께 싣는다 */
    private final List<String> fetchProblems = new ArrayList<>();

    private String[] both(MockHttpServletRequestBuilder request) throws Exception {
        return new String[]{lenientBody(analyst, request, "분석가"), lenientBody(viewer, request, "조회자")};
    }

    private String lenientBody(MockHttpSession session, MockHttpServletRequestBuilder request, String who) {
        String uri = request.buildRequest(new org.springframework.mock.web.MockServletContext()).getRequestURI();
        try {
            MvcResult res = mockMvc.perform(request.session(session)).andReturn();
            int code = res.getResponse().getStatus();
            if (code != 200) {
                fetchProblems.add(uri + "/" + who + ": HTTP " + code);
                return "{}";
            }
            return res.getResponse().getContentAsString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            fetchProblems.add(uri + "/" + who + ": 응답 실패 " + e.getClass().getSimpleName() + " "
                    + String.valueOf(e.getMessage()).lines().findFirst().orElse(""));
            return "{}";
        }
    }

    private String body(MockHttpSession session, MockHttpServletRequestBuilder request) throws Exception {
        MvcResult res = mockMvc.perform(request.session(session)).andExpect(status().isOk()).andReturn();
        return res.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private void postJson(MockHttpSession session, String url, Map<String, ?> body) throws Exception {
        Cookie csrf = csrf();
        mockMvc.perform(post(url).session(session).cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body)))
                .andExpect(status().is2xxSuccessful());
    }

    private Cookie csrf() throws Exception {
        return mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn()
                .getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession login(String username) throws Exception {
        Cookie csrf = csrf();
        MvcResult result = mockMvc.perform(post("/api/auth/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private MockHttpSession loginAdmin(String username) throws Exception {
        Cookie csrf = csrf();
        MockHttpSession session = login(username);
        String code = totpService.generateCode(ADMIN_SECRET, clock.instant());
        mockMvc.perform(post("/api/auth/totp/verify").session(session).cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());
        return session;
    }

    private void loginFails(String username) throws Exception {
        Cookie csrf = csrf();
        mockMvc.perform(post("/api/auth/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, "wrong-password"))));
    }

    private DashboardUser createUserOnce(String username, String display, UserRole role, String patterns) {
        DashboardUser existing = userMapper.findByUsername(username);
        if (existing != null) {
            return existing;
        }
        return userAdminService.createUser(username, display, PASSWORD, role, patterns, "seed", "ADMIN", "127.0.0.1");
    }

    /* ───────────────────────── 자료 ───────────────────────── */

    private void insertJobs() {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'failed', TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-20 00:01:00Z', ?, 0)
                """, JOB_FAILED_OLD, CAP, T63Attacks.LONG);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'failed', TIMESTAMP WITH TIME ZONE '2026-11-20 01:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-20 01:01:00Z', ?, 0)
                """, JOB_FAILED, CAP, T63Attacks.CONTROL + " 10.0​.0.9");
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20 02:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-20 02:05:00Z', NULL, ?)
                """, JOB, CAP, SEARCH_ROW);
    }

    private List<String> hostNames(int i) {
        if (i <= ATTACK_ROWS) {
            List<String> names = new ArrayList<>(List.of(attack(i), "srv-" + i));
            if (i <= T63Attacks.EXTRA_HIDDEN.size()) {
                names.add(T63Attacks.EXTRA_HIDDEN.get(i - 1));
            }
            return names;
        }
        if (i == MASK_ROW) {
            return List.of("10.0.0.1​.5", "7.​10.0.0.1", "10.0​.0.1");
        }
        return List.of("web​-ｓｅｒｖｅｒ-63");
    }

    private void insertQueueRow(int i) {
        List<String> names = hostNames(i);
        List<Object> args = new ArrayList<>(List.of(JOB, CAP, i, incidentId(i), hostIp(i)));
        args.add(10 + i);
        args.add(names.toArray(new String[0]));
        zeekadJdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, "
                + "host_ip, zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-20 01:30:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 01:45:00Z', 'iforest', NULL, ?, ?)",
                args.toArray());
    }

    private void insertAssetRow(int i, String kerberos, String ntlm, String name) {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_asset_names (capture_id, host_ip, kerberos_user, ntlm_user, source_log, observation_count,
                    first_seen, last_seen, zeekad_name, zeekad_name_kind)
                VALUES (?, ?, ?, ?, 'kerberos', 3, TIMESTAMP WITH TIME ZONE '2026-11-20 01:31:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-20 01:44:00Z', ?, 'kerberos_user')
                """, CAP, hostIp(i), kerberos, ntlm, name);
    }

    private void insertReport(int i) throws Exception {
        String a = attack(i);
        ObjectNode report = objectMapper.createObjectNode();
        report.put("observation_summary", a);
        report.putArray("claims").addObject().put("claim", a).putArray("fact_ids").add("F1").add("F9");
        ObjectNode exp = report.putArray("possible_explanations").addObject();
        exp.put("explanation", a);
        exp.putArray("fact_ids").add("F2");
        exp.putArray("attack_ids").add("T1046");
        ObjectNode rec = report.putObject("send_recommendation");
        rec.put("choice", "hold");
        rec.put("reason", a);
        rec.putArray("fact_ids").add("F1");
        report.putArray("limitations").add(a);
        report.putArray("follow_up").add(a);

        ArrayNode problems = objectMapper.createArrayNode();
        problems.add(a);
        ObjectNode problem = problems.addObject();
        problem.put("kind", a);
        problem.put("va‮lue", a);

        ArrayNode candidates = objectMapper.createArrayNode();
        ObjectNode c1 = candidates.addObject();
        c1.put("attack_id", "T1046");
        c1.put("name", T63Attacks.CONTROL);
        c1.putArray("tactics").add("Discovery");
        ObjectNode c2 = candidates.addObject();
        c2.put("attack_id", "T1059");
        c2.put("name", a);
        c2.putArray("tactics").add("Execution").add(a);

        ArrayNode facts = objectMapper.createArrayNode();
        ObjectNode f1 = facts.addObject();
        f1.put("id", "F1");
        f1.put("name", a);
        f1.put("value", a);
        ObjectNode f2 = facts.addObject();
        f2.put("id", "F2");
        f2.put("name", "structured");
        ObjectNode f2v = f2.putObject("value");
        f2v.put("k‮ey", a);
        f2v.putArray("list").add(a).add(T63Attacks.CONTROL);

        ObjectNode pseudonyms = objectMapper.createObjectNode();
        pseudonyms.put("H", hostIp(i));
        pseudonyms.put("X1", a);

        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version,
                    zeekad_input_version, zeekad_report, zeekad_verification_passed, zeekad_verification_reason,
                    zeekad_verification_problems, llm_model_requested, llm_model_version, llm_seconds, llm_input_tokens,
                    llm_output_tokens, llm_thinking_tokens, llm_error, zeekad_attack_candidates, zeekad_source_run, created_at,
                    zeekad_facts, zeekad_pseudonyms)
                VALUES (?, ?, 'llm', 'llm-report.v1', 'evidence.v1', ? FORMAT JSON, FALSE, ?, ? FORMAT JSON,
                        'gemini-2.5-pro', 'gemini-2.5-pro-002', 1.5, 100, 50, 10, ?, ? FORMAT JSON, ?,
                        TIMESTAMP WITH TIME ZONE '2026-11-20 02:06:00Z', ? FORMAT JSON, ? FORMAT JSON)
                """, JOB, incidentId(i), objectMapper.writeValueAsString(report), a, objectMapper.writeValueAsString(problems),
                a, objectMapper.writeValueAsString(candidates), "run-t63-" + i, objectMapper.writeValueAsString(facts),
                objectMapper.writeValueAsString(pseudonyms));
    }

    private void insertSendDecision(int i) throws Exception {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, policy_id,
                    policy_choice, policy_mandatory, policy_reasons, llm_choice, decision_model, decision_model_choice,
                    decision_model_confidence, decision_model_probabilities, decision_model_error, zeekad_source_run, created_at)
                VALUES (?, ?, TRUE, 'policy', 'p1', 'send', FALSE, ? FORMAT JSON, 'hold', 'dm-1', 'send', 0.7,
                        '{"send": 0.7, "hold": 0.3}' FORMAT JSON, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-20 02:07:00Z')
                """, JOB, incidentId(i), objectMapper.writeValueAsString(List.of(attack(i))), attack(i), "run-t63-" + i);
    }

    private void insertSlack(int i) throws Exception {
        String a = attack(i);
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("channel", i == 11 ? a : "#sec-alerts");
        payload.put("text", a);
        ObjectNode block = payload.putArray("blocks").addObject();
        block.put("type", "section");
        block.putObject("text").put("type", "mrkdwn").put("te​xt", a);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version,
                    zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at,
                    zeekad_thread_parent, zeekad_reply_broadcast)
                VALUES (?, ?, 'incident', 'incident.v1', 'dry_run', 'recorded', ? FORMAT JSON, NULL, NULL, ?,
                        TIMESTAMP WITH TIME ZONE '2026-11-20 02:08:00Z', NULL, FALSE)
                """, JOB, incidentId(i), objectMapper.writeValueAsString(payload), a);
        ObjectNode summary = objectMapper.createObjectNode();
        summary.put("channel", "#sec-daily");
        summary.put("text", a);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_slack_summaries (job_id, capture_id, zeekad_message_version, zeekad_delivery_mode,
                    zeekad_delivery_status, slack_payload, slack_ts, delivered_at, created_at)
                VALUES (?, ?, 'daily-summary.v1', 'dry_run', 'recorded', ? FORMAT JSON, NULL, NULL,
                        TIMESTAMP WITH TIME ZONE '2026-11-20 02:09:00Z')
                """, JOB, CAP, objectMapper.writeValueAsString(summary));
    }

    private void insertStatus(int i) {
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by)
                VALUES (?, ?, 'investigating', NULL, TIMESTAMP WITH TIME ZONE '2026-11-20 02:10:00Z', ?)
                """, JOB, incidentId(i), EVIL_A);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution,
                    actor, reason, changed_at)
                VALUES (?, ?, 'open', 'investigating', NULL, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-20 02:10:00Z')
                """, JOB, incidentId(i), EVIL_A, attack(i));
    }

    private void insertReview(int i) {
        boolean decided = i % 2 == 0;
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_analyst_review_queue (job_id, incident_id, queue_rank, host_ip, zeekad_role,
                    zeekad_review_reason, requested_at, zeekad_review_action, analyst, decided_at, zeekad_review_resumed_at,
                    zeekad_review_resume_failed)
                VALUES (?, ?, ?, ?, 'originator', ?, TIMESTAMP WITH TIME ZONE '2026-11-20 02:11:00Z', ?, ?, ?, NULL, FALSE)
                """, JOB, incidentId(i), i, hostIp(i), attack(i), decided ? "confirm" : null, decided ? EVIL_B : null,
                decided ? OffsetDateTime.parse("2026-11-20T02:12:00Z") : null);
    }

    private String evidenceJson() throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        root.putObject("host").put("ip", "10.63.0.1").putArray("name").add(T63Attacks.CONTROL);
        ObjectNode ev = root.putObject("evidence");
        ev.put("connection_count", 3);
        ObjectNode network = ev.putObject("network");
        network.putObject("transport").put("tcp", 3).put("u‮dp", 1).put(T63Attacks.LONG, 2);
        network.putObject("protocol").put("dns", 1);
        ObjectNode peers = ev.putObject("peers");
        peers.putArray("top").addObject().put("ip", "203.0.113.5").put("connections", 2).put("name", T63Attacks.CONTROL);
        peers.put("unique", 1);
        ObjectNode ports = ev.putObject("destination_ports");
        ports.putArray("top").addObject().put("port", 445).put("service", T63Attacks.CONTROL);
        ports.put("unique", 1);
        ObjectNode logs = ev.putObject("protocol_logs");
        logs.putObject("dns").put("queries", 1).put("query", ATTACKS.get(12));
        logs.putObject("ntlm").put("hostname", T63Attacks.CONTROL).put("username", T63Attacks.LONG);
        logs.putObject("we​ird").put("x", "10.0​.0.7");
        ev.putArray("representative_connections").addObject().put("note", ATTACKS.get(14))
                .putObject("source").put("ip", "10.63.0.1");
        ArrayNode limits = ev.putArray("limits");
        ATTACKS.forEach(limits::add);
        T63Attacks.EXTRA_HIDDEN.forEach(limits::add);
        ev.putObject("host").put("ip", "10.63.0.1").put("name", T63Attacks.CONTROL);
        ev.put("extra_" + "f​ield", T63Attacks.CONTROL);
        return objectMapper.writeValueAsString(root);
    }
}
