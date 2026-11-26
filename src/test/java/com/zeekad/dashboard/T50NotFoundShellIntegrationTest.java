package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T50 없는 주소: 로그인한 브라우저 요청(GET, Accept에서 text/html이 application/json보다 앞)은 SPA 셸을 404로 받는다.
 * API·JSON 요청·비로그인 요청·제외 경로는 지금처럼 JSON 404(비로그인은 302 /login)다.
 * 셸 본문과 forward 뒤의 상태·헤더는 MockMvc로 보이지 않아 내장 Tomcat 실제 포트로 본다(MockMvc는 forward 대상을 그리지 않는다).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T50NotFoundShellIntegrationTest {

    /** 브라우저가 주소창 탐색에 붙이는 Accept */
    static final String BROWSER_ACCEPT =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
    /** 검증 스크립트(security-scan.ps1, portfolio-verify.ps1)가 모든 요청에 붙이는 Accept */
    static final String SCRIPT_ACCEPT = "application/json, text/html;q=0.9, */*;q=0.8";
    static final String PASSWORD = "NotFoundPass!50";

    @LocalServerPort
    int port;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserAdminService userAdminService;

    final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    /* ───────────── 실제 포트: 셸 본문, forward 뒤의 상태·헤더 ───────────── */

    @Test
    void loggedInBrowserNavigationToMissingPathGets404ShellOverRealPort() throws Exception {
        String sessionCookie = loginOverHttp(newUser(UserRole.ANALYST));
        String marker = "t50mark" + UUID.randomUUID().toString().replace("-", "");

        HttpResponse<String> shell = httpGet("/nonexistent-" + marker, sessionCookie, BROWSER_ACCEPT);
        assertThat(shell.statusCode()).isEqualTo(404);
        assertThat(shell.headers().firstValue("Content-Type").orElse("")).startsWith("text/html");
        assertThat(shell.body()).contains("<div id=\"root\"></div>");
        assertThat(shell.body()).as("요청 경로를 본문에 옮겨 적지 않는다").doesNotContain(marker);
        assertThat(shell.headers().firstValue("Content-Security-Policy").orElse(""))
                .contains("frame-ancestors 'none'").contains("script-src 'self'");
        assertThat(shell.headers().firstValue("X-Content-Type-Options").orElse("")).isEqualTo("nosniff");
        assertThat(shell.headers().firstValue("X-Frame-Options").orElse("")).isEqualTo("DENY");
        assertThat(shell.headers().allValues("Cache-Control")).containsExactly("no-store");
        assertThat(varyTokens(shell)).contains("accept");

        // 같은 주소라도 JSON을 앞세운 요청은 지금과 같은 JSON 404(같은 보안 헤더, Vary: Accept)
        HttpResponse<String> jsonRes = httpGet("/nonexistent-" + marker, sessionCookie, "application/json");
        assertThat(jsonRes.statusCode()).isEqualTo(404);
        assertThat(jsonRes.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");
        assertThat(objectMapper.readTree(jsonRes.body()).get("code").asText()).isEqualTo("NOT_FOUND");
        assertThat(jsonRes.body()).doesNotContain(marker).doesNotContain("<div id=\"root\">");
        assertThat(jsonRes.headers().firstValue("Content-Security-Policy").orElse("")).contains("frame-ancestors 'none'");
        assertThat(varyTokens(jsonRes)).contains("accept");

        // 비로그인은 지금과 같다: 같은 주소가 302 /login(셸도 JSON도 아니다)
        HttpResponse<String> anonymous = httpGet("/nonexistent-" + marker, null, BROWSER_ACCEPT);
        assertThat(anonymous.statusCode()).isEqualTo(302);
        assertThat(anonymous.headers().firstValue("Location").orElse("")).endsWith("/login");
        assertThat(anonymous.body()).doesNotContain("<div id=\"root\">");
    }

    /* ───────────── MockMvc: 셸을 주는 조건과 주지 않는 조건 ───────────── */

    @Test
    void shellOnlyForLoggedInGetWhoseAcceptPrefersHtml() throws Exception {
        MockHttpSession s = loginMock(newUser(UserRole.VIEWER));

        // 브라우저 탐색: 404 + 셸(forward), no-store, Vary: Accept
        expectShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", BROWSER_ACCEPT)));
        // 목록 꼴에 맞지 않는 화면 주소도 같은 404 셸(화면이 "잘못된 인시던트 경로입니다."를 그린다)
        expectShell(mockMvc.perform(get("/incidents/abc").session(s).header("Accept", BROWSER_ACCEPT)));
        expectShell(mockMvc.perform(get("/hosts/10.0.0.1").session(s).header("Accept", BROWSER_ACCEPT)));
        // application/json이 없으면 text/html이 있기만 하면 된다. 같은 q면 앞에 쓴 쪽이 앞이다
        expectShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "text/html")));
        expectShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "text/html;q=0.5, */*;q=0.9")));
        expectShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "text/html, application/json")));
        expectShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "application/json;q=0.8, text/html")));

        // JSON 404 그대로인 Accept: JSON만, 검증 스크립트의 값, JSON이 앞, 없음, */*뿐, 읽지 못하는 값
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "application/json")));
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", SCRIPT_ACCEPT)));
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "application/json, text/html")));
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s)));
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "*/*")));
        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "text/*, */*;q=0.8")));

        expectJson404(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "text/html;q=0, application/json")));
        // 읽지 못하는 Accept는 셸이 아니다
        expectNotShell(mockMvc.perform(get("/nonexistent-t50").session(s).header("Accept", "t50 garbage;;")))
                .andExpect(status().is4xxClientError());

        // 제외 경로: 브라우저 Accept여도 셸이 아니다
        expectJson404(mockMvc.perform(get("/api/nonexistent").session(s).header("Accept", BROWSER_ACCEPT)));
        expectJson404(mockMvc.perform(get("/api").session(s).header("Accept", BROWSER_ACCEPT)));
        expectJson404(mockMvc.perform(get("/assets/t50-missing.js").session(s).header("Accept", BROWSER_ACCEPT)));
        expectJson404(mockMvc.perform(get("/actuator/t50-missing").session(s).header("Accept", BROWSER_ACCEPT)));
        expectJson404(mockMvc.perform(get("/actuator").session(s).header("Accept", BROWSER_ACCEPT)));

        // GET이 아니면 셸이 아니다
        Cookie csrf = csrfCookie();
        expectNotShell(mockMvc.perform(post("/nonexistent-t50").session(s).cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue()).header("Accept", BROWSER_ACCEPT)))
                .andExpect(status().is4xxClientError());
        expectNotShell(mockMvc.perform(head("/nonexistent-t50").session(s).header("Accept", BROWSER_ACCEPT)))
                .andExpect(status().isNotFound());
    }

    @Test
    void anonymousResponsesAreUnchanged() throws Exception {
        // 화면 경로가 아닌 없는 경로는 모두 같은 302 /login(Accept와 무관)
        for (String accept : List.of(BROWSER_ACCEPT, "application/json", SCRIPT_ACCEPT)) {
            mockMvc.perform(get("/nonexistent-t50").header("Accept", accept))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("**/login"));
            mockMvc.perform(get("/incidents/abc").header("Accept", accept))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("**/login"));
        }
        mockMvc.perform(get("/nonexistent-t50"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
        // 화면 경로는 지금처럼 셸 200
        mockMvc.perform(get("/incidents").header("Accept", BROWSER_ACCEPT))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));
        // permitAll 경로는 비로그인 요청도 처리기까지 온다. 처리기까지 왔다는 것만으로 셸을 주지 않는다
        expectJson404(mockMvc.perform(get("/assets/없는파일.js").header("Accept", BROWSER_ACCEPT)));
        expectJson404(mockMvc.perform(get("/assets/t50-missing.js").header("Accept", BROWSER_ACCEPT)));
        // 비로그인 API는 401 그대로
        mockMvc.perform(get("/api/nonexistent").header("Accept", BROWSER_ACCEPT))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    /* ───────────── 도우미 ───────────── */

    private void expectShell(ResultActions r) throws Exception {
        r.andExpect(status().isNotFound())
                .andExpect(forwardedUrl("/index.html"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
        assertVaryAccept(r);
    }

    /** Vary 헤더는 여러 줄일 수 있다(Origin 등). 모든 값의 토큰에서 Accept를 찾는다 */
    private static void assertVaryAccept(ResultActions r) {
        List<String> tokens = r.andReturn().getResponse().getHeaders("Vary").stream()
                .flatMap(v -> List.of(v.split(",")).stream())
                .map(v -> v.trim().toLowerCase())
                .toList();
        assertThat(tokens).as("Vary: Accept").contains("accept");
    }

    private ResultActions expectNotShell(ResultActions r) throws Exception {
        MvcResult res = r.andReturn();
        assertThat(res.getResponse().getForwardedUrl()).as("셸로 넘기지 않는다").isNull();
        assertThat(res.getResponse().getContentAsString()).doesNotContain("<div id=\"root\">");
        return r;
    }

    private void expectJson404(ResultActions r) throws Exception {
        expectNotShell(r)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.code").value("NOT_FOUND"))
                .andExpect(jsonPath("$.message").value("요청하신 경로를 찾을 수 없습니다."));
        assertVaryAccept(r);
    }

    private String newUser(UserRole role) {
        String username = "t50_" + role.name().toLowerCase() + "_" + UUID.randomUUID().toString().substring(0, 8);
        userAdminService.createUser(username, "T50 사용자", PASSWORD, role, "*", "seed", "ADMIN", "127.0.0.1");
        return username;
    }

    private Cookie csrfCookie() throws Exception {
        return mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession loginMock(String username) throws Exception {
        Cookie csrf = csrfCookie();
        MockHttpServletRequestBuilder login = post("/api/auth/login")
                .cookie(csrf)
                .header("X-XSRF-TOKEN", csrf.getValue())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD)));
        MvcResult result = mockMvc.perform(login).andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private HttpResponse<String> httpGet(String path, String cookie, String accept) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri(path)).GET().header("Accept", accept);
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** 폼 로그인 흐름(CSRF 쿠키·토큰 → 로그인)으로 세션 쿠키를 받는다. 돌려주는 값은 Cookie 헤더에 그대로 쓴다. */
    private String loginOverHttp(String username) throws Exception {
        HttpResponse<String> csrf = http.send(HttpRequest.newBuilder(uri("/api/auth/csrf")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(csrf.statusCode()).isEqualTo(200);
        String xsrfCookie = cookiePair(csrf, "XSRF-TOKEN");
        Matcher token = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"").matcher(csrf.body());
        assertThat(token.find()).as("CSRF 응답 본문의 token").isTrue();

        HttpResponse<String> login = http.send(HttpRequest.newBuilder(uri("/api/auth/login"))
                .header("Content-Type", "application/json")
                .header("Cookie", xsrfCookie)
                .header("X-XSRF-TOKEN", token.group(1))
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(login.statusCode()).as("로그인").isEqualTo(200);
        return cookiePair(login, "ZEEKAD_SESSION");
    }

    private static String cookiePair(HttpResponse<String> res, String name) {
        return res.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith(name + "="))
                .map(c -> c.indexOf(';') < 0 ? c : c.substring(0, c.indexOf(';')))
                .findFirst().orElseThrow(() -> new AssertionError(name + " 쿠키가 없습니다"));
    }

    private static List<String> varyTokens(HttpResponse<String> res) {
        return res.headers().allValues("Vary").stream()
                .flatMap(v -> List.of(v.split(",")).stream())
                .map(v -> v.trim().toLowerCase())
                .toList();
    }
}
