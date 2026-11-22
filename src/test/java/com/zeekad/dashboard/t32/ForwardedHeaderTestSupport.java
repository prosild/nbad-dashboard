package com.zeekad.dashboard.t32;

import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import org.apache.catalina.Valve;
import org.apache.catalina.valves.RemoteIpValve;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T32 내장 Tomcat 시험 도우미. MockMvc는 엔진 valve를 지나지 않으므로 실제 포트로 HTTP 요청을 보낸다.
 * 연결 주소는 늘 127.0.0.1이다(클라이언트가 127.0.0.1로 붙는다).
 * 감사 로그 IP는 없는 계정의 로그인 실패(LOGIN_FAILURE)로 본다. 없는 계정이라 잠금 계수에 영향이 없다.
 */
abstract class ForwardedHeaderTestSupport {

    static final String SPOOFED_IP = "203.0.113.7";

    static final String[] SPOOF_HEADERS = {
            "X-Forwarded-For", SPOOFED_IP,
            "X-Forwarded-Proto", "https",
            "X-Forwarded-Port", "443"};

    @LocalServerPort
    int port;
    @Autowired
    AuditLogMapper auditLogMapper;
    @Autowired
    ServletWebServerApplicationContext webContext;

    final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    HttpResponse<String> get(String path, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri(path)).GET();
        if (headers.length > 0) {
            b.headers(headers);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** 없는 계정으로 로그인 실패를 만들고 그 감사 행의 IP를 돌려준다. 전달 헤더는 CSRF 발급·로그인 두 요청에 같이 붙인다. */
    String loginFailureAuditIp(String... forwardedHeaders) throws Exception {
        HttpResponse<String> csrf = get("/api/auth/csrf", forwardedHeaders);
        assertThat(csrf.statusCode()).isEqualTo(200);
        String cookie = csrf.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("XSRF-TOKEN="))
                .map(c -> c.indexOf(';') < 0 ? c : c.substring(0, c.indexOf(';')))
                .findFirst().orElseThrow();
        Matcher token = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"").matcher(csrf.body());
        assertThat(token.find()).as("CSRF 응답 본문의 token").isTrue();

        String username = "t32_nouser_" + UUID.randomUUID().toString().substring(0, 8);
        HttpRequest.Builder b = HttpRequest.newBuilder(uri("/api/auth/login"))
                .header("Content-Type", "application/json")
                .header("Cookie", cookie)
                .header("X-XSRF-TOKEN", token.group(1))
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"username\":\"" + username + "\",\"password\":\"WrongPass!32\"}"));
        if (forwardedHeaders.length > 0) {
            b.headers(forwardedHeaders);
        }
        HttpResponse<String> login = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        assertThat(login.statusCode()).isEqualTo(401);
        List<AuditLog> rows = auditLogMapper.findFiltered(AuditActionType.LOGIN_FAILURE.name(), username, 5);
        assertThat(rows).hasSize(1);
        return rows.get(0).getClientIp();
    }

    List<RemoteIpValve> remoteIpValves() {
        Valve[] valves = ((TomcatWebServer) webContext.getWebServer()).getTomcat().getEngine().getPipeline().getValves();
        return Arrays.stream(valves).filter(RemoteIpValve.class::isInstance).map(RemoteIpValve.class::cast).toList();
    }

    void assertSingleValveWithPattern(String expectedPattern) {
        List<RemoteIpValve> valves = remoteIpValves();
        assertThat(valves).as("엔진의 RemoteIpValve는 하나").hasSize(1);
        assertThat(valves.get(0).getInternalProxies()).isEqualTo(expectedPattern);
        assertThat(valves.get(0).getTrustedProxies()).as("Tomcat trustedProxies는 쓰지 않는다").isNull();
    }
}
