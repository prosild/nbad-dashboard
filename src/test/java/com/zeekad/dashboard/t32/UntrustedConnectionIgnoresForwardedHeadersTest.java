package com.zeekad.dashboard.t32;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.net.http.HttpResponse;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** T32: 연결 주소(127.0.0.1)가 목록에 없으면(목록은 WAF 주소 하나) 전달 헤더를 모두 무시한다. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "dashboard.security.trusted-proxies=10.203.49.250")
@ActiveProfiles("test")
class UntrustedConnectionIgnoresForwardedHeadersTest extends ForwardedHeaderTestSupport {

    @Test
    void valvePatternIsOnlyTheListedAddress() {
        assertSingleValveWithPattern(Pattern.quote("10.203.49.250"));
    }

    @Test
    void spoofedHeadersDoNotChangeIpSchemeOrRedirect() throws Exception {
        assertThat(loginFailureAuditIp(SPOOF_HEADERS)).isEqualTo("127.0.0.1");
        HttpResponse<String> csrf = get("/api/auth/csrf", SPOOF_HEADERS);
        assertThat(csrf.headers().firstValue("Strict-Transport-Security")).as("https로 판정하지 않는다").isEmpty();
        HttpResponse<String> redirect = get("/t32-not-a-screen", SPOOF_HEADERS);
        assertThat(redirect.headers().firstValue("Location")).hasValue("http://127.0.0.1:" + port + "/login");
    }
}
