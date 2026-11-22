package com.zeekad.dashboard.t32;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** T32: 목록이 비면(기본) 아무도 믿지 않는다. 127.0.0.1도 믿지 않는다(Boot 기본 internal-proxies가 남지 않음). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "dashboard.security.trusted-proxies=")
@ActiveProfiles("test")
class EmptyTrustedProxiesTrustNobodyTest extends ForwardedHeaderTestSupport {

    @Test
    void valvePatternMatchesNothing() {
        assertSingleValveWithPattern("(?!)");
    }

    @Test
    void spoofedHeadersAreIgnored() throws Exception {
        assertThat(loginFailureAuditIp(SPOOF_HEADERS)).isEqualTo("127.0.0.1");
        HttpResponse<String> csrf = get("/api/auth/csrf", SPOOF_HEADERS);
        assertThat(csrf.headers().firstValue("Strict-Transport-Security")).isEmpty();
        HttpResponse<String> redirect = get("/t32-not-a-screen", SPOOF_HEADERS);
        assertThat(redirect.headers().firstValue("Location")).hasValue("http://127.0.0.1:" + port + "/login");
    }
}
