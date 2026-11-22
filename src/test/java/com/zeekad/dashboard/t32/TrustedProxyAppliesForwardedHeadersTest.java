package com.zeekad.dashboard.t32;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.net.http.HttpResponse;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** T32: 연결 주소(127.0.0.1)가 신뢰 목록에 있으면 X-Forwarded-For·Proto·Port를 적용한다(공백·빈 항목·IPv6 정규형 포함). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "dashboard.security.trusted-proxies= 127.0.0.1 , ,::1,")
@ActiveProfiles("test")
class TrustedProxyAppliesForwardedHeadersTest extends ForwardedHeaderTestSupport {

    @Test
    void singleValveWithExactPatternForCanonicalAddresses() {
        assertSingleValveWithPattern(Pattern.quote("127.0.0.1") + "|" + Pattern.quote("0:0:0:0:0:0:0:1"));
    }

    @Test
    void forwardedForBecomesAuditIp() throws Exception {
        assertThat(loginFailureAuditIp(SPOOF_HEADERS)).isEqualTo(SPOOFED_IP);
    }

    @Test
    void forwardedProtoHttpsMakesRequestSecureAndRedirectHttps() throws Exception {
        HttpResponse<String> csrf = get("/api/auth/csrf", SPOOF_HEADERS);
        assertThat(csrf.headers().firstValue("Strict-Transport-Security")).as("https 판정이면 HSTS").isPresent();

        HttpResponse<String> redirect = get("/t32-not-a-screen", SPOOF_HEADERS);
        assertThat(redirect.statusCode()).isEqualTo(302);
        assertThat(redirect.headers().firstValue("Location")).hasValue("https://127.0.0.1/login");
    }

    @Test
    void withoutForwardedHeadersConnectionValuesStay() throws Exception {
        assertThat(loginFailureAuditIp()).isEqualTo("127.0.0.1");
        HttpResponse<String> redirect = get("/t32-not-a-screen");
        assertThat(redirect.headers().firstValue("Location")).hasValue("http://127.0.0.1:" + port + "/login");
        assertThat(get("/api/auth/csrf").headers().firstValue("Strict-Transport-Security")).isEmpty();
    }
}
