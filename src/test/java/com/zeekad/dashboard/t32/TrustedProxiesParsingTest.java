package com.zeekad.dashboard.t32;

import com.zeekad.dashboard.ZeekAdDashboardApplication;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.security.TrustedProxies;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** T32: 신뢰 프록시 목록 해석(리터럴만, DNS 없음, IPv6 정규형, 공백·빈 항목)과 형식 오류 시 시작 실패. */
@ExtendWith(OutputCaptureExtension.class)
class TrustedProxiesParsingTest {

    private static TrustedProxies of(String... values) {
        DashboardProperties p = new DashboardProperties();
        p.getSecurity().setTrustedProxies(List.of(values));
        return new TrustedProxies(p);
    }

    @Test
    void trimsDropsEmptyDeduplicatesAndCanonicalizes() {
        TrustedProxies t = of(" 10.203.48.250 ", "", "  ", "::1", "0:0:0:0:0:0:0:1", "FE80:0000::0A", "10.203.48.250",
                "2001:db8::10.0.0.1", "1:2:3:4:5:6:7:8", "1::", "::");
        assertThat(t.addresses()).containsExactly("10.203.48.250", "0:0:0:0:0:0:0:1", "fe80:0:0:0:0:0:0:a",
                "2001:db8:0:0:0:0:a00:1", "1:2:3:4:5:6:7:8", "1:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:0");
    }

    @Test
    void singleCommaStringIsSplitToo() {
        assertThat(of(" 10.0.0.5 , ,10.0.0.6 ").addresses()).containsExactly("10.0.0.5", "10.0.0.6");
    }

    @Test
    void emptyListTrustsNobody() {
        TrustedProxies t = of();
        assertThat(t.addresses()).isEmpty();
        assertThat(t.internalProxiesPattern()).isEqualTo("(?!)");
        assertThat(Pattern.compile(t.internalProxiesPattern()).matcher("127.0.0.1").matches()).isFalse();
        assertThat(of(" ", "").addresses()).isEmpty();
    }

    @Test
    void patternMatchesOnlyExactAddresses() {
        Pattern p = Pattern.compile(of("10.203.48.250", "::1").internalProxiesPattern());
        assertThat(p.matcher("10.203.48.250").matches()).isTrue();
        assertThat(p.matcher("0:0:0:0:0:0:0:1").matches()).isTrue();
        // 점이 정규식 와일드카드가 아니고, 앞뒤로 더 붙은 주소와 맞지 않는다.
        assertThat(p.matcher("10x203.48.250").matches()).isFalse();
        assertThat(p.matcher("10.203.48.2500").matches()).isFalse();
        assertThat(p.matcher("110.203.48.250").matches()).isFalse();
        assertThat(p.matcher("10.203.48.25").matches()).isFalse();
    }

    @Test
    void rejectsNonLiteralEntries() {
        for (String bad : List.of("10.203.48.0/24", "localhost", "dashboard-app", "nginx-waf", "10\\.203\\..*", ".*",
                "10.203.48.*", "1.2.3", "1.2.3.4.5", "01.2.3.4", "256.1.1.1", "1.2.3.-1", "fe80::1%eth0", "[::1]",
                "::1/128", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1", "1:", "12345::1", "::1.2.3", "1.2.3.4::",
                "１.2.3.4", "0x0a.0.0.1", "abc")) {
            assertThat(TrustedProxies.canonicalize(bad)).as("'%s'는 주소가 아니다", bad).isNull();
            assertThatThrownBy(() -> of("10.0.0.1", bad))
                    .as("'%s'가 있으면 시작 실패", bad)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("trusted-proxies");
        }
    }

    @Test
    void parserNeverUsesNameResolution() throws IOException {
        // 호스트 이름 항목으로 DNS 조회가 일어나지 않는다: 해석 코드는 이름을 조회하는 API를 쓰지 않고 바이트로만 주소를 만든다.
        String src = Files.readString(Path.of("src/main/java/com/zeekad/dashboard/security/TrustedProxies.java"),
                StandardCharsets.UTF_8);
        assertThat(src).doesNotContain("getByName(", "getAllByName(", "InetSocketAddress", "getCanonicalHostName",
                "getHostName(");
        assertThat(src).contains("InetAddress.getByAddress(bytes)");
        // 이 PC에서 해석되는 이름도 주소로 받지 않는다.
        assertThat(TrustedProxies.canonicalize("localhost")).isNull();
    }

    /** 명령줄 인수는 application.yml보다 우선한다(기본 속성 properties()는 application.yml에 진다). */
    private static ConfigurableApplicationContext start(String trustedProxies) {
        return new SpringApplicationBuilder(ZeekAdDashboardApplication.class)
                .web(WebApplicationType.SERVLET).profiles("test")
                .run("--server.port=0", "--dashboard.security.trusted-proxies=" + trustedProxies);
    }

    @Test
    void invalidEntryStopsApplicationStartup() {
        for (String bad : List.of("10.203.48.0/24", "nginx-waf", "10.203.*")) {
            assertThatThrownBy(() -> start("10.203.48.250," + bad).close())
                    .as("'%s'가 있으면 앱이 시작하지 않는다", bad)
                    .hasStackTraceContaining("dashboard.security.trusted-proxies")
                    .hasStackTraceContaining(bad);
        }
    }

    @Test
    void startupLogsListOrWarnsWhenEmpty(CapturedOutput output) {
        try (ConfigurableApplicationContext ignored = start(" ::1 ,10.203.49.250")) {
            assertThat(output).contains("전달 헤더를 믿을 프록시 주소: 0:0:0:0:0:0:0:1, 10.203.49.250");
        }
        try (ConfigurableApplicationContext ignored = start("")) {
            assertThat(output).contains("전달 헤더를 믿을 프록시가 없습니다");
        }
    }
}
