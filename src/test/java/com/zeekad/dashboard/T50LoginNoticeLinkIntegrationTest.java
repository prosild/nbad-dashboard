package com.zeekad.dashboard;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.controller.LoginNoticeController;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T50 로그인 안내문 링크: 설정 둘(DASHBOARD_LOGIN_NOTICE_LINK_URL·LABEL)이 검사를 통과하고 안내문 글도 있을 때만
 * 응답에 link가 내려간다. 새 불변식은 "필드는 notice, 그리고 검사를 통과한 link뿐"이다(link가 없으면 필드 자체가 없다).
 * 검사에 걸리면 기동 로그에 이유만 남기고 값은 남기지 않는다.
 */
@SpringBootTest(properties = {
        // 인라인 설정은 properties 형식이라 줄바꿈을 \\n(글자 둘)으로 적는다
        "dashboard.login-notice=안내 첫 줄입니다.\\n둘째 줄입니다.",
        "dashboard.login-notice-link-url=  https://example.org/zeekad/docs#readme  ",
        "dashboard.login-notice-link-label=  소개와 구조 보기(README)  "
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T50LoginNoticeLinkIntegrationTest {

    static final String NOTICE = "안내 첫 줄입니다.\n둘째 줄입니다.";
    static final String URL = "https://example.org/zeekad/docs#readme";
    static final String LABEL = "소개와 구조 보기(README)";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;

    private ListAppender<ILoggingEvent> appender;
    private Logger controllerLogger;

    @BeforeEach
    void attachAppender() {
        controllerLogger = (Logger) LoggerFactory.getLogger(LoginNoticeController.class);
        appender = new ListAppender<>();
        appender.start();
        controllerLogger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        controllerLogger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void validLinkIsServedWithExactlyUrlAndLabel() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/login-notice")).andExpect(status().isOk()).andReturn();
        JsonNode body = objectMapper.readTree(res.getResponse().getContentAsString());
        assertThat(fieldNames(body)).as("필드는 notice, 그리고 검사를 통과한 link뿐").containsExactly("notice", "link");
        assertThat(body.get("notice").asText()).as("줄바꿈 유지").isEqualTo(NOTICE);
        JsonNode link = body.get("link");
        assertThat(link.isObject()).isTrue();
        assertThat(fieldNames(link)).as("link의 키는 url·label뿐").containsExactly("url", "label");
        assertThat(link.get("url").asText()).as("앞뒤 공백만 걷어 낸 설정값 그대로").isEqualTo(URL);
        assertThat(link.get("label").asText()).isEqualTo(LABEL);
    }

    @Test
    void boundaryLengthsAndPlainTextLabelAreAccepted() {
        String url200 = "https://example.org/" + "a".repeat(180);
        String label40 = "가".repeat(40);
        assertThat(url200.length()).isEqualTo(200);
        JsonNode body = bodyOf(NOTICE, url200, label40);
        assertThat(fieldNames(body)).containsExactly("notice", "link");
        assertThat(body.at("/link/url").asText()).isEqualTo(url200);
        assertThat(body.at("/link/label").asText()).isEqualTo(label40);

        // 라벨은 일반 텍스트다(태그는 글자 그대로, 화면이 텍스트 노드로 그린다). 포트·경로·쿼리·조각이 있는 https 주소
        JsonNode plain = bodyOf(NOTICE, "https://example.org:8443/a/b?x=1&y=2#frag", "<b>굵게</b> & 보기");
        assertThat(plain.at("/link/url").asText()).isEqualTo("https://example.org:8443/a/b?x=1&y=2#frag");
        assertThat(plain.at("/link/label").asText()).isEqualTo("<b>굵게</b> & 보기");
        assertThat(warnings()).isEmpty();
    }

    @Test
    void rejectedUrlsDropTheLinkFieldAndLogOnlyTheReason() {
        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("http", "http://example.org/t50secretpath");
        bad.put("javascript", "javascript:alert('t50secretpath')");
        bad.put("data", "data:text/html,t50secretpath");
        bad.put("user info", "https://t50secretuser@example.org/");
        bad.put("user info with password", "https://t50secretuser:t50secretpw@example.org/");
        bad.put("github.com@evil", "https://github.com@t50secret.example/");
        bad.put("no host", "https:///t50secretpath");
        bad.put("no host, authority only", "https://");
        bad.put("opaque", "https:t50secretpath");
        bad.put("scheme-relative", "//example.org/t50secretpath");
        bad.put("no scheme", "example.org/t50secretpath");
        bad.put("relative", "/t50secretpath");
        bad.put("space in host", "https://exa mple.org/t50secretpath");
        bad.put("space in path", "https://example.org/t50 secretpath");
        bad.put("tab", "https://example.org/t50\tsecretpath");
        bad.put("newline", "https://example.org/t50\nsecretpath");
        bad.put("carriage return", "https://example.org/t50\rsecretpath");
        bad.put("NUL", "https://example.org/t50\u0000secretpath");
        bad.put("BEL", "https://example.org/t50\u0007secretpath");
        bad.put("DEL", "https://example.org/t50\u007Fsecretpath");
        bad.put("C1 control", "https://example.org/t50\u0085secretpath");
        bad.put("zero width space", "https://example.org/t50​secretpath");
        bad.put("left-to-right mark", "https://example.org/t50‎secretpath");
        bad.put("right-to-left override", "https://example.org/t50‮secretpath");
        bad.put("left-to-right embedding", "https://example.org/t50‪secretpath");
        bad.put("isolate", "https://example.org/t50⁦secretpath");
        bad.put("pop isolate", "https://example.org/t50⁩secretpath");
        bad.put("backslash", "https://example.org\\t50secretpath");
        bad.put("too long", "https://example.org/t50secretpath" + "a".repeat(200));

        bad.forEach((name, url) -> {
            appender.list.clear();
            JsonNode body = bodyOf(NOTICE, url, LABEL);
            assertThat(fieldNames(body)).as("URL %s: link 필드가 없다", name).containsExactly("notice");
            assertThat(body.get("notice").asText()).isEqualTo(NOTICE);
            assertReasonLoggedWithoutValues(name, "secret", url);
        });
    }

    @Test
    void rejectedLabelsDropTheLinkFieldAndLogOnlyTheReason() {
        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("newline", "t50secretlabel\n[위조] 로그 줄");
        bad.put("carriage return", "t50secretlabel\r둘째");
        bad.put("tab", "t50secretlabel\t둘째");
        bad.put("NUL", "t50secretlabel\u0000");
        bad.put("escape", "t50secretlabel\u001B[31m");
        bad.put("zero width joiner", "t50secret‍label");
        bad.put("right-to-left mark", "t50secret‏label");
        bad.put("right-to-left override", "t50secret‮label");
        bad.put("pop directional", "t50secret‬label");
        bad.put("right-to-left isolate", "t50secret⁧label");
        bad.put("too long", "t50secretlabel" + "가".repeat(27));

        bad.forEach((name, label) -> {
            appender.list.clear();
            JsonNode body = bodyOf(NOTICE, URL, label);
            assertThat(fieldNames(body)).as("라벨 %s: link 필드가 없다", name).containsExactly("notice");
            assertReasonLoggedWithoutValues(name, "secret", label);
        });
    }

    @Test
    void linkNeedsBothSettingsAndANotice() {
        // 하나만 있으면 내리지 않는다(경고는 남긴다. 값은 남기지 않는다)
        assertThat(fieldNames(bodyOf(NOTICE, "https://example.org/t50secretpath", ""))).containsExactly("notice");
        assertReasonLoggedWithoutValues("url only", "secret", "https://example.org/t50secretpath");
        appender.list.clear();
        assertThat(fieldNames(bodyOf(NOTICE, null, "t50secretlabel"))).containsExactly("notice");
        assertReasonLoggedWithoutValues("label only", "secret", "t50secretlabel");
        appender.list.clear();
        assertThat(fieldNames(bodyOf(NOTICE, "   ", "t50secretlabel"))).containsExactly("notice");
        assertReasonLoggedWithoutValues("blank url", "secret", "t50secretlabel");

        // 안내문이 비었으면 링크가 맞아도 내리지 않는다
        appender.list.clear();
        JsonNode noNotice = bodyOf("   ", "https://example.org/t50secretpath", "t50secretlabel");
        assertThat(fieldNames(noNotice)).containsExactly("notice");
        assertThat(noNotice.get("notice").asText()).isEmpty();
        assertReasonLoggedWithoutValues("empty notice", "secret", "t50secretlabel");

        // 둘 다 없으면 링크 없음이고 경고도 없다(기본 설정)
        appender.list.clear();
        assertThat(fieldNames(bodyOf(NOTICE, null, null))).containsExactly("notice");
        assertThat(fieldNames(bodyOf(NOTICE, "", "  "))).containsExactly("notice");
        assertThat(fieldNames(bodyOf("", "", ""))).containsExactly("notice");
        assertThat(warnings()).isEmpty();
    }

    /* ───────────── 도우미 ───────────── */

    /** 환경 변수가 묶이는 것과 같은 길(설정 이름 → DashboardProperties)로 컨트롤러를 만들고 응답을 앱의 ObjectMapper로 직렬화한다 */
    private JsonNode bodyOf(String notice, String url, String label) {
        Map<String, String> source = new HashMap<>();
        if (notice != null) {
            source.put("dashboard.login-notice", notice);
        }
        if (url != null) {
            source.put("dashboard.login-notice-link-url", url);
        }
        if (label != null) {
            source.put("dashboard.login-notice-link-label", label);
        }
        DashboardProperties props = new Binder(new MapConfigurationPropertySource(source))
                .bindOrCreate("dashboard", DashboardProperties.class);
        return objectMapper.valueToTree(new LoginNoticeController(props).loginNotice());
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private List<ILoggingEvent> warnings() {
        return appender.list.stream().filter(e -> e.getLevel().isGreaterOrEqual(Level.WARN)).toList();
    }

    /** 경고가 정확히 한 줄이고(이유), 어느 로그 줄에도 값이 없다(값 전체와 값에 심은 표식 모두) */
    private void assertReasonLoggedWithoutValues(String name, String marker, String rawValue) {
        assertThat(warnings()).as("%s: 경고 한 줄", name).hasSize(1);
        assertThat(warnings().get(0).getFormattedMessage()).as("%s: 경고에 이유가 있다", name).contains("로그인 안내 링크");
        for (ILoggingEvent e : appender.list) {
            String line = e.getFormattedMessage();
            assertThat(line).as("%s: 로그에 값이 없다", name).doesNotContain(marker).doesNotContain(rawValue);
            assertThat(line).as("%s: 로그 한 줄에 줄바꿈·제어 문자가 없다", name).doesNotContainPattern("[\\p{Cntrl}]");
            assertThat(e.getArgumentArray() == null ? List.of() : List.of(e.getArgumentArray()))
                    .as("%s: 로그 인자에도 값이 없다", name)
                    .noneMatch(a -> String.valueOf(a).contains(marker));
        }
    }
}
