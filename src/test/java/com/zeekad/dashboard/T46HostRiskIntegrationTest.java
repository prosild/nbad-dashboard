package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.IncidentRefMapper;
import com.zeekad.dashboard.mapper.zeekad.read.HostReadMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.IncidentRefService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T46 호스트 위험도 목록(GET /api/hosts)과 상세의 같은 호스트 인시던트
 * (GET /api/incidents/{jobId}/rank/{queueRank}/related-host-incidents).
 *
 * 시험 자료(job 96000~96999, 이 시험만 쓰는 H2). 기준 시각 2026-11-21T00:00Z.
 * <pre>
 * /hosts 쪽
 *  lab-t46a  옛 작업 96010(08:00), 최신 96011(10:00)   H1~H7
 *  lab-t46b  96020(11:00)                               H1(같은 주소, 다른 캡처), H4
 *  t46imp-c  96030(2026-11-10)                          H8(가져온 데이터, 이름·계정 6개 이상)
 *  lab-t46n  96050(완료 시각 없음 = 탐지 시각 없음)      H9
 *  lab-t46h  96040(숨김)                                H1과 같은 주소, 다른 주소 하나
 *   H1 10.46.1.10  목적지 01:00 → 출발지 02:00(같은 캡처) = 전환
 *   H2 10.46.1.20  출발지·목적지 같은 시각                = 전환 아님
 *   H3 10.46.2.30  출발지 01:00 → 목적지 02:00            = 전환 아님(순서 반대)
 *   H4 10.47.0.40  목적지(a) → 출발지(b)                  = 전환 아님(캡처가 다름)
 *   H5 10.47.0.50  목적지가 오탐 종결                     = 전환 아님
 *   H6 10.47.0.60  출발지가 정상 종결(공백·대문자 값)     = 전환 아님
 *   H7 10.48.0.70  목적지가 정탐 종결 → 출발지            = 전환(정탐 종결은 빼지 않는다)
 * 같은 호스트 쪽
 *  lab-t46r  옛 작업 96060(08:00), 최신 96061(10:00)   SELF(10.50.0.1)와 같은 호스트 12건, 같은 대역 다른 호스트 1건
 *  lab-t46s  96070(11:00)                               같은 호스트 2건(번호 동기화 뒤에 넣어 번호 행이 없다)
 *  lab-t46h  96040(숨김)                                같은 호스트 1건
 * </pre>
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t46_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t46_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t46_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T46HostRiskIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final String CAP_A = "lab-t46a";
    private static final String CAP_B = "lab-t46b";
    private static final String CAP_IMP = "t46imp-c";
    private static final String CAP_NULL = "lab-t46n";
    private static final String HIDDEN = "lab-t46h";
    private static final String CAP_R = "lab-t46r";
    private static final String CAP_S = "lab-t46s";
    private static final String CAP_BIG = "t46big-cap";
    private static final String HOST_PATTERNS = CAP_A + "," + CAP_B + ",t46imp-*," + CAP_NULL;
    private static final String RELATED_PATTERNS = CAP_R + "," + CAP_S;

    private static final String H1 = "10.46.1.10";
    private static final String H2 = "10.46.1.20";
    private static final String H3 = "10.46.2.30";
    private static final String H4 = "10.47.0.40";
    private static final String H5 = "10.47.0.50";
    private static final String H6 = "10.47.0.60";
    private static final String H7 = "10.48.0.70";
    private static final String H8 = "172.20.5.80";
    private static final String H9 = "192.0.2.90";
    private static final String SELF_HOST = "10.50.0.1";
    private static final OffsetDateTime SELF_START = OffsetDateTime.parse("2026-11-20T06:00:00Z");

    private static final Pattern FULL_IPV4 =
            Pattern.compile("(?<![0-9.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![0-9.])");
    /** 조회자 응답 어디에도 없어야 하는 계정 이름 원문 */
    private static final List<String> RAW_ACCOUNTS = List.of("alice.kim", "FINPC-07$", "bob.lee", "BOB_NT", "adam.cho",
            "u1.one", "u6.six", "hidden.user", "ghost.pair");

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(FIXED_NOW);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired private IncidentRefService refService;
    @MockitoSpyBean private ZeekadReadMapper zeekadReadMapper;
    @MockitoSpyBean private HostReadMapper hostReadMapper;
    @MockitoSpyBean private IncidentRefMapper refMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;
    private String tag;
    private final Map<MockHttpSession, String> names = new HashMap<>();

    @BeforeEach
    void setUp() {
        tag = "t46s" + (++seq);
        seedHosts();
        seedRelated();
        refService.syncAll();
        // 번호 동기화 뒤에 넣는 행: 번호 행이 없다(읽기 전용 조회가 번호를 만들지 않는지 본다)
        job(96070, CAP_S, "2026-11-20T11:00:00Z");
        incident(96070, CAP_S, 1, SELF_HOST, "originator", minutes(-10), 1, "hbos", "NULL", "NULL", "s1");
        incident(96070, CAP_S, 2, SELF_HOST, "originator", minutes(80), 1, "hbos", "NULL", "NULL", "s2");
        clearSpies();
    }

    @AfterEach
    void cleanup() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 96000 AND 96999";
        z.update("DELETE FROM dashboard.raw_send_decisions WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_reports WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
        z.update("DELETE FROM dashboard.raw_asset_names WHERE capture_id LIKE 'lab-t46%' OR capture_id LIKE 't46%'");
        Mockito.reset(zeekadReadMapper, hostReadMapper, refMapper);
    }

    /* ───────────── /api/hosts: 묶음과 줄의 값 ───────────── */

    @Test
    void analystGroupsByRawHostAcrossCapturesWithExactRowValues() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        String body = getBody(a, "/api/hosts?period=all");
        JsonNode res = objectMapper.readTree(body);
        assertThat(res.get("maskedView").asBoolean()).isFalse();
        assertThat(res.get("total").asLong()).isEqualTo(9);
        assertThat(res.get("page").asInt()).isEqualTo(1);
        assertThat(res.get("size").asInt()).isEqualTo(50);
        assertThat(res.get("pageCount").asInt()).isEqualTo(1);
        assertThat(res.get("period").asText()).isEqualTo("all");
        assertThat(res.get("periodStart").isNull()).isTrue();
        assertThat(res.get("periodEnd").isNull()).isTrue();
        assertThat(Instant.parse(res.get("anchor").asText())).isEqualTo(FIXED_NOW);
        assertThat(res.get("anchorMode").asText()).isEqualTo("now");
        assertThat(res.get("snapshot").asBoolean()).isFalse();
        // 수집원 선택지: 허용 캡처 전체와 종류(큐·운영 현황 응답과 같은 모양). 숨김 캡처는 없다
        Map<String, String> sources = new HashMap<>();
        for (JsonNode s : res.get("sources")) {
            sources.put(s.get("captureId").asText(), s.get("sourceType").asText());
        }
        assertThat(sources).containsOnly(Map.entry(CAP_A, "live"), Map.entry(CAP_B, "live"),
                Map.entry(CAP_IMP, "imported"), Map.entry(CAP_NULL, "live"));
        assertThat(body).doesNotContain(HIDDEN).doesNotContain("hidden.user").doesNotContain("10.46.9.99");

        // 기본 순서 = 위험도(high → medium → low → incidents → 마지막 탐지 → 주소)
        assertThat(hostIps(res)).containsExactly(H1, H7, H4, H3, H2, H5, H6, H8, H9);

        // H1: 두 캡처에 걸친 같은 주소가 한 줄. 옛 작업에만 있는 행과 숨김 캡처 행은 세지 않는다
        JsonNode h1 = host(res, H1);
        assertThat(h1.get("incidents").asLong()).isEqualTo(3);
        assertThat(h1.get("high").asLong()).isEqualTo(1);
        assertThat(h1.get("medium").asLong()).isEqualTo(1);
        assertThat(h1.get("low").asLong()).isEqualTo(1);
        assertThat(h1.get("connections").asLong()).isEqualTo(157);
        assertThat(texts(h1.get("models"))).containsExactly("iforest", "hbos");
        assertThat(texts(h1.get("hostNames"))).containsExactly("fin-alias", "ws-fin-01", "ws-fin-01.corp.local");
        assertThat(h1.get("hostNameCount").asInt()).isEqualTo(3);
        // 관측 계정: zeekad_name이 먼저, 없으면 Kerberos·NTLM 이름. 숨김 캡처와 (캡처, 주소) 쌍이 다른 행은 붙지 않는다
        assertThat(texts(h1.get("accounts"))).containsExactly("BOB_NT", "FINPC-07$", "alice.kim", "bob.lee");
        assertThat(h1.get("accountCount").asInt()).isEqualTo(4);
        assertThat(Instant.parse(h1.get("lastDetectedAt").asText())).isEqualTo(Instant.parse("2026-11-20T11:00:00Z"));
        assertThat(h1.get("roleTransition").asBoolean()).isTrue();

        // H2: 종결은 우선순위가 없다(incidents에는 든다)
        JsonNode h2 = host(res, H2);
        assertThat(h2.get("incidents").asLong()).isEqualTo(2);
        assertThat(h2.get("high").asLong() + h2.get("medium").asLong()).isZero();
        assertThat(h2.get("low").asLong()).isEqualTo(1);
        assertThat(h2.get("connections").asLong()).isEqualTo(30);
        assertThat(texts(h2.get("models"))).containsExactly("hbos");
        assertThat(texts(h2.get("hostNames"))).containsExactly("dev-box-20");
        assertThat(texts(h2.get("accounts"))).containsExactly("adam.cho");
        assertThat(body).doesNotContain("ghost.pair");
        assertThat(Instant.parse(h2.get("lastDetectedAt").asText())).isEqualTo(Instant.parse("2026-11-20T10:00:00Z"));

        // H8: 이름·계정은 글자 순 5개까지 싣고 전체 수를 따로 준다
        JsonNode h8 = host(res, H8);
        assertThat(texts(h8.get("hostNames"))).containsExactly("h1.imp.local", "h2.imp.local", "h3.imp.local",
                "h4.imp.local", "h5.imp.local");
        assertThat(h8.get("hostNameCount").asInt()).isEqualTo(7);
        assertThat(texts(h8.get("accounts"))).containsExactly("u1.one", "u2.two", "u3.three", "u4.four", "u5.five");
        assertThat(h8.get("accountCount").asInt()).isEqualTo(6);
        assertThat(h8.get("connections").asLong()).isEqualTo(999);
        assertThat(Instant.parse(h8.get("lastDetectedAt").asText())).isEqualTo(Instant.parse("2026-11-10T00:00:00Z"));

        // H9: 탐지 시각 없음. 이름·계정 없음
        JsonNode h9 = host(res, H9);
        assertThat(h9.get("lastDetectedAt").isNull()).isTrue();
        assertThat(h9.get("hostNames")).isEmpty();
        assertThat(h9.get("accounts")).isEmpty();
        assertThat(h9.get("hostNameCount").asInt() + h9.get("accountCount").asInt()).isZero();

        // 캡처 하나로 좁히면 그 캡처의 행과 그 (캡처, 주소) 쌍의 계정만 남는다
        JsonNode onlyB = getJson(a, "/api/hosts?period=all&captureId=" + CAP_B);
        assertThat(hostIps(onlyB)).containsExactly(H1, H4);
        JsonNode h1b = host(onlyB, H1);
        assertThat(h1b.get("incidents").asLong()).isEqualTo(1);
        assertThat(h1b.get("low").asLong()).isEqualTo(1);
        assertThat(texts(h1b.get("accounts"))).containsExactly("BOB_NT", "bob.lee");
        assertThat(texts(h1b.get("hostNames"))).containsExactly("fin-alias");
        assertThat(h1b.get("roleTransition").asBoolean()).isFalse();

        // 기간: 7일이면 2026-11-10 탐지(H8)와 탐지 시각 없음(H9)이 빠진다
        JsonNode week = getJson(a, "/api/hosts?period=7d");
        assertThat(hostIps(week)).containsExactly(H1, H7, H4, H3, H2, H5, H6);
        assertThat(Instant.parse(week.get("periodEnd").asText())).isEqualTo(FIXED_NOW);
        assertThat(Instant.parse(week.get("periodStart").asText())).isEqualTo(FIXED_NOW.minusSeconds(7 * 24 * 3600));
        // 기간을 주지 않으면 서버 기본 24시간이다
        assertThat(getJson(a, "/api/hosts").get("period").asText()).isEqualTo("24h");
    }

    @Test
    void viewerGroupsByMaskedRangeAndResponseHasNoFullIpv4OrRawAccountName() throws Exception {
        MockHttpSession v = login(UserRole.VIEWER, HOST_PATTERNS);
        String body = getBody(v, "/api/hosts?period=all");
        JsonNode res = objectMapper.readTree(body);
        assertThat(res.get("maskedView").asBoolean()).isTrue();
        // 원문 호스트 9개가 대역 5줄로 묶인다(원문으로 계산한 뒤 가린 것이 아니다)
        assertThat(hostIps(res)).containsExactly("10.46.*.*", "10.48.*.*", "10.47.*.*", "172.20.*.*", "192.0.*.*");
        assertThat(res.get("total").asLong()).isEqualTo(5);

        JsonNode r46 = host(res, "10.46.*.*");
        assertThat(r46.get("incidents").asLong()).isEqualTo(7);
        assertThat(r46.get("high").asLong()).isEqualTo(1);
        assertThat(r46.get("medium").asLong()).isEqualTo(1);
        assertThat(r46.get("low").asLong()).isEqualTo(4);
        assertThat(r46.get("connections").asLong()).isEqualTo(197);
        assertThat(texts(r46.get("models"))).containsExactly("hbos", "autoencoder", "iforest");
        assertThat(texts(r46.get("hostNames"))).containsExactly("dev-box-20", "fin-alias", "ws-fin-01", "ws-fin-01.corp.local");
        // 계정은 가린 뒤 중복을 없앤다(alice.kim과 adam.cho가 같은 글이 된다)
        assertThat(texts(r46.get("accounts"))).containsExactly("B***", "F***", "a***", "b***");
        assertThat(r46.get("accountCount").asInt()).isEqualTo(4);
        assertThat(r46.get("roleTransition").asBoolean()).isFalse();

        JsonNode r47 = host(res, "10.47.*.*");
        assertThat(r47.get("incidents").asLong()).isEqualTo(6);
        assertThat(r47.get("low").asLong()).isEqualTo(4);

        JsonNode r172 = host(res, "172.20.*.*");
        assertThat(texts(r172.get("accounts"))).containsExactly("u***");
        assertThat(r172.get("accountCount").asInt()).isEqualTo(1);
        assertThat(r172.get("hostNameCount").asInt()).isEqualTo(7);

        // 전환 표시는 조회자에게 늘 false이고 전환만 보기는 빈 목록이다
        for (JsonNode it : res.get("items")) {
            assertThat(it.get("roleTransition").asBoolean()).isFalse();
        }
        JsonNode only = getJson(v, "/api/hosts?period=all&roleTransitionOnly=true");
        assertThat(only.get("total").asLong()).isZero();
        assertThat(only.get("items")).isEmpty();
        assertThat(only.get("pageCount").asInt()).isEqualTo(1);

        // 응답 어디에도 온전한 IPv4와 계정 이름 원문이 없다(검색·정렬을 바꿔도)
        for (String url : List.of("/api/hosts?period=all", "/api/hosts?period=all&sort=hostIp&dir=desc",
                "/api/hosts?period=all&q=node-172", "/api/hosts?period=7d&source=live", "/api/hosts?period=all&q=10.46.1.10")) {
            String b = getBody(v, url);
            assertNoFullIpv4(b);
            for (String raw : RAW_ACCOUNTS) {
                assertThat(b).as(url).doesNotContain(raw);
            }
        }
        // 조회자의 합도 같은 조건 큐 건수와 같다
        assertThat(sumIncidents(res)).isEqualTo(getJson(v, "/api/incidents/queue?period=all").at("/summary/total").asLong());
    }

    /* ───────────── 방향 전환 ───────────── */

    @Test
    void roleTransitionRequiresOriginatorStrictlyAfterEarliestResponderInSameCapture() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        JsonNode res = getJson(a, "/api/hosts?period=all");
        Map<String, Boolean> expected = new HashMap<>();
        expected.put(H1, true);    // 같은 캡처에서 목적지 뒤 출발지
        expected.put(H2, false);   // 시각이 같다(>가 아니다)
        expected.put(H3, false);   // 순서가 반대
        expected.put(H4, false);   // 캡처가 다르다
        expected.put(H5, false);   // 목적지가 오탐 종결
        expected.put(H6, false);   // 출발지가 정상 종결(앞뒤 공백·대문자 값)
        expected.put(H7, true);    // 정탐 종결은 빼지 않는다. 방향 값의 공백·대문자도 같은 값으로 본다
        expected.put(H8, false);
        expected.put(H9, false);
        for (JsonNode it : res.get("items")) {
            assertThat(it.get("roleTransition").asBoolean()).as(it.get("hostIp").asText())
                    .isEqualTo(expected.get(it.get("hostIp").asText()));
        }
        for (String flag : List.of("true", "TRUE", " True ")) {
            JsonNode only = getJson(a, "/api/hosts?period=all&roleTransitionOnly=" + enc(flag));
            assertThat(hostIps(only)).as(flag).containsExactly(H1, H7);
            assertThat(only.get("total").asLong()).isEqualTo(2);
        }
        for (String flag : List.of("false", "FALSE", "")) {
            assertThat(getJson(a, "/api/hosts?period=all&roleTransitionOnly=" + flag).get("total").asLong()).isEqualTo(9);
        }
        // 조건이 캡처 하나로 좁혀지면 그 안의 행만 본다(H1은 lab-t46b에 출발지 한 건뿐)
        assertThat(getJson(a, "/api/hosts?period=all&roleTransitionOnly=true&captureId=" + CAP_B).get("total").asLong()).isZero();
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&roleTransitionOnly=true&captureId=" + CAP_A)))
                .containsExactly(H1, H7);
    }

    /* ───────────── 정렬·검색·쪽 ───────────── */

    private record Row(String hostIp, long high, long medium, long low, long incidents, long connections, Instant last) {
    }

    private static Row row(JsonNode it) {
        return new Row(it.get("hostIp").asText(), it.get("high").asLong(), it.get("medium").asLong(),
                it.get("low").asLong(), it.get("incidents").asLong(), it.get("connections").asLong(),
                it.get("lastDetectedAt").isNull() ? null : Instant.parse(it.get("lastDetectedAt").asText()));
    }

    /** 인계 2절의 순서를 그대로 옮긴 기준 비교 */
    private static int refCompare(Row x, Row y, String sort, boolean asc) {
        int c;
        if (!"risk".equals(sort)) {
            c = switch (sort) {
                case "incidents" -> dir(Long.compare(x.incidents(), y.incidents()), asc);
                case "connections" -> dir(Long.compare(x.connections(), y.connections()), asc);
                case "lastDetected" -> lastCompare(x.last(), y.last(), asc);
                default -> dir(x.hostIp().compareTo(y.hostIp()), asc);
            };
            if (c != 0) return c;
        }
        boolean riskAsc = "risk".equals(sort) && asc;
        c = dir(Long.compare(x.high(), y.high()), riskAsc);
        if (c != 0) return c;
        c = dir(Long.compare(x.medium(), y.medium()), riskAsc);
        if (c != 0) return c;
        c = dir(Long.compare(x.low(), y.low()), riskAsc);
        if (c != 0) return c;
        c = dir(Long.compare(x.incidents(), y.incidents()), riskAsc);
        if (c != 0) return c;
        c = lastCompare(x.last(), y.last(), riskAsc);
        if (c != 0) return c;
        return x.hostIp().compareTo(y.hostIp());
    }

    private static int dir(int c, boolean asc) {
        return asc ? c : -c;
    }

    /** 값 없음은 방향과 상관없이 뒤 */
    private static int lastCompare(Instant x, Instant y, boolean asc) {
        if (x == null && y == null) return 0;
        if (x == null) return 1;
        if (y == null) return -1;
        return dir(x.compareTo(y), asc);
    }

    @Test
    void sortAndDirFollowTheDocumentedOrderIncludingTiesAndMissingLastDetected() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        List<Row> all = new ArrayList<>();
        for (JsonNode it : getJson(a, "/api/hosts?period=all").get("items")) {
            all.add(row(it));
        }
        assertThat(all).hasSize(9);
        for (String sort : List.of("risk", "incidents", "connections", "lastDetected", "hostIp")) {
            for (String d : List.of("asc", "desc")) {
                boolean asc = "asc".equals(d);
                List<Row> expected = new ArrayList<>(all);
                expected.sort((x, y) -> refCompare(x, y, sort, asc));
                JsonNode res = getJson(a, "/api/hosts?period=all&sort=" + sort + "&dir=" + d);
                assertThat(hostIps(res)).as("%s %s", sort, d)
                        .containsExactlyElementsOf(expected.stream().map(Row::hostIp).toList());
            }
        }
        // 손으로 적은 기대값(기준 비교 함수와 구현이 같은 실수를 하지 않게)
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=risk&dir=desc")))
                .containsExactly(H1, H7, H4, H3, H2, H5, H6, H8, H9);
        // risk 오름차순: 앞의 키들만 뒤집히고 같은 값의 주소 오름차순(H2, H5, H6)과 탐지 시각 없음 맨 뒤(H9)는 그대로다
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=risk&dir=asc")))
                .containsExactly(H8, H9, H2, H5, H6, H3, H4, H7, H1);
        // 마지막 탐지: 같은 값이면 위험도 기본 순서, 값 없음(H9)은 어느 방향에서도 맨 뒤
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=lastDetected&dir=desc")))
                .containsExactly(H1, H4, H7, H3, H2, H5, H6, H8, H9);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=lastDetected&dir=asc")))
                .containsExactly(H8, H7, H3, H2, H5, H6, H1, H4, H9);
        // 세션 수: 같은 값(2)이면 위험도 기본 순서(H7 → H4 → H5 → H6)
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=connections")))
                .containsExactly(H8, H1, H2, H3, H9, H7, H4, H5, H6);
        // 기본 방향: hostIp만 오름, 나머지는 내림. 정렬 키는 대소문자를 가리지 않는다
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=hostIp")))
                .containsExactly(H1, H2, H3, H4, H5, H6, H7, H8, H9);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=HOSTIP&dir=DESC")))
                .containsExactly(H9, H8, H7, H6, H5, H4, H3, H2, H1);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=incidents")).get(0)).isEqualTo(H1);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&sort=lastdetected")).get(0)).isEqualTo(H1);
    }

    @Test
    void searchMatchesAddressNamesAndAccountsAndViewerOnlyMatchesMaskedText() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=alice"))).containsExactly(H1);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=" + enc("  ALICE.Kim "))))
                .as("앞뒤 공백을 떼고 대소문자를 가리지 않는다").containsExactly(H1);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=10.46.1"))).containsExactly(H1, H2);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=dev-box"))).containsExactly(H2);
        // 줄에 싣지 않은 6번째부터의 이름·계정에도 맞는다
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=u6.six"))).containsExactly(H8);
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=node-172.20.5.80"))).containsExactly(H8);
        JsonNode none = getJson(a, "/api/hosts?period=all&q=no-such-host");
        assertThat(none.get("total").asLong()).isZero();
        assertThat(none.get("items")).isEmpty();
        // 빈 검색어는 조건 없음, 숨김 캡처의 계정으로는 찾지 못한다
        assertThat(getJson(a, "/api/hosts?period=all&q=" + enc("   ")).get("total").asLong()).isEqualTo(9);
        assertThat(getJson(a, "/api/hosts?period=all&q=hidden.user").get("total").asLong()).isZero();
        // 검색과 전환만 보기를 함께 걸면 둘 다 맞는 줄만
        assertThat(hostIps(getJson(a, "/api/hosts?period=all&q=10.4&roleTransitionOnly=true"))).containsExactly(H1, H7);
        // 정확히 100자는 받는다
        assertThat(getJson(a, "/api/hosts?period=all&q=" + "x".repeat(100)).get("total").asLong()).isZero();

        MockHttpSession v = login(UserRole.VIEWER, HOST_PATTERNS);
        // 조회자는 원문으로 찾아도 가린 글에 없으면 맞지 않는다
        for (String raw : List.of("alice", "10.46.1.10", "46.1", "1.10", "bob.lee", "node-172.20.5.80", "u6.six")) {
            assertThat(getJson(v, "/api/hosts?period=all&q=" + raw).get("total").asLong()).as(raw).isZero();
        }
        assertThat(hostIps(getJson(v, "/api/hosts?period=all&q=" + enc("a***")))).containsExactly("10.46.*.*");
        assertThat(hostIps(getJson(v, "/api/hosts?period=all&q=" + enc("10.46.*")))).containsExactly("10.46.*.*");
        assertThat(hostIps(getJson(v, "/api/hosts?period=all&q=10.4"))).containsExactly("10.46.*.*", "10.48.*.*", "10.47.*.*");
        assertThat(hostIps(getJson(v, "/api/hosts?period=all&q=" + enc("node-172.20.*")))).containsExactly("172.20.*.*");
        assertThat(hostIps(getJson(v, "/api/hosts?period=all&q=ws-fin"))).containsExactly("10.46.*.*");
    }

    @Test
    void overCapIs400AndPagingClampsAndQueryCountDoesNotGrowWithHosts() throws Exception {
        MockHttpSession small = login(UserRole.ANALYST, HOST_PATTERNS);
        clearSpies();
        assertThat(getJson(small, "/api/hosts?period=all").get("total").asLong()).isEqualTo(9);
        int zeekadCallsNine = Mockito.mockingDetails(zeekadReadMapper).getInvocations().size();
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findUnifiedQueue(ArgumentMatchers.any());
        Mockito.verify(hostReadMapper, Mockito.times(1)).findRawAssetNamesForHosts(ArgumentMatchers.any(), ArgumentMatchers.any());
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);
        clearSpies();
        assertThat(getJson(small, "/api/hosts?period=all&source=imported").get("total").asLong()).isEqualTo(1);
        assertThat(Mockito.mockingDetails(zeekadReadMapper).getInvocations()).hasSize(zeekadCallsNine);
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);

        // 조건 안 큐 행이 5,000건을 넘으면 400(큐 자산 검색과 같은 응답)
        JdbcTemplate jdbc = jdbc();
        job(96900, CAP_BIG, "2026-11-20T09:00:00Z");
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role, "
                + "event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                + "SELECT 96900, CAST(? AS VARCHAR), 'zeekad-fusion/1', CAST(\"X\" AS INT), CONCAT(CAST(? AS VARCHAR), '|big|', \"X\"), "
                + "CONCAT('10.9.', CAST(\"X\" / 250 AS INT), '.', CAST(MOD(\"X\", 250) AS INT)), 'originator', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 08:00:00Z', TIMESTAMP WITH TIME ZONE '2026-11-20 08:05:00Z', 'hbos', NULL, 1, NULL "
                + "FROM SYSTEM_RANGE(1, 5001)", CAP_BIG, CAP_BIG + tag);
        MockHttpSession big = login(UserRole.ANALYST, "t46big-*");
        mockMvc.perform(get("/api/hosts").param("period", "all").session(big))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("QUERY_TOO_BROAD"))
                .andExpect(jsonPath("$.message").value("기간이나 수집원을 좁혀 주세요"));
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), names.get(big), 10)).isEmpty();

        // 정확히 5,000건이면 받는다. 호스트가 5,000개여도 읽기 질의 수는 9개일 때와 같다
        jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = 96900 AND queue_rank = 5001");
        clearSpies();
        JsonNode first = getJson(big, "/api/hosts?period=all&sort=hostIp&size=100");
        assertThat(Mockito.mockingDetails(zeekadReadMapper).getInvocations()).hasSize(zeekadCallsNine);
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);
        assertThat(first.get("total").asLong()).isEqualTo(5000);
        assertThat(first.get("pageCount").asInt()).isEqualTo(50);
        assertThat(first.get("items")).hasSize(100);
        assertThat(sumIncidentsAllPages(big, "/api/hosts?period=all&sort=hostIp&size=100", 50)).isEqualTo(5000);

        // 쪽 이음: 겹치거나 빠지지 않고 글자 순이다
        List<String> joined = new ArrayList<>();
        for (int p = 1; p <= 3; p++) {
            JsonNode page = getJson(big, "/api/hosts?period=all&sort=hostIp&size=100&page=" + p);
            assertThat(page.get("page").asInt()).isEqualTo(p);
            joined.addAll(hostIps(page));
        }
        assertThat(joined).hasSize(300).doesNotHaveDuplicates().isSortedAccordingTo(Comparator.naturalOrder());
        // 쪽 크기·번호 규칙은 큐와 같다: 허용 밖 크기는 기본 50, 잘못된 번호는 1쪽, 범위 밖은 마지막 쪽
        JsonNode def = getJson(big, "/api/hosts?period=all&size=7&page=abc");
        assertThat(def.get("size").asInt()).isEqualTo(50);
        assertThat(def.get("page").asInt()).isEqualTo(1);
        assertThat(def.get("pageCount").asInt()).isEqualTo(100);
        assertThat(getJson(big, "/api/hosts?period=all&size=25&page=0").get("page").asInt()).isEqualTo(1);
        JsonNode last = getJson(big, "/api/hosts?period=all&size=25&page=99999");
        assertThat(last.get("page").asInt()).isEqualTo(200);
        assertThat(last.get("items")).hasSize(25);

        // 조회자에게는 5,000개 호스트가 대역 한 줄이다(줄 수로 원문 호스트 수가 드러나지 않는다)
        MockHttpSession bigViewer = login(UserRole.VIEWER, "t46big-*");
        JsonNode masked = getJson(bigViewer, "/api/hosts?period=all");
        assertThat(hostIps(masked)).containsExactly("10.9.*.*");
        assertThat(masked.at("/items/0/incidents").asLong()).isEqualTo(5000);
    }

    /* ───────────── 검증·권한·감사·건수 일치 ───────────── */

    @Test
    void invalidValuesAre400WithoutAuditAndDeniedCaptureIs403WithOneIdorAudit() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        String user = names.get(a);
        String marker = "ZZ_INPUT_MARKER";
        List<String> bad = List.of(
                "period=all&sort=" + marker, "period=all&sort=priority", "period=all&dir=" + marker, "period=all&dir=up",
                "period=all&roleTransitionOnly=" + marker, "period=all&roleTransitionOnly=1", "period=all&roleTransitionOnly=yes",
                "period=all&q=" + marker + "x".repeat(101 - marker.length()),
                "period=" + marker, "period=all&source=" + marker, "period=custom", "period=all&start=2026-11-19T00:00:00Z");
        for (String q : bad) {
            MvcResult r = mockMvc.perform(get(URI.create("/api/hosts?" + q)).session(a))
                    .andExpect(status().isBadRequest()).andReturn();
            String body = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
            JsonNode json = objectMapper.readTree(body);
            assertThat(json.get("code").asText()).as(q).isEqualTo("INVALID_REQUEST");
            assertThat(json.get("message").asText()).as(q).matches(".*[가-힣].*");
            // 오류 문장에 입력 값을 넣지 않는다
            assertThat(body).as(q).doesNotContain(marker);
        }
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).isEmpty();

        // 허용 밖 캡처는 403과 감사 1건. 잘못된 sort가 함께 와도 403이다(조건을 먼저 본다)
        mockMvc.perform(get("/api/hosts?period=all&captureId=" + HIDDEN + "&sort=" + marker).session(a))
                .andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(1);
        // 없는 캡처도 같은 403과 감사 1건
        mockMvc.perform(get("/api/hosts?period=all&captureId=t46-no-such-capture").session(a))
                .andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(2);

        // 비로그인은 401
        mockMvc.perform(get("/api/hosts?period=all")).andExpect(status().isUnauthorized());
        // 정상 목록 조회는 원문 열람 감사를 남기지 않는다(상세만 남긴다)
        getJson(a, "/api/hosts?period=all");
        getJson(a, "/api/hosts?period=all&q=alice&sort=hostIp");
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), user, 10)).isEmpty();

        // 화면 경로 /hosts: 조회자·분석가 모두 셸을 받는다(관리자 전용 경로가 아니다)
        for (UserRole role : List.of(UserRole.VIEWER, UserRole.ANALYST)) {
            mockMvc.perform(get("/hosts").session(login(role, HOST_PATTERNS)))
                    .andExpect(status().isOk())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl("/index.html"));
        }

        // 허용 캡처가 없는 사용자: 빈 목록(오류가 아니다), 매퍼를 부르지 않는다
        MockHttpSession nobody = login(UserRole.ANALYST, "t46-none-*");
        clearSpies();
        JsonNode empty = getJson(nobody, "/api/hosts?period=all&roleTransitionOnly=true&q=x");
        assertThat(empty.get("total").asLong()).isZero();
        assertThat(empty.get("items")).isEmpty();
        assertThat(empty.get("sources")).isEmpty();
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(ArgumentMatchers.any());
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).isEmpty();
    }

    @Test
    void sumOfIncidentsEqualsQueueSummaryTotalForTheSameCondition() throws Exception {
        String custom = "period=custom&start=" + enc("2026-11-20T09:00:00Z") + "&end=" + enc("2026-11-20T10:30:00Z");
        for (UserRole role : List.of(UserRole.ANALYST, UserRole.VIEWER)) {
            MockHttpSession s = login(role, HOST_PATTERNS);
            Map<String, Long> expected = new HashMap<>();
            for (String cond : List.of("period=all", "period=7d", "period=24h", "period=1h", "period=all&source=live",
                    "period=all&source=imported", "period=all&captureId=" + CAP_B, "period=30d&captureId=" + CAP_A, custom)) {
                long queueTotal = getJson(s, "/api/incidents/queue?" + cond).at("/summary/total").asLong();
                JsonNode hosts = getJson(s, "/api/hosts?" + cond);
                assertThat(sumIncidents(hosts)).as("%s %s", role, cond).isEqualTo(queueTotal);
                expected.put(cond, queueTotal);
            }
            // 시험 자료가 0 = 0으로 통과하지 않게 값을 못 박는다
            assertThat(expected.get("period=all")).isEqualTo(17);
            assertThat(expected.get("period=7d")).isEqualTo(15);
            assertThat(expected.get("period=24h")).isEqualTo(15);
            assertThat(expected.get("period=1h")).isZero();
            assertThat(expected.get("period=all&source=imported")).isEqualTo(1);
            assertThat(expected.get("period=all&captureId=" + CAP_B)).isEqualTo(2);
            // 지정 기간 (09:00, 10:30]: lab-t46a의 10:00 탐지만(08:00에 처음 탐지된 H1 한 건은 빠진다)
            assertThat(expected.get(custom)).isEqualTo(12);
        }
    }

    /**
     * T45 계약: 화면은 줄을 /incidents?&lt;지금 조건&gt;&amp;hostIp=&lt;hostIp&gt;로 잇는다.
     * 그래서 줄의 incidents는 같은 조건 큐 hostIp= 목록의 total과 같아야 한다(분석가는 원문 주소, 조회자는 가려진 대역).
     */
    @Test
    void rowIncidentsEqualQueueTotalFilteredByThatHostIpForTheSameCondition() throws Exception {
        String custom = "period=custom&start=" + enc("2026-11-20T09:00:00Z") + "&end=" + enc("2026-11-20T10:30:00Z");
        Map<UserRole, Integer> rowsAtAll = new HashMap<>();
        for (UserRole role : List.of(UserRole.ANALYST, UserRole.VIEWER)) {
            MockHttpSession s = login(role, HOST_PATTERNS);
            for (String cond : List.of("period=all", "period=7d", "period=all&source=live", "period=all&source=imported",
                    "period=all&captureId=" + CAP_B, "period=30d&captureId=" + CAP_A, custom)) {
                JsonNode hosts = getJson(s, "/api/hosts?" + cond);
                assertThat(hosts.get("pageCount").asInt()).isEqualTo(1);
                assertThat(hosts.get("items")).as("%s %s", role, cond).isNotEmpty();
                for (JsonNode it : hosts.get("items")) {
                    String hostIp = it.get("hostIp").asText();
                    JsonNode queue = getJson(s, "/api/incidents/queue?" + cond + "&hostIp=" + enc(hostIp));
                    assertThat(queue.get("total").asLong()).as("%s %s hostIp=%s", role, cond, hostIp)
                            .isEqualTo(it.get("incidents").asLong());
                    assertThat(queue.at("/summary/total").asLong()).isEqualTo(it.get("incidents").asLong());
                }
                if ("period=all".equals(cond)) {
                    rowsAtAll.put(role, hosts.get("items").size());
                }
            }
        }
        // 0 = 0으로 통과하지 않게: 분석가 9줄(원문 주소), 조회자 5줄(대역)을 실제로 돌았다
        assertThat(rowsAtAll).containsEntry(UserRole.ANALYST, 9).containsEntry(UserRole.VIEWER, 5);
        // 분석가가 조회자에게 받은 대역 링크(A.B.*.*)도 같은 건수다: H1 3 + H2 2 + H3 2
        MockHttpSession a = login(UserRole.ANALYST, HOST_PATTERNS);
        assertThat(getJson(a, "/api/incidents/queue?period=all&hostIp=" + enc("10.46.*.*")).get("total").asLong()).isEqualTo(7);
    }

    /* ───────────── 같은 호스트 인시던트 ───────────── */

    @Test
    void relatedPicksNearestTenExcludingSelfEvenWhenCalledWithOldJobRow() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, RELATED_PATTERNS);
        String selfId = id(CAP_R, SELF_HOST, "self");
        for (String url : List.of("/api/incidents/96061/rank/1/related-host-incidents",
                // 상세가 옛 작업 행을 보고 있어도(같은 인시던트가 최신 큐에도 있다) 자신이 남지 않는다
                "/api/incidents/96060/rank/1/related-host-incidents")) {
            String body = getBody(a, url);
            JsonNode res = objectMapper.readTree(body);
            assertThat(res.get("maskedView").asBoolean()).isFalse();
            assertThat(res.get("hostIp").asText()).isEqualTo(SELF_HOST);
            // 자신을 뺀 전체: lab-t46r 12건 + lab-t46s 2건. 같은 대역의 다른 호스트와 숨김 캡처는 세지 않는다
            assertThat(res.get("total").asLong()).as(url).isEqualTo(14);
            assertThat(res.get("items")).hasSize(10);
            // 고르기: 시간 차 → 탐지 시각 최근(±80분 셋 가운데 lab-t46s가 먼저) / 응답: 발생 시각 최근 → 캡처 → 순위
            assertThat(keys(res)).as(url).containsExactly(CAP_S + "/2", CAP_R + "/9", CAP_R + "/7", CAP_R + "/5",
                    CAP_R + "/3", CAP_R + "/2", CAP_S + "/1", CAP_R + "/4", CAP_R + "/6", CAP_R + "/8");
            assertThat(body).doesNotContain(HIDDEN).doesNotContain("10.50.9.9").doesNotContain("incidentId").doesNotContain(selfId);
            for (JsonNode it : res.get("items")) {
                assertThat(it.get("hostIp").asText()).isEqualTo(SELF_HOST);
                assertThat(it.get("jobId").asLong()).isIn(96061L, 96070L);
            }
        }
        JsonNode res = getJson(a, "/api/incidents/96061/rank/1/related-host-incidents");
        // 항목 값: 우선순위·탐지 시각은 큐 식에서 읽은 값이다
        JsonNode r4 = item(res, CAP_R, 4);
        assertThat(r4.get("priority").isNull()).isTrue();
        assertThat(r4.get("zeekadStatus").asText()).isEqualTo("closed");
        assertThat(r4.get("zeekadResolution").asText()).isEqualTo("true_positive");
        JsonNode r5 = item(res, CAP_R, 5);
        assertThat(r5.get("priority").asText()).isEqualTo("medium");
        assertThat(r5.get("zeekadRole").asText()).isEqualTo("responder");
        assertThat(r5.get("zeekadPickedBy").asText()).isEqualTo("iforest");
        assertThat(r5.get("connectionCount").asLong()).isEqualTo(55);
        assertThat(Instant.parse(r5.get("eventStart").asText())).isEqualTo(SELF_START.plusMinutes(30).toInstant());
        assertThat(Instant.parse(r5.get("detectedAt").asText())).isEqualTo(Instant.parse("2026-11-20T10:00:00Z"));
        assertThat(item(res, CAP_R, 2).get("priority").asText()).isEqualTo("low");
        // 번호: 번호 행이 있으면 그 값, 없으면 null(작업·순위로 잇는다)
        assertThat(r5.get("incidentNo").asLong()).isEqualTo(no(id(CAP_R, SELF_HOST, "r5")));
        JsonNode s1 = item(res, CAP_S, 1);
        assertThat(s1.get("incidentNo").isNull()).isTrue();
        assertThat(s1.get("jobId").asLong()).isEqualTo(96070);
        assertThat(s1.get("queueRank").asInt()).isEqualTo(1);
        assertThat(Instant.parse(s1.get("detectedAt").asText())).isEqualTo(Instant.parse("2026-11-20T11:00:00Z"));

        // 허용 캡처가 lab-t46r뿐이면 그 안의 12건만. ±80분 둘(순위 10·11)이 모두 든다
        MockHttpSession onlyR = login(UserRole.ANALYST, CAP_R);
        JsonNode narrow = getJson(onlyR, "/api/incidents/96061/rank/1/related-host-incidents");
        assertThat(narrow.get("total").asLong()).isEqualTo(12);
        assertThat(keys(narrow)).containsExactly(CAP_R + "/11", CAP_R + "/9", CAP_R + "/7", CAP_R + "/5", CAP_R + "/3",
                CAP_R + "/2", CAP_R + "/4", CAP_R + "/6", CAP_R + "/8", CAP_R + "/10");
        // 다른 인시던트가 없는 호스트: 0건
        JsonNode lonely = getJson(a, "/api/incidents/96061/rank/14/related-host-incidents");
        assertThat(lonely.get("hostIp").asText()).isEqualTo("10.50.9.9");
        assertThat(lonely.get("total").asLong()).isZero();
        assertThat(lonely.get("items")).isEmpty();
    }

    @Test
    void relatedForViewerIsSameMaskedRangeWithoutFullIpv4OrIncidentId() throws Exception {
        MockHttpSession v = login(UserRole.VIEWER, RELATED_PATTERNS);
        for (String url : List.of("/api/incidents/96061/rank/1/related-host-incidents",
                "/api/incidents/96060/rank/1/related-host-incidents")) {
            String body = getBody(v, url);
            JsonNode res = objectMapper.readTree(body);
            assertThat(res.get("maskedView").asBoolean()).isTrue();
            assertThat(res.get("hostIp").asText()).isEqualTo("10.50.*.*");
            // 같은 대역: 같은 호스트 14건 + 같은 대역의 다른 호스트 1건
            assertThat(res.get("total").asLong()).isEqualTo(15);
            assertThat(keys(res)).as(url).containsExactly(CAP_R + "/9", CAP_R + "/7", CAP_R + "/5", CAP_R + "/3",
                    CAP_R + "/14", CAP_R + "/2", CAP_S + "/1", CAP_R + "/4", CAP_R + "/6", CAP_R + "/8");
            for (JsonNode it : res.get("items")) {
                assertThat(it.get("hostIp").asText()).isEqualTo("10.50.*.*");
            }
            assertNoFullIpv4(body);
            assertThat(body).doesNotContain("incidentId").doesNotContain(tag).doesNotContain(HIDDEN);
        }
        // 대역의 다른 호스트에서 열어도 같은 대역이다(자신만 빠진다)
        JsonNode other = getJson(v, "/api/incidents/96061/rank/14/related-host-incidents");
        assertThat(other.get("total").asLong()).isEqualTo(15);
        // 조회자는 대역의 원문 주소를 고르는 조회까지 2회
        clearSpies();
        getJson(v, "/api/incidents/96061/rank/1/related-host-incidents");
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findDistinctLatestHostIps(ArgumentMatchers.any());
        Mockito.verify(hostReadMapper, Mockito.times(1))
                .findLatestQueueByHostIps(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), names.get(v), 10)).isEmpty();
    }

    @Test
    void relatedDeniesLikeDetailAndNeverWritesNumbersOrAuditsAndUsesFixedQueryCount() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, RELATED_PATTERNS);
        String user = names.get(a);
        String s1 = id(CAP_S, SELF_HOST, "s1");
        assertThat(countRefs(s1)).isZero();

        // 읽기 질의 수: 분석가는 큐 식 1회. 관련 인시던트가 14건이든 0건이든 같다
        clearSpies();
        assertThat(getJson(a, "/api/incidents/96061/rank/1/related-host-incidents").get("total").asLong()).isEqualTo(14);
        int zeekadCalls = Mockito.mockingDetails(zeekadReadMapper).getInvocations().size();
        Mockito.verify(hostReadMapper, Mockito.times(1))
                .findLatestQueueByHostIps(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findDistinctLatestHostIps(ArgumentMatchers.any());
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);
        // 큐 목록 질의를 따로 부르지 않는다(허용 캡처 최신 큐 전체를 Java로 읽어 와 거르지 않는다)
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(ArgumentMatchers.any());
        // 번호는 읽기만: 넣기 호출 0회, 번호 행이 여전히 없다
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());
        Mockito.verify(refMapper, Mockito.times(1)).findByIncidentIds(ArgumentMatchers.any());
        assertThat(countRefs(s1)).isZero();
        clearSpies();
        assertThat(getJson(a, "/api/incidents/96061/rank/14/related-host-incidents").get("total").asLong()).isZero();
        assertThat(Mockito.mockingDetails(zeekadReadMapper).getInvocations()).hasSize(zeekadCalls);
        assertThat(Mockito.mockingDetails(hostReadMapper).getInvocations()).hasSize(1);
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());

        // 이 API는 원문 열람 감사를 남기지 않는다(상세 열람 때 이미 남는다)
        assertThat(auditLogMapper.findFiltered(AuditActionType.INCIDENT_VIEW_UNMASKED.name(), user, 10)).isEmpty();
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).isEmpty();

        // 허용 밖 캡처의 인시던트: 403과 감사 1건(상세와 같은 검사)
        MockHttpSession onlyS = login(UserRole.ANALYST, CAP_S);
        String denied = mockMvc.perform(get("/api/incidents/96061/rank/1/related-host-incidents").session(onlyS))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), names.get(onlyS), 10)).hasSize(1);
        // 없는 작업·없는 순위는 상세 API와 같은 응답(403)이고 감사가 남는다
        String detailDenied = mockMvc.perform(get("/api/incidents/96061/rank/1").session(onlyS))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(denied).isEqualTo(detailDenied);
        mockMvc.perform(get("/api/incidents/96999/rank/1/related-host-incidents").session(a)).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/96061/rank/999/related-host-incidents").session(a)).andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(2);
        // 형식 오류는 상세 API와 같은 400이고 감사가 없다
        for (String bad : List.of("/api/incidents/abc/rank/1/related-host-incidents",
                "/api/incidents/96061/rank/x/related-host-incidents")) {
            mockMvc.perform(get(bad).session(a)).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        }
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), user, 10)).hasSize(2);
        // 비로그인은 401
        mockMvc.perform(get("/api/incidents/96061/rank/1/related-host-incidents")).andExpect(status().isUnauthorized());

        // 상세 응답은 그대로다: 같은 호스트 목록을 싣지 않는다
        JsonNode detail = getJson(a, "/api/incidents/96061/rank/1");
        assertThat(detail.at("/detail/relatedHostIncidents").isMissingNode()).isTrue();
        assertThat(detail.has("relatedHostIncidents")).isFalse();
    }

    /* ───────────── 시험 자료 ───────────── */

    private void seedHosts() {
        String wsNames = "ARRAY['ws-fin-01.corp.local', 'ws-fin-01']";
        // lab-t46a 옛 작업: H1의 첫 행(최신 작업에도 있다 = 탐지 08:00)과 옛 작업에만 있는 행
        job(96010, CAP_A, "2026-11-20T08:00:00Z");
        incident(96010, CAP_A, 1, H1, "responder", "2026-11-20T01:00:00Z", 100, "iforest", "ARRAY['hbos']", wsNames, "a1");
        incident(96010, CAP_A, 2, H1, "originator", "2026-11-19T23:00:00Z", 77, "hbos", "NULL", "NULL", "old-only");
        job(96011, CAP_A, "2026-11-20T10:00:00Z");
        incident(96011, CAP_A, 1, H1, "responder", "2026-11-20T01:00:00Z", 100, "iforest", "ARRAY['hbos']", wsNames, "a1");
        incident(96011, CAP_A, 2, H1, "originator", "2026-11-20T02:00:00Z", 50, "iforest", "NULL",
                "ARRAY['ws-fin-01.corp.local']", "a2");
        high(96011, id(CAP_A, H1, "a2"));
        incident(96011, CAP_A, 3, H2, "originator", "2026-11-20T01:00:00Z", 10, "hbos", "NULL", "ARRAY['dev-box-20']", "a3");
        incident(96011, CAP_A, 4, H2, "responder", "2026-11-20T01:00:00Z", 20, "hbos", "NULL", "NULL", "a4");
        markStatus(96011, id(CAP_A, H2, "a4"), "closed", "true_positive");
        incident(96011, CAP_A, 5, H3, "originator", "2026-11-20T01:00:00Z", 5, "autoencoder", "NULL", "NULL", "a5");
        incident(96011, CAP_A, 6, H3, "responder", "2026-11-20T02:00:00Z", 5, "autoencoder", "NULL", "NULL", "a6");
        incident(96011, CAP_A, 7, H4, "responder", "2026-11-20T01:00:00Z", 1, "hbos", "NULL", "NULL", "a7");
        incident(96011, CAP_A, 8, H5, "responder", "2026-11-20T01:00:00Z", 1, "hbos", "NULL", "NULL", "a8");
        markStatus(96011, id(CAP_A, H5, "a8"), "closed", "false_positive");
        incident(96011, CAP_A, 9, H5, "originator", "2026-11-20T02:00:00Z", 1, "hbos", "NULL", "NULL", "a9");
        incident(96011, CAP_A, 10, H6, "responder", "2026-11-20T01:00:00Z", 1, "hbos", "NULL", "NULL", "a10");
        incident(96011, CAP_A, 11, H6, "originator", "2026-11-20T02:00:00Z", 1, "hbos", "NULL", "NULL", "a11");
        markStatus(96011, id(CAP_A, H6, "a11"), " Closed ", " BENIGN ");
        incident(96011, CAP_A, 12, H7, " Responder ", "2026-11-20T01:00:00Z", 1, "hbos", "NULL", "NULL", "a12");
        markStatus(96011, id(CAP_A, H7, "a12"), "closed", "true_positive");
        incident(96011, CAP_A, 13, H7, "ORIGINATOR", "2026-11-20T02:00:00Z", 1, "hbos", "ARRAY['iforest']", "NULL", "a13");

        job(96020, CAP_B, "2026-11-20T11:00:00Z");
        incident(96020, CAP_B, 1, H1, "originator", "2026-11-20T03:00:00Z", 7, "hbos", "NULL", "ARRAY['fin-alias']", "b1");
        incident(96020, CAP_B, 2, H4, "originator", "2026-11-20T02:00:00Z", 1, "hbos", "NULL", "NULL", "b2");

        job(96030, CAP_IMP, "2026-11-10T00:00:00Z");
        incident(96030, CAP_IMP, 1, H8, "originator", "2026-11-09T22:00:00Z", 999, "hbos", "NULL",
                "ARRAY['h1.imp.local', 'h2.imp.local', 'h3.imp.local', 'h4.imp.local', 'h5.imp.local', 'h6.imp.local', "
                        + "'node-172.20.5.80.imp.local']", "c1");

        // 완료 시각이 없는 성공 작업: 최신 큐에는 있지만 탐지 시각이 없다
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (96050, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20T00:00:00Z', NULL, NULL, 0)", CAP_NULL);
        incident(96050, CAP_NULL, 1, H9, "originator", "2026-11-20T01:00:00Z", 3, "hbos", "NULL", "NULL", "n1");

        job(96040, HIDDEN, "2026-11-20T10:00:00Z");
        incident(96040, HIDDEN, 1, H1, "originator", "2026-11-20T05:00:00Z", 4000, "hidden-model", "NULL",
                "ARRAY['hidden-host']", "h1");
        incident(96040, HIDDEN, 2, "10.46.9.99", "originator", "2026-11-20T05:00:00Z", 4000, "hbos", "NULL", "NULL", "h2");
        incident(96040, HIDDEN, 3, SELF_HOST, "originator", minutes(1), 4000, "hbos", "NULL", "NULL", "h3");

        asset(CAP_A, H1, "alice.kim", "kerberos_user", null, null);
        asset(CAP_A, H1, "FINPC-07$", "kerberos_machine", null, null);
        asset(CAP_B, H1, null, null, "bob.lee", "BOB_NT");
        asset(CAP_A, H2, "adam.cho", "kerberos_user", "ignored.krb", "ignored.ntlm");
        asset(HIDDEN, H1, "hidden.user", "kerberos_user", null, null);
        // H2는 lab-t46b 큐에 없다: (캡처, 주소) 쌍이 달라 붙지 않아야 한다
        asset(CAP_B, H2, "ghost.pair", "kerberos_user", null, null);
        for (String name : List.of("u1.one", "u2.two", "u3.three", "u4.four", "u5.five", "u6.six")) {
            asset(CAP_IMP, H8, name, "kerberos_user", null, null);
        }
    }

    private void seedRelated() {
        job(96060, CAP_R, "2026-11-20T08:00:00Z");
        incident(96060, CAP_R, 1, SELF_HOST, "originator", minutes(0), 1, "hbos", "NULL", "NULL", "self");
        job(96061, CAP_R, "2026-11-20T10:00:00Z");
        incident(96061, CAP_R, 1, SELF_HOST, "originator", minutes(0), 1, "hbos", "NULL", "NULL", "self");
        int[] offsets = {-10, 10, -20, 30, -40, 50, -60, 70, -80, 80, -100, 110};
        for (int i = 0; i < offsets.length; i++) {
            int rank = i + 2;
            boolean r5 = rank == 5;
            incident(96061, CAP_R, rank, SELF_HOST, r5 ? "responder" : "originator", minutes(offsets[i]), r5 ? 55 : 1,
                    r5 ? "iforest" : "hbos", r5 ? "ARRAY['hbos']" : "NULL", "NULL", "r" + rank);
        }
        markStatus(96061, id(CAP_R, SELF_HOST, "r4"), "closed", "true_positive");
        incident(96061, CAP_R, 14, "10.50.9.9", "originator", minutes(5), 1, "hbos", "NULL", "NULL", "r14");
    }

    private static String minutes(int offset) {
        return SELF_START.plusMinutes(offset).toString();
    }

    private String id(String capture, String ip, String key) {
        return capture + "|" + ip + "|" + key + "|" + tag;
    }

    private void job(long jobId, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20T00:00:00Z', "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                jobId, capture, finished);
    }

    /** alsoSql·namesSql은 시험 코드가 정한 SQL 조각(NULL 또는 ARRAY[...])이다 */
    private void incident(long jobId, String capture, int rank, String ip, String role, String start, long connections,
                          String pickedBy, String alsoSql, String namesSql, String key) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-20T23:00:00Z', ?, " + alsoSql + ", ?, " + namesSql + ")",
                jobId, capture, rank, id(capture, ip, key), ip, role, start, pickedBy, connections);
    }

    private void markStatus(long jobId, String incidentId, String status, String resolution) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-20T12:00:00Z', 't46')", jobId, incidentId, status, resolution);
    }

    /** 우선순위 high: 리포트와 발송 판단(보냄) */
    private void high(long jobId, String incidentId) {
        jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                + "zeekad_report, created_at) VALUES (?, ?, 'template', 'template.v1', '{}' FORMAT JSON, "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20T10:01:00Z')", jobId, incidentId);
        jdbc().update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                + "VALUES (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-20T10:02:00Z')", jobId, incidentId);
    }

    private void asset(String capture, String ip, String zeekadName, String kind, String kerberos, String ntlm) {
        jdbc().update("INSERT INTO dashboard.raw_asset_names (capture_id, host_ip, kerberos_user, ntlm_user, source_log, "
                + "observation_count, first_seen, last_seen, zeekad_name, zeekad_name_kind) VALUES (?, ?, ?, ?, 'kerberos', 1, "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20T01:00:00Z', TIMESTAMP WITH TIME ZONE '2026-11-20T02:00:00Z', ?, ?)",
                capture, ip, kerberos, ntlm, zeekadName, kind);
    }

    /* ───────────── 도우미 ───────────── */

    private void clearSpies() {
        Mockito.clearInvocations(zeekadReadMapper, hostReadMapper, refMapper);
    }

    private static List<String> hostIps(JsonNode res) {
        List<String> out = new ArrayList<>();
        for (JsonNode it : res.get("items")) {
            out.add(it.get("hostIp").asText());
        }
        return out;
    }

    private static List<String> keys(JsonNode res) {
        List<String> out = new ArrayList<>();
        for (JsonNode it : res.get("items")) {
            out.add(it.get("captureId").asText() + "/" + it.get("queueRank").asInt());
        }
        return out;
    }

    private static JsonNode host(JsonNode res, String hostIp) {
        for (JsonNode it : res.get("items")) {
            if (hostIp.equals(it.get("hostIp").asText())) {
                return it;
            }
        }
        throw new AssertionError("줄 없음: " + hostIp);
    }

    private static JsonNode item(JsonNode res, String capture, int rank) {
        for (JsonNode it : res.get("items")) {
            if (capture.equals(it.get("captureId").asText()) && it.get("queueRank").asInt() == rank) {
                return it;
            }
        }
        throw new AssertionError("항목 없음: " + capture + "/" + rank);
    }

    private static List<String> texts(JsonNode array) {
        List<String> out = new ArrayList<>();
        for (JsonNode n : array) {
            out.add(n.asText());
        }
        return out;
    }

    private static long sumIncidents(JsonNode res) {
        assertThat(res.get("pageCount").asInt()).as("한 쪽에 다 들어와야 합을 낼 수 있다").isEqualTo(1);
        long sum = 0;
        for (JsonNode it : res.get("items")) {
            sum += it.get("incidents").asLong();
        }
        return sum;
    }

    private long sumIncidentsAllPages(MockHttpSession s, String url, int pageCount) throws Exception {
        long sum = 0;
        for (int p = 1; p <= pageCount; p++) {
            for (JsonNode it : getJson(s, url + "&page=" + p).get("items")) {
                sum += it.get("incidents").asLong();
            }
        }
        return sum;
    }

    private static void assertNoFullIpv4(String body) {
        var m = FULL_IPV4.matcher(body);
        while (m.find()) {
            boolean valid = true;
            for (int g = 1; g <= 4; g++) {
                if (Integer.parseInt(m.group(g)) > 255) valid = false;
            }
            assertThat(valid).as("가려지지 않은 IPv4: %s", m.group()).isFalse();
        }
    }

    private long no(String incidentId) {
        Long n = app().queryForObject("SELECT incident_no FROM incident_refs WHERE incident_id = ?", Long.class, incidentId);
        assertThat(n).as(incidentId).isNotNull();
        return n;
    }

    private int countRefs(String incidentId) {
        return app().queryForObject("SELECT COUNT(*) FROM incident_refs WHERE incident_id = ?", Integer.class, incidentId);
    }

    /** MockMvc는 쿼리의 +를 공백으로 풀지 않으므로 공백은 %20으로 적는다 */
    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t46_u" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession s = (MockHttpSession) result.getRequest().getSession(false);
        names.put(s, username);
        return s;
    }

    private String getBody(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(URI.create(url)).session(session)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        return objectMapper.readTree(getBody(session, url));
    }
}
