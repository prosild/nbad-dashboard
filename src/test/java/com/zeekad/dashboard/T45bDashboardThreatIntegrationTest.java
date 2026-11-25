package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.IncidentRefMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.SlackThreadLink;
import com.zeekad.dashboard.service.IncidentRefService;
import com.zeekad.dashboard.service.SlackThreadService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T45b 현황판 위협 가시성: GET /api/dashboard/overview의 attack(ATT&amp;CK 전술·기법 후보 분포),
 * topHosts(통신 방향별 위험 호스트 상위 5), topThreads(주요 알림 묶음 상위 5).
 * 각 수가 같은 조건 큐(attack·role+hostIp·thread 조건)의 total과 같은지 조건을 바꿔 가며 본다.
 *
 * 시험 자료(기준 시각 = 2026-11-21 00:00Z, now 모드. job 98120~98129. 인시던트 ID = 캡처|열쇠|꼬리표):
 *  - lab-t45ba(실습망, 허용) 옛 작업 98120(11-10 00:00): OLDH·KOLD·OLDT(최신 작업에도 있음 = 탐지 11-10), G(옛 작업에만)
 *  - lab-t45ba 최신 작업 98121(11-20 10:00): 호스트 줄 H*·R*, 리포트 후보 K1~K10·KOLD, 묶음 T1~T13·OLDT·GONE, 채움 F1~F30
 *  - t45bi-cap(가져온 데이터, 허용) 98122(11-20 11:00): IH1·IH2·IR2, IK1, IT1~IT6
 *  - lab-t45bh(숨김) 98123(11-20 10:00): HH, HK1, HT1·HT2
 *
 * 호스트(출발지): 10.50.1.1 High 2(두 캡처)·Low 1 / 10.50.1.2 High 2·Medium 1 / 10.50.2.1 High 1 / 10.51.1.1 Medium 2 /
 *  10.51.1.2 Medium 2·종결 1 / 10.52.1.1·.2·.3 Low 1씩 / 10.53.1.1 종결 1 / 10.50.9.9 Low 1(탐지 11-10)
 * 호스트(목적지): 10.60.1.2 Low 1("Responder", 11:00) / 10.60.1.1·10.60.1.3 Low 1(10:00) / 10.60.2.1 종결 1.
 *  통신 방향이 unknown·" responder"·both인 행은 어느 목록에도 없다.
 *
 * 알림 묶음(머리 ← 답글): T1 ← T2·T3(부모 앞뒤 공백)·IT1·HT1 / OLDT(탐지 11-10) ← T4·T5 / IT2 ← IT3 /
 *  HT2(숨김 머리) ← T6 / G(번호 행 없음) ← T2 / T7 혼자 / IT4(자기 Slack 행 없음) ← IT5·IT6 / T8 ← T9 / T10 ← T11 /
 *  GONE ← T12·T13
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t45b_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t45b_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t45b_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T45bDashboardThreatIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    static final String CAP_A = "lab-t45ba";
    static final String CAP_I = "t45bi-cap";
    static final String HIDDEN = "lab-t45bh";
    static final String ALLOWED = "lab-t45ba,t45bi-*";
    static final String EVERYTHING = "lab-t45b*,t45bi-*";
    static final Pattern FULL_IPV4 = Pattern.compile("(?<![0-9.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![0-9.])");
    static final int FILLERS = 30;
    static final String CSI = "Command and Scripting Interpreter";
    static final String CUSTOM = "period=custom&start=2026-11-09T00:00:00Z&end=2026-11-20T10:30:00Z";

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
    @Autowired private MutableTestClock clock;
    @MockitoSpyBean private IncidentRefService refService;
    @MockitoSpyBean private IncidentRefMapper refMapper;
    @MockitoSpyBean private ZeekadReadMapper zeekadReadMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;
    private String tag;

    @BeforeEach
    void setUp() throws Exception {
        clock.set(FIXED_NOW);
        deleteRows();
        tag = "t45bs" + (++seq);

        job(98120, CAP_A, "2026-11-10T00:00:00Z");
        inc(98120, CAP_A, 1, "OLDH", "10.50.9.9", "originator", "low");
        inc(98120, CAP_A, 2, "KOLD", "10.70.0.90", "both", "low");
        inc(98120, CAP_A, 3, "OLDT", "10.80.0.20", "both", "low", "autoencoder");
        inc(98120, CAP_A, 4, "G", "10.80.0.99", "both", "low");

        job(98121, CAP_A, "2026-11-20T10:00:00Z");
        int r = 0;
        inc(98121, CAP_A, ++r, "H1A", "10.50.1.1", "originator", "high");
        inc(98121, CAP_A, ++r, "H1B", "10.50.1.1", "originator", "low");
        inc(98121, CAP_A, ++r, "H2A", "10.50.1.2", "originator", "high");
        inc(98121, CAP_A, ++r, "H2B", "10.50.1.2", "originator", "high");
        inc(98121, CAP_A, ++r, "H2C", "10.50.1.2", "originator", "medium");
        inc(98121, CAP_A, ++r, "H3", "10.50.2.1", "originator", "high");
        inc(98121, CAP_A, ++r, "H4A", "10.51.1.1", "originator", "medium");
        inc(98121, CAP_A, ++r, "H4B", "10.51.1.1", "originator", "medium");
        inc(98121, CAP_A, ++r, "H5A", "10.51.1.2", "originator", "medium");
        inc(98121, CAP_A, ++r, "H5B", "10.51.1.2", "originator", "medium");
        inc(98121, CAP_A, ++r, "H5C", "10.51.1.2", "originator", "closed");
        inc(98121, CAP_A, ++r, "H6", "10.52.1.1", "originator", "low");
        inc(98121, CAP_A, ++r, "H7", "10.52.1.2", "originator", "low");
        inc(98121, CAP_A, ++r, "H8", "10.53.1.1", "originator", "closed");
        inc(98121, CAP_A, ++r, "OLDH", "10.50.9.9", "originator", "low");
        inc(98121, CAP_A, ++r, "R1", "10.60.1.1", "responder", "low");
        inc(98121, CAP_A, ++r, "R3", "10.60.1.3", "responder", "low");
        inc(98121, CAP_A, ++r, "R4", "10.60.2.1", "responder", "closed");
        inc(98121, CAP_A, ++r, "RX1", "10.61.1.1", "unknown", "low");
        inc(98121, CAP_A, ++r, "RX2", "10.61.1.2", " responder", "low");
        for (int k = 1; k <= 10; k++) {
            inc(98121, CAP_A, ++r, "K" + k, "10.70.0." + k, "both", "low");
        }
        inc(98121, CAP_A, ++r, "KOLD", "10.70.0.90", "both", "low");
        for (int k = 1; k <= 13; k++) {
            inc(98121, CAP_A, ++r, "T" + k, "10.80.0." + k, "both", "low");
        }
        inc(98121, CAP_A, ++r, "OLDT", "10.80.0.20", "both", "low", "autoencoder");
        inc(98121, CAP_A, ++r, "GONE", "10.80.0.30", "both", "low");
        for (int k = 1; k <= FILLERS; k++) {
            inc(98121, CAP_A, ++r, "F" + k, "10.90.0." + k, "both", "low");
        }

        job(98122, CAP_I, "2026-11-20T11:00:00Z");
        inc(98122, CAP_I, 1, "IH1", "10.50.1.1", "originator", "high");
        inc(98122, CAP_I, 2, "IH2", "10.52.1.3", "originator", "low");
        inc(98122, CAP_I, 3, "IR2", "10.60.1.2", "Responder", "low");
        inc(98122, CAP_I, 4, "IK1", "10.70.1.1", "both", "low");
        for (int k = 1; k <= 6; k++) {
            inc(98122, CAP_I, 4 + k, "IT" + k, "10.80.1." + k, "both", "low");
        }

        job(98123, HIDDEN, "2026-11-20T10:00:00Z");
        inc(98123, HIDDEN, 1, "HH", "10.50.1.1", "originator", "high");
        inc(98123, HIDDEN, 2, "HK1", "10.70.2.1", "both", "low");
        inc(98123, HIDDEN, 3, "HT1", "10.80.2.1", "both", "low");
        inc(98123, HIDDEN, 4, "HT2", "10.80.2.2", "both", "low");

        // 리포트의 ATT&CK 후보
        report(98121, a("K1"), "[" + cand("T1059", CSI, "[\"Execution\"]") + ","
                + cand("T1558.003", "Kerberoasting", "[\"Credential Access\"]") + ","
                + cand("T1059", CSI, "[\"execution\"]") + "]");
        report(98121, a("K2"), "[" + cand(" t1059 ", "Cmd Interp", "[\"execution\"]") + "]");
        report(98121, a("K3"), "[" + cand("T1059", CSI, "\"Execution\"") + "]");
        report(98121, a("K4"), "[" + cand("T1110", "Brute Force 10.70.9.9 host",
                "[\"credential_access\",\"Command and Control\",\"t1059\",\"x\",\"Bad/Tactic\"]") + "]");
        report(98121, a("K5"), "[" + cand("TA0001", "n", "[\"Initial Access\"]") + "]");
        report(98121, a("K6"), "[" + cand("bogus", "n", "[]") + "]");
        report(98121, a("K7"), null);
        report(98121, a("K8"), "[]");
        StringBuilder many = new StringBuilder("[" + cand("T2001", "Zeta", "[\"Discovery\"]")
                + ",{\"attack_id\":\"T2002\"}");
        for (int k = 3; k <= 11; k++) {
            many.append(",").append(cand(String.format("T20%02d", k), "n", "[]"));
        }
        report(98121, a("K9"), many.append("]").toString());
        report(98121, a("K10"), "[" + cand("T2001", "Alpha", "[]") + "]");
        report(98121, a("KOLD"), "[" + cand("T1021", "Remote Services", "[\"Lateral Movement\"]") + "]");
        report(98122, i("IK1"), "[" + cand("T1059", CSI, "[\"Credential Access\"]") + "]");
        report(98123, h("HK1"), "[" + cand("T1059", CSI, "[\"Impact\"]") + "]");

        // 알림 묶음
        int m = 0;
        slack(98121, a("T1"), null, m++);
        slack(98121, a("T2"), a("T1"), m++);
        slack(98121, a("T3"), "  " + a("T1") + " ", m++);
        slack(98122, i("IT1"), a("T1"), m++);
        slack(98123, h("HT1"), a("T1"), m++);
        slack(98121, a("OLDT"), null, m++);
        slack(98121, a("T4"), a("OLDT"), m++);
        slack(98121, a("T5"), a("OLDT"), m++);
        slack(98122, i("IT2"), null, m++);
        slack(98122, i("IT3"), i("IT2"), m++);
        slack(98123, h("HT2"), null, m++);
        slack(98121, a("T6"), h("HT2"), m++);
        slack(98121, a("T2"), a("G"), m++);
        slack(98121, a("T7"), null, m++);
        slack(98122, i("IT5"), i("IT4"), m++);
        slack(98122, i("IT6"), i("IT4"), m++);
        slack(98121, a("T8"), null, m++);
        slack(98121, a("T9"), a("T8"), m++);
        slack(98121, a("T10"), null, m++);
        slack(98121, a("T11"), a("T10"), m++);
        slack(98121, a("GONE"), null, m++);
        slack(98121, a("T12"), a("GONE"), m++);
        slack(98121, a("T13"), a("GONE"), m++);
        for (int k = 1; k <= FILLERS; k++) {
            slack(98121, a("F" + k), null, 25 + k % 30);
        }

        refService.syncAll();
        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
    }

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        deleteRows();
        Mockito.reset(refService, refMapper, zeekadReadMapper);
    }

    /* ───────────── attack ───────────── */

    @Test
    void attackDistributionDedupesNormalizesOrdersAndCutsToTopTen() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        JsonNode attack = getJson(a, "/api/dashboard/overview?period=24h").get("attack");

        // 후보가 있는 인시던트: K1·K2·K3·K4·K5·K9·K10·IK1(K6 셀 값 없음, K7 열 값 없음, K8 빈 배열, KOLD 기간 밖)
        assertThat(attack.get("incidentsWithCandidates").asLong()).isEqualTo(8);
        // 전술: 제목 표기·밑줄·소문자가 같은 전술, 글 하나짜리 tactics도 읽는다. count DESC → tactic ASC
        assertThat(pairs(attack.get("tactics"), "tactic")).containsExactly(
                "credential-access=3", "execution=3", "command-and-control=1", "discovery=1", "initial-access=1");
        // 기법 ID 꼴 전술(t1059), 슬러그가 안 되는 값(x, Bad/Tactic), ID 꼴이 아닌 attack_id(TA0001·bogus)는 세지 않는다
        assertThat(attack.toString()).doesNotContain("\"t1059\"").doesNotContain("TA0001").doesNotContain("bogus")
                .doesNotContain("bad");
        // 기법: 한 인시던트에 같은 ID가 두 번(K1)이어도 한 번, 소문자·공백(K2)도 같은 ID. 고유 14개 가운데 상위 10개
        assertThat(attack.get("techniqueCount").asInt()).isEqualTo(14);
        assertThat(pairs(attack.get("techniques"), "attackId")).containsExactly(
                "T1059=4", "T2001=2", "T1110=1", "T1558.003=1", "T2002=1", "T2003=1", "T2004=1", "T2005=1",
                "T2006=1", "T2007=1");
        Map<String, JsonNode> byId = byField(attack.get("techniques"), "attackId");
        // 이름: 가장 많은 인시던트에 붙은 것(CSI 3 : Cmd Interp 1), 같으면 글자 순으로 앞(Alpha < Zeta), 없으면 null
        assertThat(byId.get("T1059").get("name").asText()).isEqualTo(CSI);
        assertThat(byId.get("T2001").get("name").asText()).isEqualTo("Alpha");
        assertThat(byId.get("T2002").get("name").isNull()).isTrue();
        assertThat(byId.get("T1110").get("name").asText()).isEqualTo("Brute Force 10.70.9.9 host");

        // 조회자: 같은 수, 이름의 주소는 가린다
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        JsonNode vAttack = getJson(v, "/api/dashboard/overview?period=24h").get("attack");
        assertThat(pairs(vAttack.get("tactics"), "tactic")).isEqualTo(pairs(attack.get("tactics"), "tactic"));
        assertThat(pairs(vAttack.get("techniques"), "attackId")).isEqualTo(pairs(attack.get("techniques"), "attackId"));
        assertThat(byField(vAttack.get("techniques"), "attackId").get("T1110").get("name").asText())
                .isEqualTo("Brute Force 10.70.*.* host");

        // 기간 전체: 11-10에 탐지된 KOLD(T1021·lateral-movement)가 더해진다
        JsonNode all = getJson(a, "/api/dashboard/overview?period=all").get("attack");
        assertThat(all.get("incidentsWithCandidates").asLong()).isEqualTo(9);
        assertThat(all.get("techniqueCount").asInt()).isEqualTo(15);
        assertThat(pairs(all.get("tactics"), "tactic")).contains("lateral-movement=1");
        assertThat(pairs(all.get("techniques"), "attackId")).contains("T1021=1").doesNotContain("T2007=1");
        // 수집원: 실습망만이면 IK1이 빠진다. 숨김 캡처(HK1)는 허용한 사용자에게만 더해진다
        JsonNode live = getJson(a, "/api/dashboard/overview?period=24h&source=live").get("attack");
        assertThat(pairs(live.get("techniques"), "attackId")).contains("T1059=3");
        assertThat(pairs(live.get("tactics"), "tactic")).contains("execution=3", "credential-access=2");
        assertThat(attack.toString()).doesNotContain("impact");
        MockHttpSession every = login(UserRole.ANALYST, EVERYTHING);
        JsonNode eAttack = getJson(every, "/api/dashboard/overview?period=24h").get("attack");
        assertThat(pairs(eAttack.get("techniques"), "attackId")).contains("T1059=5");
        assertThat(pairs(eAttack.get("tactics"), "tactic")).contains("impact=1");
    }

    /* ───────────── topHosts ───────────── */

    @Test
    void topHostsRankByOpenPriorityAndGroupByRawAddressForAnalyst() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        JsonNode hosts = getJson(a, "/api/dashboard/overview?period=24h").get("topHosts");
        // high DESC → medium DESC → low DESC → total DESC. 여러 캡처의 같은 주소(10.50.1.1)는 한 줄, 숨김 캡처는 세지 않는다
        assertThat(hostLines(hosts.get("originator"))).containsExactly(
                "10.50.1.2 2/1/0/3", "10.50.1.1 2/0/1/3", "10.50.2.1 1/0/0/1", "10.51.1.2 0/2/0/3", "10.51.1.1 0/2/0/2");
        assertThat(hosts.get("originator").get(1).get("lastDetectedAt").asText()).startsWith("2026-11-20T11:00");
        assertThat(hosts.get("originator").get(0).get("lastDetectedAt").asText()).startsWith("2026-11-20T10:00");
        // 목적지: 통신 방향은 소문자로만 바꿔 맞춘다("Responder"는 들어가고 " responder"·unknown·both는 빠진다).
        // 동률이면 마지막 탐지 시각이 늦은 쪽(10.60.1.2, 11:00) → 주소 순(10.60.1.1 < 10.60.1.3). 종결만 있는 호스트는 뒤
        assertThat(hostLines(hosts.get("responder"))).containsExactly(
                "10.60.1.2 0/0/1/1", "10.60.1.1 0/0/1/1", "10.60.1.3 0/0/1/1", "10.60.2.1 0/0/0/1");
        assertThat(hosts.toString()).doesNotContain("10.61.").doesNotContain("10.70.").doesNotContain("10.80.");

        // 가져온 데이터만: 출발지 2줄(High가 앞), 목적지 1줄
        JsonNode imported = getJson(a, "/api/dashboard/overview?period=24h&source=imported").get("topHosts");
        assertThat(hostLines(imported.get("originator"))).containsExactly("10.50.1.1 1/0/0/1", "10.52.1.3 0/0/1/1");
        assertThat(hostLines(imported.get("responder"))).containsExactly("10.60.1.2 0/0/1/1");
        // 숨김 캡처까지 허용하면 10.50.1.1에 High 1건이 더해진다
        MockHttpSession every = login(UserRole.ANALYST, EVERYTHING);
        assertThat(hostLines(getJson(every, "/api/dashboard/overview?period=24h").at("/topHosts/originator")))
                .startsWith("10.50.1.1 3/0/1/4");
    }

    @Test
    void viewerTopHostsGroupByMaskedAddressAndNewFieldsCarryNoFullIpv4() throws Exception {
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        JsonNode ov = getJson(v, "/api/dashboard/overview?period=24h");
        assertThat(ov.get("maskedView").asBoolean()).isTrue();
        // 가린 주소(A.B.*.*)가 묶는 단위다: 원문 호스트 9개가 4줄이 된다(원문으로 묶은 뒤 가리면 5줄이 나온다)
        assertThat(hostLines(ov.at("/topHosts/originator"))).containsExactly(
                "10.50.*.* 5/1/1/7", "10.51.*.* 0/4/0/5", "10.52.*.* 0/0/3/3", "10.53.*.* 0/0/0/1");
        assertThat(hostLines(ov.at("/topHosts/responder"))).containsExactly("10.60.*.* 0/0/3/4");
        for (String cond : List.of("period=24h", "period=all", "period=30d&source=live", "period=all&source=imported",
                "period=24h&captureId=" + CAP_A, CUSTOM)) {
            JsonNode o = getJson(v, "/api/dashboard/overview?" + cond);
            for (String field : List.of("attack", "topHosts", "topThreads")) {
                assertThat(FULL_IPV4.matcher(o.get(field).toString()).find()).as(cond + " " + field).isFalse();
            }
            assertThat(o.get("topThreads")).as(cond).isNotEmpty();
            assertThat(o.at("/attack/techniques")).as(cond).isNotEmpty();
        }
    }

    /* ───────────── topThreads ───────────── */

    @Test
    void topThreadsPickVisibleThreadsWithMembersInConditionAndOrderThem() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        long t1 = no(a("T1"));
        long oldT = no(a("OLDT"));
        long gone = no(a("GONE"));
        long it2 = no(i("IT2"));
        long it4 = no(i("IT4"));
        long t8 = no(a("T8"));
        long t10 = no(a("T10"));
        long ht2 = no(h("HT2"));

        // 24시간: 기간 내 건수 DESC → 전체 건수 DESC → 가장 늦은 탐지 DESC. 6번째 뒤(T8·T10 묶음)는 잘린다
        JsonNode day = getJson(a, "/api/dashboard/overview?period=24h");
        assertThat(day.get("topThreadsOmitted").asBoolean()).isFalse();
        assertThat(threadLines(day.get("topThreads"))).containsExactly(
                t1 + " 4/4", it4 + " 3/3", gone + " 3/3", oldT + " 2/3", it2 + " 2/2");
        JsonNode first = day.get("topThreads").get(0);
        assertThat(first.get("headHostIp").asText()).isEqualTo("10.80.0.1");
        assertThat(first.get("headPickedBy").asText()).isEqualTo("hbos");
        assertThat(first.get("latestDetectedAt").asText()).startsWith("2026-11-20T11:00");
        // 머리가 기간 밖(11-10 탐지)이어도 머리의 호스트·탐지 모델이 나온다. 자기 Slack 행이 없는 머리(IT4)도 답글로 오른다
        JsonNode outside = day.get("topThreads").get(3);
        assertThat(outside.get("headHostIp").asText()).isEqualTo("10.80.0.20");
        assertThat(outside.get("headPickedBy").asText()).isEqualTo("autoencoder");
        assertThat(outside.get("latestDetectedAt").asText()).startsWith("2026-11-20T10:00");
        assertThat(day.get("topThreads").get(1).get("headHostIp").asText()).isEqualTo("10.80.1.4");

        // 기간 전체: OLDT 묶음이 3/3이 되고, 3/3·10:00 동률은 머리 번호가 큰 쪽(GONE > OLDT)이 앞이다
        assertThat(gone).isGreaterThan(oldT);
        assertThat(threadLines(getJson(a, "/api/dashboard/overview?period=all").get("topThreads"))).containsExactly(
                t1 + " 4/4", it4 + " 3/3", gone + " 3/3", oldT + " 3/3", it2 + " 2/2");

        // 캡처 하나: 다른 캡처 구성원(IT1)은 기간 내 건수에서 빠지고 전체 건수에는 남는다. 2/2 동률은 머리 번호 내림차순.
        // 숨김 머리(HT2 ← T6), 번호 행 없는 머리(G ← T2), 혼자인 알림(T7·채움 행)은 나오지 않는다
        JsonNode capA = getJson(a, "/api/dashboard/overview?period=24h&captureId=" + CAP_A);
        assertThat(threadLines(capA.get("topThreads"))).containsExactly(
                t1 + " 3/4", gone + " 3/3", oldT + " 2/3", Math.max(t8, t10) + " 2/2", Math.min(t8, t10) + " 2/2");
        for (JsonNode row : capA.get("topThreads")) {
            assertThat(row.get("headIncidentNo").asLong()).isNotEqualTo(ht2);
        }
        assertThat(capA.toString()).doesNotContain(HIDDEN).doesNotContain("10.80.2.");

        // 가져온 데이터만: 머리(T1)가 다른 수집원에 있어도 조건 안 구성원(IT1)이 있으면 오르고 머리 호스트가 나온다
        JsonNode imported = getJson(a, "/api/dashboard/overview?period=24h&source=imported");
        assertThat(threadLines(imported.get("topThreads"))).containsExactly(it4 + " 3/3", it2 + " 2/2", t1 + " 1/4");
        assertThat(imported.get("topThreads").get(2).get("headHostIp").asText()).isEqualTo("10.80.0.1");

        // 조회자: 같은 줄, 머리 호스트만 가려진다
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        JsonNode vDay = getJson(v, "/api/dashboard/overview?period=24h");
        assertThat(threadLines(vDay.get("topThreads"))).isEqualTo(threadLines(day.get("topThreads")));
        assertThat(vDay.get("topThreads").get(0).get("headHostIp").asText()).isEqualTo("10.80.*.*");
        assertThat(vDay.get("topThreads").get(0).get("headPickedBy").asText()).isEqualTo("hbos");

        // 허용 캡처가 다르면 묶음도 다르다: 가져온 데이터만 허용하면 머리 T1이 보이지 않고,
        // 숨김 캡처까지 허용하면 T1 묶음이 5건이 되고 HT2 묶음이 보인다
        MockHttpSession onlyI = login(UserRole.ANALYST, "t45bi-*");
        assertThat(threadLines(getJson(onlyI, "/api/dashboard/overview?period=24h").get("topThreads")))
                .containsExactly(it4 + " 3/3", it2 + " 2/2");
        MockHttpSession every = login(UserRole.ANALYST, EVERYTHING);
        JsonNode hidden = getJson(every, "/api/dashboard/overview?period=24h&captureId=" + HIDDEN);
        assertThat(threadLines(hidden.get("topThreads"))).containsExactly(t1 + " 1/5", ht2 + " 1/2");
    }

    @Test
    void headWithoutLatestQueueRowHasNoHostOrModel() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        long gone = no(a("GONE"));
        // 번호가 매겨진 뒤 머리가 최신 큐에서 빠졌다(번호 행은 남는다)
        jdbc().update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = 98121 AND incident_id = ?", a("GONE"));
        JsonNode capA = getJson(a, "/api/dashboard/overview?period=24h&captureId=" + CAP_A);
        JsonNode row = null;
        for (JsonNode t : capA.get("topThreads")) {
            if (t.get("headIncidentNo").asLong() == gone) {
                row = t;
            }
        }
        assertThat(row).isNotNull();
        assertThat(row.get("periodIncidentCount").asLong()).isEqualTo(2);
        assertThat(row.get("totalMemberCount").asLong()).isEqualTo(2);
        assertThat(row.get("headHostIp").isNull()).isTrue();
        assertThat(row.get("headPickedBy").isNull()).isTrue();
        assertThat(getJson(a, "/api/incidents/queue?period=all&thread=" + gone).get("total").asLong()).isEqualTo(2);
    }

    @Test
    void replyPairCapOmitsThreadsAndSaysSo() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        List<SlackThreadLink> tooMany = new ArrayList<>();
        for (int k = 0; k <= SlackThreadService.BADGE_REPLY_ROW_CAP; k++) {
            SlackThreadLink link = new SlackThreadLink();
            link.setIncidentId("x" + k);
            link.setThreadParent(a("T1"));
            tooMany.add(link);
        }
        Mockito.doReturn(tooMany).when(zeekadReadMapper).findThreadRepliesByHeads(any(), anyInt());
        JsonNode ov = getJson(a, "/api/dashboard/overview?period=24h");
        assertThat(ov.get("topThreads")).isEmpty();
        assertThat(ov.get("topThreadsOmitted").asBoolean()).isTrue();
        // 다른 두 집계와 기존 필드는 그대로 나온다
        assertThat(ov.at("/attack/techniques")).isNotEmpty();
        assertThat(ov.at("/topHosts/originator")).hasSize(5);
        Mockito.verify(zeekadReadMapper, Mockito.never()).findLatestQueueHeadRows(any(), any());
    }

    /* ───────────── 현황판 수 = 같은 조건 큐 건수 ───────────── */

    @Test
    void everyCountEqualsTheQueueTotalOfTheSameCondition() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        MockHttpSession every = login(UserRole.ANALYST, EVERYTHING);
        List<String> conditions = List.of("period=24h", "period=all", "period=30d&source=live",
                "period=all&source=imported", "period=24h&captureId=" + CAP_A, CUSTOM);
        int checked = 0;
        for (String cond : conditions) {
            checked += assertCountsMatchQueue(a, cond);
        }
        for (String cond : List.of("period=24h", "period=all&source=imported", CUSTOM)) {
            checked += assertCountsMatchQueue(v, cond);
        }
        checked += assertCountsMatchQueue(every, "period=all");
        assertThat(checked).isGreaterThan(200);
    }

    /** overview의 세 집계를 같은 사용자·같은 조건의 큐와 견준다. 견준 값의 수를 돌려준다 */
    private int assertCountsMatchQueue(MockHttpSession s, String cond) throws Exception {
        JsonNode ov = getJson(s, "/api/dashboard/overview?" + cond);
        String queue = "/api/incidents/queue?size=25&" + cond;
        int n = 0;
        // 기존 불변식: 캡처 행 합 = 같은 조건 큐 summary.total
        long captureSum = 0;
        for (JsonNode c : ov.get("captures")) {
            captureSum += c.get("total").asLong();
        }
        assertThat(captureSum).as(cond).isEqualTo(getJson(s, queue).at("/summary/total").asLong());
        for (JsonNode t : ov.at("/attack/tactics")) {
            assertThat(getJson(s, queue + "&attack=" + t.get("tactic").asText()).get("total").asLong())
                    .as(cond + " tactic " + t.get("tactic").asText()).isEqualTo(t.get("count").asLong());
            n++;
        }
        for (JsonNode t : ov.at("/attack/techniques")) {
            assertThat(getJson(s, queue + "&attack=" + t.get("attackId").asText()).get("total").asLong())
                    .as(cond + " technique " + t.get("attackId").asText()).isEqualTo(t.get("count").asLong());
            n++;
        }
        for (String dir : List.of("originator", "responder")) {
            for (JsonNode h : ov.at("/topHosts/" + dir)) {
                String host = h.get("hostIp").asText();
                JsonNode q = getJson(s, queue + "&role=" + dir + "&hostIp=" + host);
                String what = cond + " " + dir + " " + host;
                assertThat(q.get("total").asLong()).as(what).isEqualTo(h.get("total").asLong());
                assertThat(q.at("/summary/high").asLong()).as(what).isEqualTo(h.get("high").asLong());
                assertThat(q.at("/summary/medium").asLong()).as(what).isEqualTo(h.get("medium").asLong());
                assertThat(q.at("/summary/low").asLong()).as(what).isEqualTo(h.get("low").asLong());
                assertThat(h.get("total").asLong()).isPositive();
                n++;
            }
        }
        for (JsonNode t : ov.get("topThreads")) {
            long headNo = t.get("headIncidentNo").asLong();
            // 전체 건수 = 큐 period=all&thread=의 total, 기간 내 건수 = 같은 조건 + thread의 total
            JsonNode members = getJson(s, "/api/incidents/queue?period=all&size=100&thread=" + headNo);
            assertThat(members.get("total").asLong()).as(cond + " thread " + headNo)
                    .isEqualTo(t.get("totalMemberCount").asLong());
            assertThat(getJson(s, queue + "&thread=" + headNo).get("total").asLong()).as(cond + " thread " + headNo)
                    .isEqualTo(t.get("periodIncidentCount").asLong());
            assertThat(t.get("totalMemberCount").asLong()).isGreaterThanOrEqualTo(2);
            assertThat(t.get("periodIncidentCount").asLong()).isPositive();
            // 머리 상세 Slack 탭의 memberCount(머리 자신의 Slack 행이 있는 묶음)와 머리 호스트
            for (JsonNode row : members.get("items")) {
                if (row.get("incidentNo").asLong() != headNo) {
                    continue;
                }
                assertThat(t.get("headHostIp").asText()).isEqualTo(row.get("hostIp").asText());
                JsonNode detail = getJson(s, "/api/incidents/" + row.get("jobId").asLong() + "/rank/"
                        + row.get("queueRank").asInt());
                for (JsonNode group : detail.at("/detail/slackThreadGroups")) {
                    if (group.get("headIsSelf").asBoolean()) {
                        assertThat(group.get("memberCount").asLong()).as(cond + " detail " + headNo)
                                .isEqualTo(t.get("totalMemberCount").asLong());
                        n++;
                    }
                }
            }
            n++;
        }
        return n;
    }

    /* ───────────── 읽기 횟수 ───────────── */

    @Test
    void readsOnceEachRegardlessOfRowCountAndNeverWritesNumbers() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        getJson(a, "/api/dashboard/overview?period=all");

        // 작은 조건(가져온 데이터 10행)
        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
        JsonNode small = getJson(a, "/api/dashboard/overview?period=24h&source=imported");
        int smallReads = Mockito.mockingDetails(zeekadReadMapper).getInvocations().size();
        int smallRefReads = Mockito.mockingDetails(refMapper).getInvocations().size();
        assertThat(small.get("topThreads")).isNotEmpty();
        verifyThreatReadsOnce();

        // 큰 조건(두 캡처 80행 남짓): 읽기 DB·번호 DB 호출 수가 같다
        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
        JsonNode large = getJson(a, "/api/dashboard/overview?period=all");
        long rows = 0;
        for (JsonNode c : large.get("captures")) {
            rows += c.get("total").asLong();
        }
        assertThat(rows).isGreaterThan(70);
        assertThat(Mockito.mockingDetails(zeekadReadMapper).getInvocations()).hasSize(smallReads);
        assertThat(Mockito.mockingDetails(refMapper).getInvocations()).hasSize(smallRefReads);
        verifyThreatReadsOnce();
        // 번호 행이 없는 머리(G)에 번호를 매기지 않았다
        assertThat(app().queryForObject("SELECT COUNT(*) FROM incident_refs WHERE incident_id = ?", Integer.class, a("G")))
                .isZero();
    }

    private void verifyThreatReadsOnce() {
        // 같은 조건의 큐 행은 한 번만 훑는다(점 질의 하나, 큐 목록·요약 질의 없음)
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findUnifiedQueuePoints(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countUnifiedQueue(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).summarizeUnifiedQueue(any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findLatestAttackCandidates(any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findThreadRepliesByHeads(any(), anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).countLatestQueueRowsByIncidentIds(any(), any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findLatestQueueHeadRows(any(), any());
        // 머리·행마다 부르는 질의는 쓰지 않는다
        Mockito.verify(zeekadReadMapper, Mockito.never()).findThreadReplyIncidentIds(any(), anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countLatestQueueByIncidentIds(any(), any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findDistinctLatestHostIps(any());
        // 번호는 읽기만 한 번. 동기화·쓰기 없음
        Mockito.verify(refService, Mockito.times(1)).readRefsOnly(any());
        Mockito.verify(refService, Mockito.never()).numbersFor(any());
        Mockito.verify(refService, Mockito.never()).numberFor(any());
        Mockito.verify(refService, Mockito.never()).syncAll();
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());
    }

    @Test
    void emptyConditionReadsNothingAndReturnsEmptyAggregates() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        // 수집원과 고른 캡처가 어긋나 캡처가 없다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        JsonNode none = getJson(a, "/api/dashboard/overview?period=all&source=live&captureId=" + CAP_I);
        assertEmptyAggregates(none);
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueuePoints(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findLatestAttackCandidates(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(refService, Mockito.never()).readRefsOnly(any());

        // 캡처는 있지만 기간 안 행이 없다(1시간): 점 질의만 부른다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        JsonNode hour = getJson(a, "/api/dashboard/overview?period=1h");
        assertEmptyAggregates(hour);
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findUnifiedQueuePoints(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findLatestAttackCandidates(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(refService, Mockito.never()).readRefsOnly(any());

        // 형식 오류 400, 허용 밖 캡처 403은 지금 그대로다
        mockMvc.perform(get(URI.create("/api/dashboard/overview?period=2h")).session(a)).andExpect(status().isBadRequest());
        mockMvc.perform(get(URI.create("/api/dashboard/overview?captureId=" + HIDDEN)).session(a))
                .andExpect(status().isForbidden());
    }

    private static void assertEmptyAggregates(JsonNode ov) {
        assertThat(ov.at("/attack/incidentsWithCandidates").asLong()).isZero();
        assertThat(ov.at("/attack/techniqueCount").asInt()).isZero();
        assertThat(ov.at("/attack/tactics").isArray()).isTrue();
        assertThat(ov.at("/attack/tactics")).isEmpty();
        assertThat(ov.at("/attack/techniques")).isEmpty();
        assertThat(ov.at("/topHosts/originator").isArray()).isTrue();
        assertThat(ov.at("/topHosts/originator")).isEmpty();
        assertThat(ov.at("/topHosts/responder")).isEmpty();
        assertThat(ov.get("topThreads").isArray()).isTrue();
        assertThat(ov.get("topThreads")).isEmpty();
        assertThat(ov.get("topThreadsOmitted").asBoolean()).isFalse();
    }

    /* ───────────── 도우미 ───────────── */

    /** "값=count" 목록(응답 순서) */
    private static List<String> pairs(JsonNode rows, String field) {
        List<String> out = new ArrayList<>();
        for (JsonNode row : rows) {
            out.add(row.get(field).asText() + "=" + row.get("count").asLong());
        }
        return out;
    }

    private static Map<String, JsonNode> byField(JsonNode rows, String field) {
        Map<String, JsonNode> out = new HashMap<>();
        for (JsonNode row : rows) {
            out.put(row.get(field).asText(), row);
        }
        return out;
    }

    /** "주소 high/medium/low/total" 목록(응답 순서) */
    private static List<String> hostLines(JsonNode rows) {
        List<String> out = new ArrayList<>();
        for (JsonNode row : rows) {
            out.add(row.get("hostIp").asText() + " " + row.get("high").asLong() + "/" + row.get("medium").asLong() + "/"
                    + row.get("low").asLong() + "/" + row.get("total").asLong());
        }
        return out;
    }

    /** "머리 번호 기간 내/전체" 목록(응답 순서) */
    private static List<String> threadLines(JsonNode rows) {
        List<String> out = new ArrayList<>();
        for (JsonNode row : rows) {
            out.add(row.get("headIncidentNo").asLong() + " " + row.get("periodIncidentCount").asLong() + "/"
                    + row.get("totalMemberCount").asLong());
        }
        return out;
    }

    private static String cand(String attackId, String name, String tacticsJson) {
        return "{\"attack_id\":\"" + attackId + "\",\"name\":\"" + name + "\",\"tactics\":" + tacticsJson + "}";
    }

    private String a(String key) { return id(CAP_A, key); }
    private String i(String key) { return id(CAP_I, key); }
    private String h(String key) { return id(HIDDEN, key); }

    private String id(String capture, String key) {
        return capture + "|" + key + "|" + tag;
    }

    private long no(String incidentId) {
        Long n = app().queryForObject("SELECT incident_no FROM incident_refs WHERE incident_id = ?", Long.class, incidentId);
        assertThat(n).as(incidentId).isNotNull();
        return n;
    }

    private void deleteRows() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 98120 AND 98129";
        z.update("DELETE FROM dashboard.raw_slack_deliveries WHERE " + range);
        z.update("DELETE FROM dashboard.raw_send_decisions WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_reports WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    private void job(long jobId, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-09T00:00:00Z', "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                jobId, capture, finished);
    }

    private void inc(long jobId, String capture, int rank, String key, String ip, String role, String kind) {
        inc(jobId, capture, rank, key, ip, role, kind, "hbos");
    }

    /** kind: low / medium(교차 탐지) / high(템플릿 리포트 + 발송) / closed */
    private void inc(long jobId, String capture, int rank, String key, String ip, String role, String kind, String pickedBy) {
        String incidentId = id(capture, key);
        String also = "medium".equals(kind) ? "ARRAY['autoencoder']" : "NULL";
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-09T20:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-09T20:05:00Z', ?, " + also + ", ?, NULL)",
                jobId, capture, rank, incidentId, ip, role, pickedBy, 1000 - rank);
        if ("high".equals(kind)) {
            report(jobId, incidentId, null);
            jdbc().update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                    + "VALUES (?, ?, TRUE, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-20T10:30:00Z')", jobId, incidentId);
        }
        if ("closed".equals(kind)) {
            jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                    + "VALUES (?, ?, 'closed', 'benign', TIMESTAMP WITH TIME ZONE '2026-11-20T12:00:00Z', 't45b')", jobId, incidentId);
        }
    }

    private void slack(long jobId, String incidentId, String parent, int minute) throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("text", "t45b 알림");
        if (parent != null) {
            payload.put("zeekad_thread_parent", parent.trim());
        }
        jdbc().update("INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version, "
                        + "zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at, "
                        + "zeekad_thread_parent, zeekad_reply_broadcast) VALUES (?, ?, 'incident', 'incident.v2', 'dry_run', 'recorded', "
                        + "? FORMAT JSON, NULL, NULL, NULL, CAST(? AS TIMESTAMP WITH TIME ZONE), ?, FALSE)",
                jobId, incidentId, objectMapper.writeValueAsString(payload), String.format("2026-11-20T12:%02d:00Z", minute), parent);
    }

    /** candidates가 null이면 열 값 없음(SQL NULL) */
    private void report(long jobId, String incidentId, String candidates) {
        if (candidates == null) {
            jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                            + "zeekad_report, zeekad_attack_candidates, created_at) VALUES (?, ?, 'template', 'template.v1', "
                            + "'{}' FORMAT JSON, NULL, TIMESTAMP WITH TIME ZONE '2026-11-20T10:30:00Z')",
                    jobId, incidentId);
            return;
        }
        jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                        + "zeekad_report, zeekad_attack_candidates, created_at) VALUES (?, ?, 'llm', 'report.v1', "
                        + "'{}' FORMAT JSON, ? FORMAT JSON, TIMESTAMP WITH TIME ZONE '2026-11-20T10:30:00Z')",
                jobId, incidentId, candidates);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t45b_u" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private String getBody(MockHttpSession session, String url) throws Exception {
        // URI 그대로 보낸다(문자열 템플릿은 %를 한 번 더 인코딩한다)
        MvcResult r = mockMvc.perform(get(URI.create(url)).session(session)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        return objectMapper.readTree(getBody(session, url));
    }
}
