package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.IncidentRefMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.service.IncidentQueueService;
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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T45 통합 큐 hostIp 정확 일치·attack 조건(세 API)과 큐 행 알림 묶음 표지(threadHeadNo·threadMemberCount).
 *
 * 시험 자료(기준 시각 = 2026-11-21 00:00Z, now 모드. job 98110~98119):
 *  - lab-t45a(실습망, 허용) 옛 작업 98110(11-10 00:00): OLD(10.45.9.9), G(10.45.8.8, 옛 작업에만 = 최신 큐에 없음·번호 행 없음)
 *  - lab-t45a 최신 작업 98111(11-20 10:00): A1(10.45.1.1) A2(10.45.1.2) A3(10.45.1.12) A4(10.45.2.4) OLD(탐지 11-10, 24시간 밖)
 *    A6(10.46.1.1) A7(10.45.1.1 응답자) + 채움 행 F1~F40(10.47.x.y, 저마다 혼자인 Slack 알림)
 *  - t45i-cap(가져온 데이터, 허용) 98112(11-20 11:00): I1(10.45.1.1) I2(10.45.3.3) I3(10.45.3.4) I4(10.45.3.5) I5(10.45.3.6)
 *  - lab-t45h(숨김) 98113(11-20 10:00): H1(10.45.1.1) H2(10.45.5.5) H3(10.45.5.6)
 *
 * 알림 묶음(머리 ← 답글): A1 ← A2·A3(부모 앞뒤 공백)·A7·H1 / H2(숨김 머리) ← A4 / G(번호 행 없음) ← A2 /
 *  A6 ← OLD(기준 시각 2026-11-19 06:20Z 전 알림만) / OLD ← I2 / I1 ← A7·I2 / I3(자기 Slack 행 없음) ← I4·I5
 *
 * 리포트 ATT&amp;CK 후보: A1 T1059(Execution)·T1558.003(Credential Access) / A2 옛 리포트 T1059.001, 최신 리포트 T1021 /
 *  A3 " t1059.001 "(execution) / A4 T1110(credential_access, Command and Control) / OLD T1059 / A6 값 없음 / A7 빈 배열 /
 *  I1 T1059(Credential Access) / I2 JSON null / H1 T1059(Credential Access)
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t45_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t45_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t45_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T45QueueFiltersAndThreadBadgeIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    static final String CAP_A = "lab-t45a";
    static final String CAP_I = "t45i-cap";
    static final String HIDDEN = "lab-t45h";
    /** 허용 캡처 둘(실습망 + 가져온 데이터) */
    static final String ALLOWED = "lab-t45a,t45i-*";
    static final String EVERYTHING = "lab-t45*,t45i-*";
    static final Pattern IPV4 = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    static final int FILLERS = 40;
    static final String SINCE = "2026-01-01T00:00:00Z";

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
        tag = "t45s" + (++seq);
        job(98110, CAP_A, "2026-11-10T00:00:00Z");
        incident(98110, CAP_A, 1, "10.45.9.9", "originator");
        incident(98110, CAP_A, 2, "10.45.8.8", "originator");
        job(98111, CAP_A, "2026-11-20T10:00:00Z");
        incident(98111, CAP_A, 1, "10.45.1.1", "originator");
        incident(98111, CAP_A, 2, "10.45.1.2", "originator");
        incident(98111, CAP_A, 3, "10.45.1.12", "originator");
        incident(98111, CAP_A, 4, "10.45.2.4", "originator");
        incident(98111, CAP_A, 5, "10.45.9.9", "originator");
        incident(98111, CAP_A, 6, "10.46.1.1", "originator");
        incident(98111, CAP_A, 7, "10.45.1.1", "responder");
        for (int i = 1; i <= FILLERS; i++) {
            incident(98111, CAP_A, 10 + i, "10.47." + (i / 200) + "." + i, "originator");
        }
        job(98112, CAP_I, "2026-11-20T11:00:00Z");
        String[] iIps = {"10.45.1.1", "10.45.3.3", "10.45.3.4", "10.45.3.5", "10.45.3.6"};
        for (int i = 0; i < iIps.length; i++) {
            incident(98112, CAP_I, i + 1, iIps[i], "originator");
        }
        job(98113, HIDDEN, "2026-11-20T10:00:00Z");
        incident(98113, HIDDEN, 1, "10.45.1.1", "originator");
        incident(98113, HIDDEN, 2, "10.45.5.5", "originator");
        incident(98113, HIDDEN, 3, "10.45.5.6", "originator");

        // 알림 묶음
        slack(98111, a1(), null, 0);
        slack(98111, a(2), a1(), 1);
        slack(98111, a(12), "  " + a1() + " ", 2);
        slack(98111, a7(), a1(), 3);
        slack(98113, h(1, 1), a1(), 4);
        slack(98113, h(5, 5), null, 5);
        slack(98111, id(CAP_A, "10.45.2.4"), h(5, 5), 6);
        slack(98111, a(2), g(), 7);
        // 기준 시각(2026-11-19 06:20Z) 전에 기록된 알림만으로 된 묶음
        slackAt(98111, a6(), null, "2026-11-18T01:00:00Z");
        slackAt(98111, old(), a6(), "2026-11-18T01:05:00Z");
        slack(98111, old(), null, 8);
        slack(98112, i(3, 3), old(), 9);
        slack(98112, i(1, 1), null, 10);
        slack(98111, a7(), i(1, 1), 11);
        slack(98112, i(3, 3), i(1, 1), 12);
        slack(98112, i(3, 5), i(3, 4), 13);
        slack(98112, i(3, 6), i(3, 4), 14);
        for (int k = 1; k <= FILLERS; k++) {
            slack(98111, id(CAP_A, "10.47." + (k / 200) + "." + k), null, 15 + k);
        }

        // 리포트의 ATT&CK 후보
        report(98111, a1(), "[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Execution\"]},"
                + "{\"attack_id\":\"T1558.003\",\"name\":\"n\",\"tactics\":[\"Credential Access\"]}]");
        report(98110, a(2), "[{\"attack_id\":\"T1059.001\",\"name\":\"n\",\"tactics\":[\"Execution\"]}]");
        report(98111, a(2), "[{\"attack_id\":\"T1021\",\"name\":\"n\",\"tactics\":[\"Lateral Movement\"]}]");
        report(98111, a(12), "[{\"attack_id\":\" t1059.001 \",\"name\":\"n\",\"tactics\":[\"execution\"]}]");
        report(98111, id(CAP_A, "10.45.2.4"),
                "[{\"attack_id\":\"T1110\",\"name\":\"n\",\"tactics\":[\"credential_access\",\"Command and Control\"]}]");
        report(98111, old(), "[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Execution\"]}]");
        report(98111, a6(), null);
        report(98111, a7(), "[]");
        report(98112, i(1, 1), "[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Credential Access\"]}]");
        report(98112, i(3, 3), "null");
        report(98113, h(1, 1), "[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Credential Access\"]}]");

        refService.syncAll();
        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
    }

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        deleteRows();
        Mockito.reset(refService, refMapper, zeekadReadMapper);
    }

    /* ───────────── hostIp ───────────── */

    @Test
    void hostIpMatchesExactlyForAnalystAndByMaskedRangeForBoth() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        String base = "/api/incidents/queue?period=all&size=100";

        // 원문 정확 일치: 같은 접두의 다른 호스트(10.45.1.12, 10.45.1.2)는 섞이지 않고 숨김 캡처의 같은 주소도 없다
        String body = getBody(a, base + "&hostIp=10.45.1.1");
        JsonNode exact = objectMapper.readTree(body);
        assertThat(exact.get("total").asLong()).isEqualTo(3);
        assertThat(hosts(exact)).containsOnly("10.45.1.1");
        assertThat(ranks(exact)).containsExactlyInAnyOrder(CAP_A + "#1", CAP_A + "#7", CAP_I + "#1");
        assertThat(body).doesNotContain(HIDDEN);
        assertThat(exact.at("/summary/total").asLong()).isEqualTo(3);
        // 앞뒤 공백은 다듬고, 빈 값·공백은 조건 없음
        assertThat(getJson(a, base + "&hostIp=%2010.45.1.1%20").get("total").asLong()).isEqualTo(3);
        long all = getJson(a, base).get("total").asLong();
        assertThat(all).isEqualTo(12 + FILLERS);
        assertThat(getJson(a, base + "&hostIp=").get("total").asLong()).isEqualTo(all);
        assertThat(getJson(a, base + "&hostIp=%20%20").get("total").asLong()).isEqualTo(all);
        // 수집원과 함께
        assertThat(getJson(a, base + "&source=live&hostIp=10.45.1.1").get("total").asLong()).isEqualTo(2);
        assertThat(getJson(a, base + "&captureId=" + CAP_I + "&hostIp=10.45.1.1").get("total").asLong()).isEqualTo(1);

        // 대역(A.B.*.*): 분석가와 조회자가 같은 행 집합(10.46·10.47 대역은 빠진다)
        JsonNode aRange = getJson(a, base + "&hostIp=10.45.*.*");
        String vBody = getBody(v, base + "&hostIp=10.45.*.*");
        JsonNode vRange = objectMapper.readTree(vBody);
        assertThat(aRange.get("total").asLong()).isEqualTo(11);
        assertThat(vRange.get("total").asLong()).isEqualTo(11);
        assertThat(ranks(vRange)).isEqualTo(ranks(aRange));
        assertThat(hosts(vRange)).containsOnly("10.45.*.*");
        assertThat(IPV4.matcher(vBody).find()).as("viewer unmasked ip").isFalse();
        assertThat(vRange.at("/summary/total").asLong()).isEqualTo(11);

        // 새 건수·이전·다음도 같은 조건
        for (String cond : List.of("hostIp=10.45.1.1", "hostIp=10.45.*.*")) {
            long total = getJson(a, base + "&" + cond).get("total").asLong();
            assertThat(getJson(a, "/api/incidents/queue/new-count?since=" + SINCE + "&" + cond).get("count").asLong())
                    .as(cond).isEqualTo(total);
            JsonNode nb = getJson(a, "/api/incidents/queue/neighbors?jobId=98111&queueRank=1&period=all&" + cond);
            assertThat(nb.get("total").asLong()).as(cond).isEqualTo(total);
            assertThat(nb.get("position").isNull()).isFalse();
        }
        // 조건 밖 인시던트의 이전·다음: 위치 없음, 전체 수는 조건의 수
        JsonNode out = getJson(a, "/api/incidents/queue/neighbors?jobId=98111&queueRank=6&period=all&hostIp=10.45.1.1");
        assertThat(out.get("position").isNull()).isTrue();
        assertThat(out.get("total").asLong()).isEqualTo(3);

        // 자산 검색(부분 일치)과 함께: 둘 다 걸린다
        assertThat(getJson(a, base + "&asset=10.45.1").get("total").asLong()).isEqualTo(5);
        assertThat(getJson(a, base + "&asset=10.45.1&hostIp=10.45.1.1").get("total").asLong()).isEqualTo(3);
        assertThat(getJson(a, base + "&asset=10.45.3&hostIp=10.45.1.1").get("total").asLong()).isZero();
        assertThat(getJson(v, base + "&asset=10.45&hostIp=10.45.*.*").get("total").asLong()).isEqualTo(11);
    }

    @Test
    void viewerRawHostIpGivesTheSameEmptyResponseWhetherTheHostExistsOrNot() throws Exception {
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        String q = "/api/incidents/queue?period=all&hostIp=";
        // 있는 호스트(10.45.1.1), 없는 호스트(10.45.77.77): 조회자에게는 둘 다 200·0건이고 응답이 같다
        String exists = getBody(v, q + "10.45.1.1");
        String missing = getBody(v, q + "10.45.77.77");
        assertThat(objectMapper.readTree(exists).get("total").asLong()).isZero();
        assertThat(objectMapper.readTree(exists).get("items")).isEmpty();
        assertThat(exists).isEqualTo(missing);
        assertThat(getBody(v, "/api/incidents/queue/new-count?since=" + SINCE + "&hostIp=10.45.1.1"))
                .isEqualTo(getBody(v, "/api/incidents/queue/new-count?since=" + SINCE + "&hostIp=10.45.77.77"));
        String nb = "/api/incidents/queue/neighbors?jobId=98111&queueRank=1&period=all&hostIp=";
        assertThat(getBody(v, nb + "10.45.1.1")).isEqualTo(getBody(v, nb + "10.45.77.77"));
        assertThat(getJson(v, nb + "10.45.1.1").get("position").isNull()).isTrue();
        // 선택지(수집원)는 허용 캡처 기준으로 남는다
        assertThat(objectMapper.readTree(exists).get("sources")).hasSize(2);

        // 분석가: 숨김 캡처에만 있는 호스트(10.45.5.5)와 없는 호스트도 응답이 같다
        assertThat(getBody(a, q + "10.45.5.5")).isEqualTo(getBody(a, q + "10.45.77.77"));
        assertThat(getJson(a, q + "10.45.5.5").get("total").asLong()).isZero();
    }

    @Test
    void hostIpUsesSqlPathAndKeepsOutsidePeriodNotice() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        Mockito.clearInvocations(zeekadReadMapper);
        JsonNode q = getJson(a, "/api/incidents/queue?period=all&size=25&hostIp=10.45.1.1");
        assertThat(q.get("total").asLong()).isEqualTo(3);
        // SQL 경로: 쪽 크기만큼만 읽고 자산 검색의 상한(5,000건 + 1) 목록 질의는 부르지 않는다
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findUnifiedQueue(ArgumentMatchers.argThat(
                (UnifiedQueueCriteria c) -> c.getLimit() != null && c.getLimit() == 25
                        && c.getHostIps() != null && c.getHostIps().length == 1));
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(ArgumentMatchers.argThat(
                (UnifiedQueueCriteria c) -> c.getLimit() != null && c.getLimit() > IncidentQueueService.ASSET_SEARCH_CAP));
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).countUnifiedQueue(any());
        // 원문 집합은 한 번만 읽는다
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findDistinctLatestHostIps(any());

        // 기간 밖에만 있는 호스트: 0건이면서 기간 밖 안내가 남는다
        JsonNode day = getJson(a, "/api/incidents/queue?period=24h&hostIp=10.45.9.9");
        assertThat(day.get("total").asLong()).isZero();
        assertThat(day.get("outsidePeriod").asLong()).isEqualTo(1);
        assertThat(day.get("newestOutsidePeriod").asText()).startsWith("2026-11-10T00:00");
        // 조회자도 대역으로 같은 안내를 받는다(24시간 안 10건, 밖 1건)
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        JsonNode vDay = getJson(v, "/api/incidents/queue?period=24h&hostIp=10.45.*.*");
        assertThat(vDay.get("total").asLong()).isEqualTo(10);
        assertThat(vDay.get("outsidePeriod").asLong()).isEqualTo(1);

        // 고른 호스트가 없으면 큐 질의를 부르지 않는다
        Mockito.clearInvocations(zeekadReadMapper);
        assertThat(getJson(a, "/api/incidents/queue?period=all&hostIp=10.99.9.9").get("total").asLong()).isZero();
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countUnifiedQueue(any());
    }

    @Test
    void malformedHostIpAndAttackAre400WithoutAuditOnAllThreeApis() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        long audits = auditCount();
        List<String> badHosts = List.of("10.45.1", "10.45.1.1:80", "10.*.*.*", "10.45.1.*", "10.45.*.1", "10..1.1",
                "01.2.3.4", "256.1.1.1", "::1", "abc", "10.45.1.1/24", "10.45.1.1,10.45.1.2");
        List<String> badAttacks = List.of("T1059.1", "T1059.0001", "a", "-x", "x-", "credential/access",
                "x".repeat(65), "T1059;T1021", "%EC%A0%84%EC%88%A0", "credential%20access%21");
        List<String> apis = List.of(
                "/api/incidents/queue?period=all&",
                "/api/incidents/queue/new-count?since=" + SINCE + "&",
                "/api/incidents/queue/neighbors?jobId=98111&queueRank=1&period=all&");
        for (MockHttpSession s : List.of(a, v)) {
            for (String api : apis) {
                for (String bad : badHosts) {
                    String body = mockMvc.perform(get(URI.create(api + "hostIp=" + bad)).session(s))
                            .andExpect(status().isBadRequest())
                            .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                            .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
                    // 오류 문장에 입력 값을 넣지 않는다(짧은 값은 다른 글자와 우연히 겹쳐 보지 않는다)
                    if (bad.length() >= 7) {
                        assertThat(body).as(bad).doesNotContain(bad);
                    }
                }
                for (String bad : badAttacks) {
                    String body = mockMvc.perform(get(URI.create(api + "attack=" + bad)).session(s))
                            .andExpect(status().isBadRequest())
                            .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                            .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
                    if (bad.length() >= 7) {
                        assertThat(body).as(bad).doesNotContain(bad);
                    }
                }
            }
        }
        assertThat(auditCount()).isEqualTo(audits);
        // 기법 ID 꼴이 아니어도 전술 슬러그 꼴이면(T10591 → t10591) 형식 오류가 아니라 0건이다
        assertThat(getJson(a, "/api/incidents/queue?period=all&attack=T10591").get("total").asLong()).isZero();
        // 형식 오류는 캡처 권한 검사 뒤다: 허용 밖 captureId면 403이 먼저다
        mockMvc.perform(get(URI.create("/api/incidents/queue?period=all&captureId=" + HIDDEN + "&hostIp=abc")).session(a))
                .andExpect(status().isForbidden());
    }

    /* ───────────── attack ───────────── */

    @Test
    void attackNormalizesTechniqueAndTacticAndReadsOnlyTheLatestReport() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        String base = "/api/incidents/queue?period=all&size=100&attack=";

        // 기법 ID: 대소문자 무시, 서브기법까지 정확 일치. 숨김 캡처(H1)는 나오지 않는다
        Set<String> t1059 = Set.of(CAP_A + "#1", CAP_A + "#5", CAP_I + "#1");
        for (String same : List.of("t1059", "T1059", "%20t1059%20")) {
            JsonNode q = getJson(a, base + same);
            assertThat(q.get("total").asLong()).as(same).isEqualTo(3);
            assertThat(ranks(q)).as(same).isEqualTo(new TreeSet<>(t1059));
            assertThat(q.at("/summary/total").asLong()).isEqualTo(3);
        }
        // T1059.001: A3만(공백·소문자 원문). A2의 옛 리포트(T1059.001)는 zeekad_report_job_id의 것이 아니라 보지 않는다
        assertThat(ranks(getJson(a, base + "t1059.001"))).containsExactly(CAP_A + "#3");
        assertThat(ranks(getJson(a, base + "T1021"))).containsExactly(CAP_A + "#2");
        assertThat(ranks(getJson(a, base + "T1558.003"))).containsExactly(CAP_A + "#1");
        // 상위 기법으로 하위를 묶지 않는다
        assertThat(ranks(getJson(a, base + "T1558"))).isEmpty();

        // 전술: 제목·밑줄·하이픈 표기가 같은 결과
        Set<String> credential = new TreeSet<>(Set.of(CAP_A + "#1", CAP_A + "#4", CAP_I + "#1"));
        for (String same : List.of("Credential%20Access", "credential_access", "credential-access", "CREDENTIAL%20%20ACCESS")) {
            JsonNode q = getJson(a, base + same);
            assertThat(q.get("total").asLong()).as(same).isEqualTo(3);
            assertThat(ranks(q)).as(same).isEqualTo(credential);
        }
        assertThat(ranks(getJson(a, base + "execution")))
                .containsExactlyInAnyOrder(CAP_A + "#1", CAP_A + "#3", CAP_A + "#5");
        assertThat(ranks(getJson(a, base + "command-and-control"))).containsExactly(CAP_A + "#4");

        // 맞는 인시던트가 없으면 SQL 오류 없이 0건(큐 질의도 부르지 않는다)
        Mockito.clearInvocations(zeekadReadMapper);
        for (String none : List.of("T9999", "impact")) {
            JsonNode q = getJson(a, base + none);
            assertThat(q.get("total").asLong()).as(none).isZero();
            assertThat(q.get("sources")).hasSize(2);
        }
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(any());
        // 빈 값·공백은 조건 없음
        assertThat(getJson(a, base).get("total").asLong()).isEqualTo(12 + FILLERS);
        assertThat(getJson(a, base + "%20").get("total").asLong()).isEqualTo(12 + FILLERS);

        // 조회자도 같은 규칙(가릴 값이 없다)
        String vBody = getBody(v, base + "t1059");
        assertThat(ranks(objectMapper.readTree(vBody))).isEqualTo(new TreeSet<>(t1059));
        assertThat(IPV4.matcher(vBody).find()).isFalse();
        // 숨김 캡처까지 보는 사용자에게만 H1이 더해진다
        MockHttpSession all = login(UserRole.ANALYST, EVERYTHING);
        assertThat(getJson(all, base + "t1059").get("total").asLong()).isEqualTo(4);
    }

    @Test
    void attackCombinesWithOtherConditionsOnAllThreeApis() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        String base = "/api/incidents/queue?period=all&size=100&attack=t1059";
        long a1No = no(a1());

        // hostIp와 함께(교집합)
        assertThat(ranks(getJson(a, base + "&hostIp=10.45.1.1"))).containsExactlyInAnyOrder(CAP_A + "#1", CAP_I + "#1");
        // thread와 함께: A1 묶음(A1·A2·A3·A7) 가운데 T1059는 A1뿐
        assertThat(ranks(getJson(a, base + "&thread=" + a1No))).containsExactly(CAP_A + "#1");
        // thread + hostIp + attack=execution: A1 묶음 ∩ 10.45.1.x ∩ 실행 전술 = A1, A3
        assertThat(ranks(getJson(a, "/api/incidents/queue?period=all&attack=execution&hostIp=10.45.*.*&thread=" + a1No)))
                .containsExactlyInAnyOrder(CAP_A + "#1", CAP_A + "#3");
        // 수집원·기간과 함께
        assertThat(ranks(getJson(a, base + "&source=live"))).containsExactlyInAnyOrder(CAP_A + "#1", CAP_A + "#5");
        JsonNode day = getJson(a, "/api/incidents/queue?period=24h&attack=t1059");
        assertThat(day.get("total").asLong()).isEqualTo(2);
        assertThat(day.get("outsidePeriod").asLong()).isEqualTo(1);
        // 띠 축(경보 발송)과 함께: 띠 합계는 조건 전체, 목록은 띠 축까지
        JsonNode alerted = getJson(a, base + "&alerted=true");
        assertThat(alerted.at("/summary/total").asLong()).isEqualTo(3);
        assertThat(alerted.at("/summary/alerted").asLong()).isEqualTo(alerted.get("total").asLong());
        assertThat(alerted.get("total").asLong()).isEqualTo(3);
        JsonNode high = getJson(a, base + "&priority=high");
        assertThat(high.at("/summary/total").asLong()).isEqualTo(3);
        assertThat(high.get("total").asLong()).isEqualTo(high.at("/summary/high").asLong());
        // 자산 검색(Java 경로)에도 걸린다
        assertThat(ranks(getJson(a, base + "&asset=10.45.9"))).containsExactly(CAP_A + "#5");
        // 담당 조건과 함께: 아무도 맡지 않았다
        assertThat(getJson(a, base + "&assignee=none").get("total").asLong()).isEqualTo(3);
        assertThat(getJson(a, base + "&assignee=me").get("total").asLong()).isZero();

        // 새 건수·이전·다음
        assertThat(getJson(a, "/api/incidents/queue/new-count?since=" + SINCE + "&attack=T1059").get("count").asLong())
                .isEqualTo(3);
        assertThat(getJson(a, "/api/incidents/queue/new-count?since=" + SINCE + "&attack=credential_access&hostIp=10.45.2.4")
                .get("count").asLong()).isEqualTo(1);
        JsonNode nb = getJson(a, "/api/incidents/queue/neighbors?jobId=98111&queueRank=1&period=all&attack=t1059");
        assertThat(nb.get("total").asLong()).isEqualTo(3);
        assertThat(nb.get("position").isNull()).isFalse();
        JsonNode outside = getJson(a, "/api/incidents/queue/neighbors?jobId=98111&queueRank=2&period=all&attack=t1059");
        assertThat(outside.get("position").isNull()).isTrue();
        assertThat(outside.get("total").asLong()).isEqualTo(3);
    }

    /* ───────────── 묶음 표지 ───────────── */

    @Test
    void threadBadgeFollowsTheDetailThreadDefinition() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        MockHttpSession v = login(UserRole.VIEWER, ALLOWED);
        long a1No = no(a1());
        long a6No = no(a6());
        long oldNo = no(old());
        long i1No = no(i(1, 1));
        long i3No = no(i(3, 4));
        // 번호는 탐지 시각 순서라 OLD(11-10)가 A6(11-20)보다 작다
        assertThat(a6No).isGreaterThan(oldNo);

        for (MockHttpSession s : List.of(a, v)) {
            Map<String, JsonNode> rows = rowsByRank(getJson(s, "/api/incidents/queue?period=all&size=100"));
            // 머리 자신 포함. 숨김 캡처 구성원(H1)은 세지 않는다
            expectBadge(rows, CAP_A + "#1", a1No, 4);
            // 여러 묶음에 속하면 큰 묶음(A2: A1 묶음과 번호 행 없는 머리 G / A7: A1 묶음 4건과 I1 묶음 3건)
            expectBadge(rows, CAP_A + "#2", a1No, 4);
            expectBadge(rows, CAP_A + "#7", a1No, 4);
            // 부모 앞뒤 공백
            expectBadge(rows, CAP_A + "#3", a1No, 4);
            // 숨김 캡처 머리(H2): 번호·건수가 나가지 않는다
            expectNoBadge(rows, CAP_A + "#4");
            // 기준 시각 전 알림만으로 된 묶음도 2건이면 표지가 있다. 건수가 같으면 번호가 큰 머리(A6 > OLD)
            expectBadge(rows, CAP_A + "#6", a6No, 2);
            expectBadge(rows, CAP_A + "#5", a6No, 2);
            expectBadge(rows, CAP_I + "#1", i1No, 3);
            expectBadge(rows, CAP_I + "#2", i1No, 3);
            // 자기 Slack 행이 없는 머리(I3)의 행에는 표지가 없고 답글 행에는 있다
            expectNoBadge(rows, CAP_I + "#3");
            expectBadge(rows, CAP_I + "#4", i3No, 3);
            expectBadge(rows, CAP_I + "#5", i3No, 3);
            // 구성원 1건(혼자인 알림)은 표지 없음
            expectNoBadge(rows, CAP_A + "#11");
            expectNoBadge(rows, CAP_A + "#" + (10 + FILLERS));
        }
        // 조회자 응답에 가리지 않은 주소가 없다
        assertThat(IPV4.matcher(getBody(v, "/api/incidents/queue?period=all&size=100")).find()).isFalse();

        // 조건(기간·수집원·거르기)과 무관하게 허용 캡처 전체에서 센다
        Map<String, JsonNode> narrowed = rowsByRank(getJson(a, "/api/incidents/queue?period=24h&source=imported&hostIp=10.45.3.3"));
        assertThat(narrowed).hasSize(1);
        expectBadge(narrowed, CAP_I + "#2", i1No, 3);

        // 허용 캡처가 다르면 건수도 다르다(가져온 데이터만 허용: I1 묶음에서 A7이 빠지고 머리 OLD는 보이지 않는다)
        MockHttpSession onlyI = login(UserRole.ANALYST, "t45i-*");
        Map<String, JsonNode> iRows = rowsByRank(getJson(onlyI, "/api/incidents/queue?period=all&size=100"));
        expectBadge(iRows, CAP_I + "#1", i1No, 2);
        expectBadge(iRows, CAP_I + "#2", i1No, 2);
        // 숨김 캡처까지 허용: A1 묶음 5건, H2 묶음이 보인다
        MockHttpSession all = login(UserRole.ANALYST, EVERYTHING);
        Map<String, JsonNode> allRows = rowsByRank(getJson(all, "/api/incidents/queue?period=all&size=100"));
        expectBadge(allRows, CAP_A + "#1", a1No, 5);
        expectBadge(allRows, HIDDEN + "#1", a1No, 5);
        expectBadge(allRows, CAP_A + "#4", no(h(5, 5)), 2);
        expectBadge(allRows, HIDDEN + "#2", no(h(5, 5)), 2);
        expectNoBadge(allRows, HIDDEN + "#3");
        // 숨김 머리의 번호 값이 분석가(허용 둘) 응답 행에 없다
        long h2No = no(h(5, 5));
        for (JsonNode row : rowsByRank(getJson(a, "/api/incidents/queue?period=all&size=100")).values()) {
            assertThat(noValue(row, "threadHeadNo") || row.get("threadHeadNo").asLong() != h2No).isTrue();
        }
    }

    @Test
    void threadBadgeEqualsDetailMemberCountAndQueueThreadTotal() throws Exception {
        for (MockHttpSession s : List.of(login(UserRole.ANALYST, ALLOWED), login(UserRole.VIEWER, ALLOWED),
                login(UserRole.ANALYST, EVERYTHING), login(UserRole.ANALYST, "t45i-*"))) {
            JsonNode q = getJson(s, "/api/incidents/queue?period=all&size=100");
            Map<Long, Long> seen = new HashMap<>();
            for (JsonNode row : q.get("items")) {
                if (!noValue(row, "threadHeadNo")) {
                    seen.put(row.get("threadHeadNo").asLong(), row.get("threadMemberCount").asLong());
                }
            }
            assertThat(seen).isNotEmpty();
            Map<Long, JsonNode> rowByNo = new HashMap<>();
            for (JsonNode row : q.get("items")) {
                rowByNo.put(row.get("incidentNo").asLong(), row);
            }
            int detailChecked = 0;
            for (Map.Entry<Long, Long> e : seen.entrySet()) {
                assertThat(e.getValue()).isGreaterThanOrEqualTo(2);
                // 큐 thread 조건의 total(같은 사용자)
                long total = getJson(s, "/api/incidents/queue?period=all&thread=" + e.getKey()).get("total").asLong();
                assertThat(total).as("thread " + e.getKey()).isEqualTo(e.getValue());
                // 머리 인시던트 상세 Slack 탭의 memberCount(머리 자신의 Slack 행이 있는 묶음)
                JsonNode headRow = rowByNo.get(e.getKey());
                assertThat(headRow).isNotNull();
                JsonNode detail = getJson(s, "/api/incidents/" + headRow.get("jobId").asLong() + "/rank/"
                        + headRow.get("queueRank").asInt());
                for (JsonNode group : detail.at("/detail/slackThreadGroups")) {
                    if (group.get("headIsSelf").asBoolean()) {
                        assertThat(group.get("memberCount").asLong()).as("detail " + e.getKey()).isEqualTo(e.getValue());
                        assertThat(group.get("headIncidentNo").asLong()).isEqualTo(e.getKey());
                        detailChecked++;
                    }
                }
            }
            assertThat(detailChecked).isPositive();
        }
    }

    @Test
    void threadBadgeReadsOnlyAndQueryCountDoesNotGrowWithPageRows() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        // 캡처별 마지막 탐지 캐시를 미리 채운다(첫 요청만 한 번 더 읽는다)
        getJson(a, "/api/incidents/queue?period=all&size=25");
        assertThat(countRefs(g())).isZero();

        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
        JsonNode small = getJson(a, "/api/incidents/queue?period=all&size=25");
        int smallReads = Mockito.mockingDetails(zeekadReadMapper).getInvocations().size();
        int smallRefReads = Mockito.mockingDetails(refMapper).getInvocations().size();
        assertThat(small.get("items")).hasSize(25);
        // 묶음 표지는 번호 행 읽기(readRefsOnly) 한 번만 쓴다. 쪽 행 번호는 지금처럼 numbersFor 한 번
        Mockito.verify(refService, Mockito.times(1)).readRefsOnly(any());
        Mockito.verify(refService, Mockito.times(1)).numbersFor(any());
        Mockito.verify(refService, Mockito.never()).numberFor(any());
        Mockito.verify(refService, Mockito.never()).syncAll();
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findThreadRepliesByHeads(any(), ArgumentMatchers.anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).countLatestQueueRowsByIncidentIds(any(), any());
        // 행마다 부르는 옛 질의는 쓰지 않는다
        Mockito.verify(zeekadReadMapper, Mockito.never()).findThreadReplyIncidentIds(any(), ArgumentMatchers.anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countLatestQueueByIncidentIds(any(), any());

        Mockito.clearInvocations(refService, refMapper, zeekadReadMapper);
        JsonNode large = getJson(a, "/api/incidents/queue?period=all&size=100");
        assertThat(large.get("items")).hasSize(12 + FILLERS);
        // 쪽 크기 25(25행)와 100(52행)에서 읽기 DB·번호 DB 호출 수가 같다
        assertThat(Mockito.mockingDetails(zeekadReadMapper).getInvocations()).hasSize(smallReads);
        assertThat(Mockito.mockingDetails(refMapper).getInvocations()).hasSize(smallRefReads);
        Mockito.verify(refMapper, Mockito.never()).insertIfAbsent(anyString(), anyString(), any(), any());
        // 번호 행이 없는 머리(G)에 번호를 매기지 않았다
        assertThat(countRefs(g())).isZero();
    }

    @Test
    void threadBadgeSkipsQueriesWhenPageIsEmptyOrHasNoVisibleHead() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        getJson(a, "/api/incidents/queue?period=all&size=25");

        // 쪽이 비면 묶음 질의를 하나도 부르지 않는다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        assertThat(getJson(a, "/api/incidents/queue?period=all&status=closed").get("items")).isEmpty();
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findUnifiedQueue(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findThreadRepliesByHeads(any(), ArgumentMatchers.anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countLatestQueueRowsByIncidentIds(any(), any());
        Mockito.verify(refService, Mockito.never()).readRefsOnly(any());

        // 후보 머리가 없으면(Slack 행이 없는 I3) 번호 행·답글·소속을 읽지 않는다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        assertThat(getJson(a, "/api/incidents/queue?period=all&hostIp=10.45.3.4").get("items")).hasSize(1);
        Mockito.verify(zeekadReadMapper, Mockito.times(1)).findSlackThreadLinksByIncidentIds(any());
        Mockito.verify(refService, Mockito.never()).readRefsOnly(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findThreadRepliesByHeads(any(), ArgumentMatchers.anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countLatestQueueRowsByIncidentIds(any(), any());

        // 후보 머리가 있어도 보이는 머리가 없으면(숨김 머리 H2뿐인 A4) 답글·소속을 읽지 않는다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        JsonNode a4 = getJson(a, "/api/incidents/queue?period=all&hostIp=10.45.2.4");
        assertThat(a4.get("items")).hasSize(1);
        assertThat(noValue(a4.get("items").get(0), "threadHeadNo")).isTrue();
        assertThat(noValue(a4.get("items").get(0), "threadMemberCount")).isTrue();
        Mockito.verify(refService, Mockito.times(1)).readRefsOnly(any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findThreadRepliesByHeads(any(), ArgumentMatchers.anyInt());
        Mockito.verify(zeekadReadMapper, Mockito.never()).countLatestQueueRowsByIncidentIds(any(), any());

        // 새 건수·이전·다음 응답에는 묶음 표지가 없고 묶음 질의도 부르지 않는다
        Mockito.clearInvocations(refService, zeekadReadMapper);
        String nc = getBody(a, "/api/incidents/queue/new-count?since=" + SINCE);
        String nb = getBody(a, "/api/incidents/queue/neighbors?jobId=98111&queueRank=1&period=all");
        assertThat(nc).doesNotContain("threadHeadNo").doesNotContain("threadMemberCount");
        assertThat(nb).doesNotContain("threadHeadNo").doesNotContain("threadMemberCount");
        Mockito.verify(zeekadReadMapper, Mockito.never()).findSlackThreadLinksByIncidentIds(any());
    }

    /** 작업 보고용 측정: 표지가 있을 때와 없을 때(Slack 기록을 지운 뒤)의 큐 응답 시간(H2, 참고 값) */
    @Test
    void threadBadgeTimingForReport() throws Exception {
        MockHttpSession a = login(UserRole.ANALYST, ALLOWED);
        String url = "/api/incidents/queue?period=all&size=100";
        for (int k = 0; k < 5; k++) {
            getBody(a, url);
        }
        long with = medianMillisTimes100(a, url);
        jdbc().update("DELETE FROM dashboard.raw_slack_deliveries WHERE job_id BETWEEN 98110 AND 98119");
        for (int k = 0; k < 5; k++) {
            getBody(a, url);
        }
        long without = medianMillisTimes100(a, url);
        System.out.println("T45-BADGE-TIMING rows=" + (12 + FILLERS) + " withBadges_ms=" + with / 100.0
                + " withoutSlackRows_ms=" + without / 100.0);
        assertThat(with).isPositive();
    }

    private long medianMillisTimes100(MockHttpSession s, String url) throws Exception {
        List<Long> nanos = new ArrayList<>();
        for (int k = 0; k < 15; k++) {
            long t = System.nanoTime();
            getBody(s, url);
            nanos.add(System.nanoTime() - t);
        }
        nanos.sort(Long::compare);
        return nanos.get(nanos.size() / 2) / 10_000;
    }

    /* ───────────── 도우미 ───────────── */

    private static void expectBadge(Map<String, JsonNode> rows, String key, long headNo, long count) {
        JsonNode row = rows.get(key);
        assertThat(row).as(key).isNotNull();
        assertThat(noValue(row, "threadHeadNo")).as(key + " has badge").isFalse();
        assertThat(row.get("threadHeadNo").asLong()).as(key + " head").isEqualTo(headNo);
        assertThat(row.get("threadMemberCount").asLong()).as(key + " count").isEqualTo(count);
    }

    private static void expectNoBadge(Map<String, JsonNode> rows, String key) {
        JsonNode row = rows.get(key);
        assertThat(row).as(key).isNotNull();
        assertThat(noValue(row, "threadHeadNo")).as(key + " head").isTrue();
        assertThat(noValue(row, "threadMemberCount")).as(key + " count").isTrue();
    }

    /** 값 없음: JSON null(필드가 빠진 응답도 같은 뜻으로 읽는다) */
    private static boolean noValue(JsonNode row, String field) {
        JsonNode v = row.path(field);
        return v.isNull() || v.isMissingNode();
    }

    /** "캡처#순위" → 행 */
    private static Map<String, JsonNode> rowsByRank(JsonNode queue) {
        Map<String, JsonNode> out = new HashMap<>();
        for (JsonNode it : queue.get("items")) {
            out.put(it.get("captureId").asText() + "#" + it.get("queueRank").asInt(), it);
        }
        return out;
    }

    private static Set<String> ranks(JsonNode queue) {
        return new TreeSet<>(rowsByRank(queue).keySet());
    }

    private static Set<String> hosts(JsonNode queue) {
        Set<String> out = new TreeSet<>();
        for (JsonNode it : queue.get("items")) {
            out.add(it.get("hostIp").asText());
        }
        return out;
    }

    private String a1() { return id(CAP_A, "10.45.1.1"); }
    private String a(int last) { return id(CAP_A, "10.45.1." + last); }
    private String a6() { return id(CAP_A, "10.46.1.1"); }
    private String a7() { return CAP_A + "|10.45.1.1|responder|" + tag; }
    private String old() { return id(CAP_A, "10.45.9.9"); }
    private String g() { return id(CAP_A, "10.45.8.8"); }
    private String i(int c, int d) { return id(CAP_I, "10.45." + c + "." + d); }
    private String h(int c, int d) { return id(HIDDEN, "10.45." + c + "." + d); }

    private String id(String capture, String ip) {
        return capture + "|" + ip + "|originator|" + tag;
    }

    private long no(String incidentId) {
        Long n = app().queryForObject("SELECT incident_no FROM incident_refs WHERE incident_id = ?", Long.class, incidentId);
        assertThat(n).as(incidentId).isNotNull();
        return n;
    }

    private int countRefs(String incidentId) {
        return app().queryForObject("SELECT COUNT(*) FROM incident_refs WHERE incident_id = ?", Integer.class, incidentId);
    }

    private long auditCount() {
        return app().queryForObject("SELECT COUNT(*) FROM audit_logs", Long.class);
    }

    private void deleteRows() {
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 98110 AND 98119";
        z.update("DELETE FROM dashboard.raw_slack_deliveries WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_reports WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    private void job(long jobId, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-09T00:00:00Z', "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                jobId, capture, finished);
    }

    private void incident(long jobId, String capture, int rank, String ip, String role) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-09T20:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-09T20:05:00Z', 'hbos', NULL, ?, NULL)",
                jobId, capture, rank, capture + "|" + ip + "|" + role + "|" + tag, ip, role, 1000 - rank);
    }

    private void slack(long jobId, String incidentId, String parent, int minute) throws Exception {
        slackAt(jobId, incidentId, parent, String.format("2026-11-20T12:%02d:00Z", minute));
    }

    private void slackAt(long jobId, String incidentId, String parent, String createdAt) throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("text", "t45 알림");
        if (parent != null) {
            payload.put("zeekad_thread_parent", parent.trim());
        }
        jdbc().update("INSERT INTO dashboard.raw_slack_deliveries (job_id, incident_id, zeekad_message_kind, zeekad_message_version, "
                        + "zeekad_delivery_mode, zeekad_delivery_status, slack_payload, slack_ts, delivered_at, error, created_at, "
                        + "zeekad_thread_parent, zeekad_reply_broadcast) VALUES (?, ?, 'incident', 'incident.v2', 'dry_run', 'recorded', "
                        + "? FORMAT JSON, NULL, NULL, NULL, CAST(? AS TIMESTAMP WITH TIME ZONE), ?, FALSE)",
                jobId, incidentId, objectMapper.writeValueAsString(payload), createdAt, parent);
    }

    /** candidates가 null이면 열 값 없음(SQL NULL), "null"이면 JSON null */
    private void report(long jobId, String incidentId, String candidates) {
        if (candidates == null) {
            jdbc().update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                            + "zeekad_report, zeekad_attack_candidates, created_at) VALUES (?, ?, 'llm', 'report.v1', "
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
        String username = "t45_u" + (++seq) + "_" + System.nanoTime() % 100000;
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
