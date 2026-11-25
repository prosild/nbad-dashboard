package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.OperationsApiResponse.HandlingTimes;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.HandlingMetricsService;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T34 사용자 지정 기간(period=custom&start&end). 입력 검사(네 API), (시작, 끝] 경계가 큐·현황판·운영 현황에서 같음,
 * 끝이 기준 시각 뒤일 때 unbucketed.afterAnchor, 기간 밖 수(앞뒤 합, newestOutsidePeriod null, SQL·자산 검색 경로),
 * 이웃 이동, 처리 시간 지표, 프리셋 응답의 periodStart·periodEnd.
 *
 * 시험 데이터(기준 시각 = 2026-11-21 00:00Z, now 모드). 시험 행은 job 93400~93419.
 *  t34a-cap(가져온 데이터): 작업 93400(11-18 00:00) X0 / 93401(11-19 00:00) +X1 / 93402(11-19 01:30) +X3 /
 *                          93403(11-19 03:00) +X2 / 93404(11-19 05:00, 최신) +X4 → 탐지 X0 11-18 00:00, X1 11-19 00:00,
 *                          X3 01:30, X2 03:00, X4 05:00
 *  t34b-cap(가져온 데이터): 93405(11-20 12:00) B1 / 93406(11-22 00:00, 최신) +B2 → B2는 기준 시각 뒤
 *  lab-t34(실습망): 93410(11-19 02:00) L1·L2. L1 사건 시작 01:00, 착수 02:30, 종결 04:00(판정 true_positive). L2 착수 03:30
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T34CustomPeriodIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final String QUEUE_PATTERNS = "t34a-*,t34b-*";
    private static final String S = "2026-11-19T00:00:00Z";
    private static final String E = "2026-11-19T03:00:00Z";
    private static final String NEW_FORMAT_MARKER = "zzT34MARKERzz";

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
    @Autowired private IncidentQueueService queueService;
    @Autowired private HandlingMetricsService metricsService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    private static int seq = 0;

    @BeforeEach
    void seed() {
        cleanup();
        String[] a = {"X0", "X1", "X3", "X2", "X4"};
        String[] aFinished = {"2026-11-18T00:00:00Z", "2026-11-19T00:00:00Z", "2026-11-19T01:30:00Z",
                "2026-11-19T03:00:00Z", "2026-11-19T05:00:00Z"};
        for (int j = 0; j < a.length; j++) {
            job(93400 + j, "t34a-cap", aFinished[j]);
            for (int k = 0; k <= j; k++) {
                incident(93400 + j, "t34a-cap", k + 1, a[k], "2026-11-01T00:00:00Z");
            }
        }
        job(93405, "t34b-cap", "2026-11-20T12:00:00Z");
        incident(93405, "t34b-cap", 1, "B1", "2026-11-01T00:00:00Z");
        job(93406, "t34b-cap", "2026-11-22T00:00:00Z");
        incident(93406, "t34b-cap", 1, "B1", "2026-11-01T00:00:00Z");
        incident(93406, "t34b-cap", 2, "B2", "2026-11-01T00:00:00Z");

        job(93410, "lab-t34", "2026-11-19T02:00:00Z");
        incident(93410, "lab-t34", 1, "L1", "2026-11-19T01:00:00Z");
        incident(93410, "lab-t34", 2, "L2", "2026-11-19T01:30:00Z");
        history(93410, "lab-t34", "L1", "open", "investigating", null, "2026-11-19T02:30:00Z");
        history(93410, "lab-t34", "L1", "investigating", "closed", "true_positive", "2026-11-19T04:00:00Z");
        setStatus(93410, "lab-t34", "L1", "closed", "true_positive", "2026-11-19T04:00:00Z");
        history(93410, "lab-t34", "L2", "open", "investigating", null, "2026-11-19T03:30:00Z");
        setStatus(93410, "lab-t34", "L2", "investigating", null, "2026-11-19T03:30:00Z");
    }

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        JdbcTemplate z = jdbc();
        String range = "job_id BETWEEN 93400 AND 93419";
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    /* ───────────── 입력 검사 ───────────── */

    @Test
    void invalidCustomPeriodIs400OnAllFourApisWithoutEchoingInput() throws Exception {
        MockHttpSession s = login(UserRole.VIEWER, QUEUE_PATTERNS);
        List<String> bad = List.of(
                "period=custom",
                "period=custom&start=" + enc(S),
                "period=custom&end=" + enc(E),
                "period=custom&start=" + NEW_FORMAT_MARKER + "&end=" + enc(E),
                "period=custom&start=" + enc(S) + "&end=" + NEW_FORMAT_MARKER,
                "period=custom&start=2026-11-19T00:00:00&end=" + enc(E),            // 오프셋 없음
                "period=custom&start=2026-11-19&end=2026-11-20",                     // 날짜만
                "period=custom&start=2026-11-19T00:00:00%2009:00&end=" + enc(E),   // + 가 공백이 된 값
                "period=24h&start=" + enc(S) + "&end=" + enc(E),
                "period=all&start=" + enc(S),
                "period=7d&end=" + enc(E),
                "start=" + enc(S) + "&end=" + enc(E),                                // period 없음(기본 기간)
                "period=custom&start=" + enc(S) + "&end=" + enc(S),                  // 시작 = 끝
                "period=custom&start=" + enc(E) + "&end=" + enc(S),                  // 시작 > 끝
                "period=custom&start=2025-11-19T00:00:00Z&end=2026-11-20T00:00:01Z", // 366일 + 1초
                "period=custom&start=1999-12-31T14:59:59Z&end=2000-01-02T00:00:00Z", // 2000-01-01 KST 1초 앞
                "period=custom&start=1999-12-31T23:59:59%2B09:00&end=2000-01-02T00:00:00%2B09:00");
        String neighborsKey = "jobId=93404&queueRank=3&";
        for (String q : bad) {
            for (String base : List.of("/api/incidents/queue?", "/api/incidents/queue/neighbors?" + neighborsKey,
                    "/api/dashboard/overview?", "/api/operations?", "/api/hosts?")) {
                MvcResult r = mockMvc.perform(get(URI.create(base + q)).session(s)).andExpect(status().isBadRequest()).andReturn();
                String body = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
                JsonNode json = objectMapper.readTree(body);
                assertThat(json.get("status").asInt()).as(base + q).isEqualTo(400);
                assertThat(json.get("message").asText()).as(base + q).matches(".*[가-힣].*");
                assertThat(body).as(base + q).doesNotContain(NEW_FORMAT_MARKER, "2026-11-19T00:00", "1999-12-31");
            }
        }
        // 운영 현황: period 없이 start·end만 와도 조용히 무시하지 않는다(위 "start=…&end=…"가 400)
        mockMvc.perform(get(URI.create("/api/operations?start=" + enc(S))).session(s)).andExpect(status().isBadRequest());
        mockMvc.perform(get(URI.create("/api/operations?end=" + enc(E))).session(s)).andExpect(status().isBadRequest());
        // period 없는 운영 현황은 그대로 전체(호환)이고 periodStart·periodEnd는 null
        JsonNode legacy = getJson(s, "/api/operations");
        assertThat(legacy.get("period").isNull()).isTrue();
        assertThat(legacy.get("periodStart").isNull()).isTrue();
        assertThat(legacy.get("periodEnd").isNull()).isTrue();
    }

    @Test
    void boundaryValuesPass() throws Exception {
        MockHttpSession s = login(UserRole.VIEWER, QUEUE_PATTERNS);
        List<String[]> ok = List.of(
                new String[]{"2025-11-19T00:00:00Z", "2026-11-20T00:00:00Z"},          // 정확히 366일
                new String[]{"1999-12-31T15:00:00Z", "2000-01-02T00:00:00Z"},          // 2000-01-01 00:00 KST
                new String[]{"2000-01-01T00:00+09:00", "2000-01-02T00:00+09:00"},      // 초 없음, +오프셋
                new String[]{"2026-11-19T09:00:00.000+09:00", "2026-11-19T12:00:00.5+09:00"},
                new String[]{"2026-11-21T00:00:00Z", "2026-11-25T00:00:00Z"});         // 끝이 기준 시각 뒤
        for (String[] r : ok) {
            String q = "period=custom&start=" + enc(r[0]) + "&end=" + enc(r[1]);
            for (String base : List.of("/api/incidents/queue?", "/api/incidents/queue/neighbors?jobId=93404&queueRank=3&",
                    "/api/dashboard/overview?", "/api/operations?", "/api/hosts?")) {
                mockMvc.perform(get(URI.create(base + q)).session(s)).andExpect(status().isOk());
            }
            JsonNode queue = getJson(s, "/api/incidents/queue?" + q);
            assertThat(queue.get("period").asText()).isEqualTo("custom");
            assertThat(instant(queue.get("periodStart"))).isEqualTo(OffsetDateTime.parse(r[0]).toInstant());
            assertThat(instant(queue.get("periodEnd"))).isEqualTo(OffsetDateTime.parse(r[1]).toInstant());
            assertThat(queue.get("periodStart").asText()).endsWith("Z");
        }
    }

    /* ───────────── 경계·응답 ───────────── */

    @Test
    void startExclusiveEndInclusiveIsTheSameOnQueueDashboardAndOperations() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, QUEUE_PATTERNS);
        String q = "period=custom&start=" + enc(S) + "&end=" + enc(E);
        JsonNode queue = getJson(s, "/api/incidents/queue?" + q + "&size=100");
        // X1(= 시작)은 빠지고 X2(= 끝)는 들어간다: X3·X2
        assertThat(queue.get("total").asLong()).isEqualTo(2);
        List<String> ids = new ArrayList<>();
        for (JsonNode it : queue.get("items")) ids.add(it.get("incidentId").asText());
        assertThat(ids).allMatch(id -> id.endsWith("X3") || id.endsWith("X2"));
        assertThat(queue.get("outsidePeriod").asLong()).isEqualTo(5);  // X0·X1·X4·B1·B2 (앞뒤 합)
        assertThat(queue.get("newestOutsidePeriod").isNull()).isTrue();
        assertThat(instant(queue.get("latestDetectedAt"))).isEqualTo(Instant.parse(E));

        JsonNode ov = getJson(s, "/api/dashboard/overview?" + q);
        assertThat(ov.get("period").asText()).isEqualTo("custom");
        assertThat(instant(ov.get("periodStart"))).isEqualTo(Instant.parse(S));
        assertThat(instant(ov.get("periodEnd"))).isEqualTo(Instant.parse(E));
        long captures = 0;
        for (JsonNode c : ov.get("captures")) captures += c.get("total").asLong();
        assertThat(captures).isEqualTo(2);
        assertThat(ov.at("/trend/bucket").asText()).isEqualTo("5m");
        assertThat(trendSum(ov) + unbucketed(ov)).isEqualTo(2);
        assertThat(ov.at("/trend/buckets").size()).isEqualTo(36);

        JsonNode ops = getJson(s, "/api/operations?" + q);
        assertThat(ops.get("period").asText()).isEqualTo("custom");
        assertThat(instant(ops.get("periodStart"))).isEqualTo(Instant.parse(S));
        assertThat(instant(ops.get("periodEnd"))).isEqualTo(Instant.parse(E));
        // 작업은 완료 시각 (시작, 끝]: 93402(01:30)·93403(03:00). 93401(00:00 = 시작)은 빠진다
        List<Long> jobIds = new ArrayList<>();
        for (JsonNode j : ops.get("jobs")) jobIds.add(j.get("jobId").asLong());
        assertThat(jobIds).containsExactlyInAnyOrder(93402L, 93403L);
    }

    @Test
    void endAfterAnchorCountsAfterAnchorRowsOutsideTheTrend() throws Exception {
        MockHttpSession s = login(UserRole.VIEWER, QUEUE_PATTERNS);
        String q = "period=custom&start=" + enc("2026-11-20T00:00:00Z") + "&end=" + enc("2026-11-22T12:00:00Z");
        JsonNode queue = getJson(s, "/api/incidents/queue?" + q);
        assertThat(queue.get("total").asLong()).isEqualTo(2); // B1, B2(기준 시각 뒤)
        JsonNode ov = getJson(s, "/api/dashboard/overview?" + q);
        assertThat(ov.at("/trend/bucket").asText()).isEqualTo("1h");
        assertThat(ov.at("/trend/unbucketed/afterAnchor").asLong()).isEqualTo(1);
        assertThat(ov.at("/trend/unbucketed/noDetectedAt").asLong()).isZero();
        assertThat(trendSum(ov)).isEqualTo(1);
        assertThat(trendSum(ov) + unbucketed(ov)).isEqualTo(queue.get("total").asLong());
        // 구간은 기준 시각까지만: 11-20 09:00 ~ 11-21 09:00 KST, 1시간 24개, 마지막 끝 = 기준 시각
        JsonNode buckets = ov.at("/trend/buckets");
        assertThat(buckets.size()).isEqualTo(24);
        assertThat(instant(buckets.get(23).get("end"))).isEqualTo(FIXED_NOW);
        assertThat(instant(ov.get("periodEnd"))).isEqualTo(Instant.parse("2026-11-22T12:00:00Z"));

        // 시작이 기준 시각 뒤면 구간 0, 모두 afterAnchor
        String later = "period=custom&start=" + enc("2026-11-21T06:00:00Z") + "&end=" + enc("2026-11-22T06:00:00Z");
        JsonNode q2 = getJson(s, "/api/incidents/queue?" + later);
        JsonNode ov2 = getJson(s, "/api/dashboard/overview?" + later);
        assertThat(ov2.at("/trend/buckets").size()).isZero();
        assertThat(ov2.at("/trend/unbucketed/afterAnchor").asLong()).isEqualTo(q2.get("total").asLong()).isEqualTo(1);
    }

    @Test
    void presetResponsesOnlyGainPeriodBounds() throws Exception {
        MockHttpSession s = login(UserRole.VIEWER, QUEUE_PATTERNS);
        for (String period : List.of("1h", "24h", "7d", "30d")) {
            long hours = switch (period) {
                case "1h" -> 1;
                case "24h" -> 24;
                case "7d" -> 24 * 7;
                default -> 24 * 30;
            };
            for (String url : List.of("/api/incidents/queue?period=", "/api/dashboard/overview?period=", "/api/operations?period=",
                    "/api/hosts?period=")) {
                JsonNode n = getJson(s, url + period);
                assertThat(n.get("period").asText()).isEqualTo(period);
                assertThat(instant(n.get("periodEnd"))).as(url + period).isEqualTo(FIXED_NOW);
                assertThat(instant(n.get("periodStart"))).as(url + period).isEqualTo(FIXED_NOW.minusSeconds(hours * 3600));
            }
        }
        for (String url : List.of("/api/incidents/queue?period=all", "/api/dashboard/overview?period=all", "/api/operations?period=all",
                "/api/hosts?period=all")) {
            JsonNode n = getJson(s, url);
            assertThat(n.get("periodStart").isNull()).as(url).isTrue();
            assertThat(n.get("periodEnd").isNull()).as(url).isTrue();
        }
        // 프리셋 24시간 기간 밖은 지금처럼 newestOutsidePeriod를 준다
        JsonNode day = getJson(s, "/api/incidents/queue?period=24h");
        assertThat(day.get("newestOutsidePeriod").isNull()).isFalse();
    }

    /* ───────────── 기간 밖(T29) ───────────── */

    @Test
    void customOutsidePeriodIsBeforePlusAfterOnSqlAndAssetPaths() {
        DashboardUserPrincipal p = principal(QUEUE_PATTERNS);
        // 자산 검색 "."는 모든 행에 맞는다(자산 검색 경로). "10.34.1."은 t34a만
        for (String asset : new String[]{null, ".", "10.34.1."}) {
            UnifiedQueueResponse r = queueService.loadQueue(p, custom(S, E, asset, null), "127.0.0.1");
            UnifiedQueueResponse all = queueService.loadQueue(p, preset("all", asset), "127.0.0.1");
            assertThat(r.total()).as(String.valueOf(asset)).isEqualTo(2);
            assertThat(r.outsidePeriod()).as(String.valueOf(asset)).isEqualTo(all.total() - r.total());
            assertThat(r.newestOutsidePeriod()).as(String.valueOf(asset)).isNull();
            assertThat(r.periodStart().toInstant()).isEqualTo(Instant.parse(S));
        }
        assertThat(queueService.loadQueue(p, custom(S, E, null, null), "127.0.0.1").outsidePeriod()).isEqualTo(5L);
        assertThat(queueService.loadQueue(p, custom(S, E, "10.34.1.", null), "127.0.0.1").outsidePeriod()).isEqualTo(3L);
    }

    /* ───────────── 이웃 이동 ───────────── */

    @Test
    void neighborsMoveOnlyInsideTheCustomRange() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, QUEUE_PATTERNS);
        String q = "period=custom&start=" + enc(S) + "&end=" + enc(E) + "&sort=detected&dir=desc";
        // 탐지 시각 최근순: X2(03:00, rank 4) → X3(01:30, rank 3)
        JsonNode x2 = getJson(s, "/api/incidents/queue/neighbors?jobId=93404&queueRank=4&" + q);
        assertThat(x2.get("total").asInt()).isEqualTo(2);
        assertThat(x2.get("position").asInt()).isEqualTo(1);
        assertThat(x2.get("prev").isNull()).isTrue();
        assertThat(x2.at("/next/queueRank").asInt()).isEqualTo(3);
        JsonNode x3 = getJson(s, "/api/incidents/queue/neighbors?jobId=93404&queueRank=3&" + q);
        assertThat(x3.get("position").asInt()).isEqualTo(2);
        assertThat(x3.at("/prev/queueRank").asInt()).isEqualTo(4);
        assertThat(x3.get("next").isNull()).isTrue();          // X1(= 시작)로 가지 않는다
        // 범위 밖 X4(05:00)는 위치 없음
        JsonNode x4 = getJson(s, "/api/incidents/queue/neighbors?jobId=93404&queueRank=5&" + q);
        assertThat(x4.get("position").isNull()).isTrue();
        assertThat(x4.get("total").asInt()).isEqualTo(2);
    }

    /* ───────────── 처리 시간 지표 ───────────── */

    @Test
    void handlingTimesIgnoreTimesOutsideTheCustomRange() throws Exception {
        MockHttpSession s = login(UserRole.ANALYST, "lab-t34*");
        // (00:00, 03:00]: 탐지 L1·L2(02:00) / 착수 L1(02:30)만, L2(03:30) 밖 / 종결 L1(04:00) 밖
        JsonNode h = getJson(s, "/api/operations?period=custom&start=" + enc(S) + "&end=" + enc(E)).get("handlingTimes");
        assertThat(h.at("/detection/n").asLong()).isEqualTo(2);
        assertThat(h.at("/acknowledge/n").asLong()).isEqualTo(1);
        assertThat(h.at("/acknowledge/medianSeconds").asLong()).isEqualTo(1800);
        assertThat(h.at("/resolve/all/n").asLong()).isZero();
        // (00:00, 05:00]: 착수 둘, 종결 하나
        JsonNode wide = getJson(s, "/api/operations?period=custom&start=" + enc(S) + "&end=" + enc("2026-11-19T05:00:00Z"))
                .get("handlingTimes");
        assertThat(wide.at("/acknowledge/n").asLong()).isEqualTo(2);
        assertThat(wide.at("/resolve/all/n").asLong()).isEqualTo(1);
        assertThat(wide.at("/resolve/all/medianSeconds").asLong()).isEqualTo(7200);
        // (02:30, 03:30]: 탐지 0(02:00 밖), 착수 L2(03:30 = 끝, 포함)만, L1(02:30 = 시작) 밖
        JsonNode edge = getJson(s, "/api/operations?period=custom&start=" + enc("2026-11-19T02:30:00Z")
                + "&end=" + enc("2026-11-19T03:30:00Z")).get("handlingTimes");
        assertThat(edge.at("/detection/n").asLong()).isZero();
        assertThat(edge.at("/acknowledge/n").asLong()).isEqualTo(1);
        assertThat(edge.at("/acknowledge/medianSeconds").asLong()).isEqualTo(5400);
        // 서비스 직접: 조건의 until이 받은 끝이다
        IncidentQueueService.Condition cond = queueService.resolveCondition(principal("lab-t34*"), "custom", S, E,
                null, null, "127.0.0.1");
        assertThat(cond.until().toInstant()).isEqualTo(Instant.parse(E));
        HandlingTimes times = metricsService.compute(cond, true).handlingTimes();
        assertThat(times.acknowledge().n()).isEqualTo(1);
    }

    /* ───────────── 도우미 ───────────── */

    private static QueueParams custom(String start, String end, String asset, String sort) {
        return new QueueParams("custom", null, null, null, null, null, null, null, null, null, null, asset,
                sort, null, null, "100", null, null, start, end);
    }

    private static QueueParams preset(String period, String asset) {
        return new QueueParams(period, null, null, null, null, null, null, null, null, null, null, asset,
                null, null, null, "100");
    }

    private static long trendSum(JsonNode ov) {
        long sum = 0;
        for (JsonNode b : ov.at("/trend/buckets")) sum += b.get("total").asLong();
        return sum;
    }

    private static long unbucketed(JsonNode ov) {
        return ov.at("/trend/unbucketed/noDetectedAt").asLong() + ov.at("/trend/unbucketed/afterAnchor").asLong();
    }

    private static Instant instant(JsonNode n) {
        return OffsetDateTime.parse(n.asText()).toInstant();
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static DashboardUserPrincipal principal(String patterns) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t34-principal");
        u.setDisplayName("t34");
        u.setRole(UserRole.ANALYST);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, List.of(patterns.split(",")), FIXED_NOW);
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t34_u" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, username, "Pass1234!", role, patterns, "seed", "ADMIN", "127.0.0.1");
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

    private static String id(String capture, String name) {
        return capture + "|" + ip(capture, name) + "|originator|t34-" + name;
    }

    private static String ip(String capture, String name) {
        int net = capture.startsWith("t34a") ? 1 : capture.startsWith("t34b") ? 2 : 3;
        return "10.34." + net + "." + (Math.abs(name.hashCode()) % 200 + 1);
    }

    private void job(long id, String capture, String finished) {
        jdbc().update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', CAST(? AS TIMESTAMP WITH TIME ZONE) - INTERVAL '5' MINUTE, "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE), NULL, 0)",
                id, capture, finished, finished);
    }

    private void incident(long jobId, String capture, int rank, String name, String eventStart) {
        jdbc().update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, 'originator', CAST(? AS TIMESTAMP WITH TIME ZONE), "
                        + "CAST(? AS TIMESTAMP WITH TIME ZONE) + INTERVAL '1' MINUTE, 'hbos', NULL, 10, NULL)",
                jobId, capture, rank, id(capture, name), ip(capture, name), eventStart, eventStart);
    }

    private void setStatus(long jobId, String capture, String name, String st, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), 't34')", jobId, id(capture, name), st, resolution, at);
    }

    private void history(long jobId, String capture, String name, String from, String to, String resolution, String at) {
        jdbc().update("INSERT INTO dashboard.raw_incident_status_history (job_id, incident_id, from_status, to_status, zeekad_resolution, "
                + "actor, reason, changed_at) VALUES (?, ?, ?, ?, ?, 'analyst1', 't34', CAST(? AS TIMESTAMP WITH TIME ZONE))",
                jobId, id(capture, name), from, to, resolution, at);
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(URI.create(url)).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
}
