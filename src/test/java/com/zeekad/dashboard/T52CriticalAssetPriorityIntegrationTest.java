package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import com.zeekad.dashboard.testsupport.T51QueueSeed;
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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T52 중요 자산이 자동 분류 우선순위에 닿는 규칙(H2 + MockMvc, 응답 JSON으로 본다).
 * <ul>
 *   <li>규칙 표: (중요 자산 여부) × (기본 우선순위 high·medium·low·종결)의 여덟 경우. host_ip가 NULL인 행은 중요 자산이 아니다.</li>
 *   <li>자산이 없으면 옛 규칙과 같다(priority = priorityBase = 옛 기준 함수, assetCritical 거짓).</li>
 *   <li>정렬: 같은 우선순위 안에서 중요 자산이 먼저(반대 방향이면 나중), 종결 무리도 같다. 쪽을 이어도 빠지거나 겹치지 않는다.</li>
 *   <li>모든 화면이 같은 값: 큐 행·이웃·상세 queueMeta·같은 호스트 인시던트·호스트 위험도·현황판·운영 현황의 착수 지연.</li>
 *   <li>조회자: assetCritical·priorityBase는 받고 criticalAssetName은 늘 null. 자산 설명은 어떤 인시던트 응답에도 없다.</li>
 * </ul>
 * 자료: {@link T51QueueSeed}(조합 표 108행 + 가져온 데이터 17행), 화면 대조용 작은 캡처 lab-t52s, host_ip가 NULL인 행 하나(t52n-cap).
 * 중요 자산은 앱 DB critical_assets에 직접 넣는다(관리자 API는 T52CriticalAssetAdminApiIntegrationTest가 본다).
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t52a_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t52a_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t52a_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T52CriticalAssetPriorityIntegrationTest {

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(T51QueueSeed.NOW);
        }
    }

    /** 화면 대조용 실습망 캡처(작업 97126, 완료 = 탐지 시각 기준 시각 1시간 전) */
    static final String SCREEN = "lab-t52s";
    static final long SCREEN_JOB = 97126L;
    /** host_ip가 NULL인 행 하나(작업 97127) */
    static final String NULL_HOST_CAPTURE = "t52n-cap";
    static final long NULL_HOST_JOB = 97127L;
    static final String NULL_HOST_ID = NULL_HOST_CAPTURE + "|nohost|1";
    static final String RULE_PATTERNS = T51QueueSeed.PATTERNS + ",t52n-*";

    static final String CRITICAL_HOST = "10.52.7.7";
    static final String CRITICAL_NAME = "결제 서버";
    static final String CRITICAL_DESCRIPTION = "설명-비공개-T52-결제-서버-내부-메모";
    /** 화면 자료의 인시던트 A(기본 medium, 중요 자산 → high), B(기본 low → medium), C(다른 호스트 medium), D(다른 호스트 종결), E(중요 자산 종결) */
    static final String A = SCREEN + "|" + CRITICAL_HOST + "|a";
    static final String B = SCREEN + "|" + CRITICAL_HOST + "|b";
    static final String C = SCREEN + "|10.52.7.8|c";
    static final String D = SCREEN + "|10.52.8.1|d";
    static final String E = SCREEN + "|" + CRITICAL_HOST + "|e";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;

    @BeforeEach
    void setUp() {
        clock.set(T51QueueSeed.NOW);
        JdbcTemplate jdbc = zeekad();
        deleteOwnRows(jdbc);
        T51QueueSeed.delete(jdbc);
        T51QueueSeed.insert(jdbc);
        insertScreenRows(jdbc);
        insertNullHostRow(jdbc);
        app().update("DELETE FROM critical_assets");
    }

    @AfterEach
    void cleanup() {
        app().update("DELETE FROM critical_assets");
        JdbcTemplate jdbc = zeekad();
        deleteOwnRows(jdbc);
        T51QueueSeed.delete(jdbc);
    }

    /* ───────────── 규칙 표 ───────────── */

    /** 옛 화면 규칙(T23 refPriority와 같다)을 응답 행의 큐 필드로 계산한다 */
    static String refBase(JsonNode it) {
        String s = it.path("zeekadStatus").isNull() ? "" : it.path("zeekadStatus").asText("").trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) s = "open";
        if ("closed".equals(s)) return null;
        if (it.path("zeekadWouldSend").asBoolean(false) || it.path("zeekadReviewPending").asBoolean(false)) return "high";
        JsonNode also = it.path("zeekadAlsoFlaggedBy");
        int alsoCount = also.isArray() ? also.size() : 0;
        if (alsoCount >= 1 || it.path("hasReport").asBoolean(false)) return "medium";
        return "low";
    }

    /** 한 단계 올림: Low → Medium, Medium → High. High와 종결은 그대로 */
    static String raise(String base, boolean critical) {
        if (base == null || !critical) return base;
        return switch (base) {
            case "low" -> "medium";
            case "medium", "high" -> "high";
            default -> base;
        };
    }

    /**
     * 조합 표 행 가운데 순위 % 3 == 1(36개 호스트)과 가져온 데이터 다섯(짝수 2~10), 행이 없는 주소 하나.
     * 가져온 데이터 다섯은 오름 정렬에서 Medium 무리의 중요·보통 경계를 50번째 뒤에 두려고 고른 수다(25·50건 쪽의 경계와 겹친다).
     */
    private Map<String, String> ruleAssets() {
        Map<String, String> assets = new LinkedHashMap<>();
        for (int rank = 1; rank <= T51QueueSeed.COMBINATIONS; rank++) {
            if (rank % 3 == 1) {
                assets.put(T51QueueSeed.liveHost(rank), "대상 " + rank);
            }
        }
        for (int k = 2; k <= 10; k += 2) {
            assets.put("10.52.0." + k, "가져온 " + k);
        }
        assets.put("10.99.99.99", "행 없음");
        return assets;
    }

    @Test
    void ruleTableCoversAllEightCasesAndNullHostIsNeverCritical() throws Exception {
        Map<String, String> assets = ruleAssets();
        register(assets);
        MockHttpSession analyst = login(UserRole.ANALYST, RULE_PATTERNS);
        List<JsonNode> items = allItems(analyst, "period=all&sort=priority");
        assertThat(items).hasSize(T51QueueSeed.COMBINATIONS + T51QueueSeed.IMPORTED_ROWS + T51QueueSeed.NO_DETECT_ROWS + 1);

        Map<String, Integer> cases = new LinkedHashMap<>();
        for (JsonNode it : items) {
            String host = it.path("hostIp").isNull() ? null : it.path("hostIp").asText();
            boolean critical = host != null && assets.containsKey(host);
            String base = refBase(it);
            String label = it.path("incidentId").asText();
            assertThat(it.has("assetCritical")).as("assetCritical 키 %s", label).isTrue();
            assertThat(it.path("assetCritical").asBoolean()).as("assetCritical %s", label).isEqualTo(critical);
            assertThat(nullableText(it, "priorityBase")).as("priorityBase %s", label).isEqualTo(base);
            assertThat(nullableText(it, "priority")).as("priority %s", label).isEqualTo(raise(base, critical));
            assertThat(nullableText(it, "criticalAssetName")).as("criticalAssetName %s", label)
                    .isEqualTo(critical ? assets.get(host) : null);
            cases.merge((critical ? "중요 " : "보통 ") + base, 1, Integer::sum);
        }
        // 여덟 경우가 모두 나온다(중요 자산 × high·medium·low·종결)
        assertThat(cases.keySet()).containsExactlyInAnyOrder(
                "중요 high", "중요 medium", "중요 low", "중요 null",
                "보통 high", "보통 medium", "보통 low", "보통 null");

        // host_ip가 NULL인 행: 자산 목록이 비어 있지 않아도 중요 자산이 아니고 우선순위는 기본값 그대로다
        assertThat(zeekad().queryForObject(
                "SELECT COUNT(*) FROM dashboard.latest_incident_queue WHERE incident_id = ? AND host_ip IS NULL",
                Long.class, NULL_HOST_ID)).isEqualTo(1L);
        JsonNode nullHost = items.stream().filter(it -> NULL_HOST_ID.equals(it.path("incidentId").asText()))
                .findFirst().orElseThrow();
        assertThat(nullHost.path("assetCritical").isBoolean()).isTrue();
        assertThat(nullHost.path("assetCritical").asBoolean()).isFalse();
        assertThat(nullHost.path("priority").asText()).isEqualTo("low");
        assertThat(nullHost.path("priorityBase").asText()).isEqualTo("low");
        assertThat(nullHost.path("criticalAssetName").isNull()).isTrue();
    }

    @Test
    void withoutAssetsEveryRowKeepsTheOldRule() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, RULE_PATTERNS);
        List<JsonNode> items = allItems(analyst, "period=all");
        assertThat(items).hasSizeGreaterThan(100);
        Set<String> seen = new HashSet<>();
        for (JsonNode it : items) {
            String base = refBase(it);
            String label = it.path("incidentId").asText();
            assertThat(nullableText(it, "priority")).as("priority %s", label).isEqualTo(base);
            assertThat(nullableText(it, "priorityBase")).as("priorityBase %s", label).isEqualTo(base);
            assertThat(it.path("assetCritical").isBoolean()).as("assetCritical 형 %s", label).isTrue();
            assertThat(it.path("assetCritical").asBoolean()).as("assetCritical %s", label).isFalse();
            assertThat(it.has("criticalAssetName") && it.get("criticalAssetName").isNull()).as("criticalAssetName %s", label).isTrue();
            seen.add(String.valueOf(base));
        }
        assertThat(seen).containsExactlyInAnyOrder("high", "medium", "low", "null");
    }

    /* ───────────── 정렬과 쪽 이음 ───────────── */

    private static int priorityIndex(String p) {
        return p == null ? -1 : List.of("high", "medium", "low").indexOf(p);
    }

    /** 서버 정렬의 기준: 우선순위(값 없음은 방향과 상관없이 뒤) → 중요 자산(High가 먼저인 방향이면 먼저) → 탐지 최근 → 캡처 → 순위 */
    static Comparator<JsonNode> refOrder(boolean asc) {
        Comparator<JsonNode> byPriority = (a, b) -> {
            int pa = priorityIndex(nullableText(a, "priority"));
            int pb = priorityIndex(nullableText(b, "priority"));
            if (pa < 0 && pb < 0) return 0;
            if (pa < 0) return 1;
            if (pb < 0) return -1;
            return asc ? Integer.compare(pa, pb) : Integer.compare(pb, pa);
        };
        Comparator<JsonNode> byCritical = (a, b) -> {
            int ca = a.path("assetCritical").asBoolean() ? 1 : 0;
            int cb = b.path("assetCritical").asBoolean() ? 1 : 0;
            return asc ? Integer.compare(cb, ca) : Integer.compare(ca, cb);
        };
        Comparator<JsonNode> byDetected = (a, b) -> {
            Instant da = instant(a.path("detectedAt"));
            Instant db = instant(b.path("detectedAt"));
            if (da == null && db == null) return 0;
            if (da == null) return 1;
            if (db == null) return -1;
            return db.compareTo(da);
        };
        return byPriority.thenComparing(byCritical).thenComparing(byDetected)
                .thenComparing(n -> n.path("captureId").asText())
                .thenComparing(n -> n.path("queueRank").asInt());
    }

    @Test
    void criticalAssetsComeFirstWithinEachPriorityAndPagesJoinWithoutGapsOrDuplicates() throws Exception {
        register(ruleAssets());
        MockHttpSession analyst = login(UserRole.ANALYST, RULE_PATTERNS);
        int boundaries = 0;
        for (String dir : new String[]{null, "asc", "desc"}) {
            boolean asc = !"desc".equals(dir);
            String base = "period=all&sort=priority" + (dir == null ? "" : "&dir=" + dir);
            List<JsonNode> full = allItems(analyst, base);
            List<JsonNode> expected = new ArrayList<>(full);
            expected.sort(refOrder(asc));
            assertThat(keys(full)).as("정렬 %s", dir).containsExactlyElementsOf(keys(expected));

            // 무리마다 중요·보통이 섞여 있어야 새 키를 실제로 시험한다(종결 무리 포함).
            // Low 무리에는 중요 자산이 남지 않는다(중요 자산의 Low는 모두 Medium으로 올라간다)
            for (String p : new String[]{"high", "medium", "low", null}) {
                Set<Boolean> kinds = new HashSet<>();
                for (JsonNode it : full) {
                    if (java.util.Objects.equals(nullableText(it, "priority"), p)) kinds.add(it.path("assetCritical").asBoolean());
                }
                if ("low".equals(p)) {
                    assertThat(kinds).as("Low 무리").containsExactly(false);
                } else {
                    assertThat(kinds).as("무리 %s에 중요·보통이 모두 있다", p).containsExactlyInAnyOrder(true, false);
                }
            }
            // 종결 무리 안에서도 같은 방향: asc면 중요 자산이 먼저, desc면 나중
            List<Boolean> closedFlags = full.stream().filter(it -> it.path("priority").isNull())
                    .map(it -> it.path("assetCritical").asBoolean()).toList();
            int firstOther = closedFlags.indexOf(!asc);
            assertThat(closedFlags.subList(firstOther, closedFlags.size())).as("종결 무리 %s", dir).doesNotContain(asc);

            for (int size : new int[]{25, 50}) {
                List<JsonNode> joined = new ArrayList<>();
                int pageCount = 1;
                for (int p = 1; p <= pageCount; p++) {
                    JsonNode page = getJson(analyst, "/api/incidents/queue?" + base + "&size=" + size + "&page=" + p);
                    pageCount = page.get("pageCount").asInt();
                    assertThat(page.get("page").asInt()).isEqualTo(p);
                    page.get("items").forEach(joined::add);
                    // 쪽 끝이 같은 우선순위의 중요·보통 경계에 걸린 곳을 센다
                    if (p < pageCount) {
                        JsonNode last = page.get("items").get(page.get("items").size() - 1);
                        JsonNode next = getJson(analyst, "/api/incidents/queue?" + base + "&size=" + size + "&page=" + (p + 1))
                                .get("items").get(0);
                        if (java.util.Objects.equals(nullableText(last, "priority"), nullableText(next, "priority"))
                                && last.path("assetCritical").asBoolean() != next.path("assetCritical").asBoolean()) {
                            boundaries++;
                        }
                    }
                }
                assertThat(keys(joined)).as("쪽 이음 %s size=%d", dir, size).containsExactlyElementsOf(keys(full));
                assertThat(keys(joined)).doesNotHaveDuplicates();
            }
        }
        assertThat(boundaries).as("중요·보통 경계가 쪽 사이에 걸린 경우").isPositive();
    }

    /* ───────────── 착수 지연 ───────────── */

    @Test
    void ackOverdueUsesTheRaisedPriorityTarget() throws Exception {
        MockHttpSession analyst = login(UserRole.ANALYST, SCREEN);
        // 등록 전: A(medium, 탐지 1시간 전)는 목표 4시간 안이라 지연이 아니다
        JsonNode before = getJson(analyst, "/api/incidents/queue?period=all&size=100");
        assertThat(item(before, A).path("ackOverdue").asBoolean()).isFalse();
        assertThat(before.path("summary").path("overdue").asLong()).isZero();
        assertThat(getJson(analyst, "/api/operations").path("workload").path("ackOverdue").asLong()).isZero();

        register(Map.of(CRITICAL_HOST, CRITICAL_NAME));
        JsonNode after = getJson(analyst, "/api/incidents/queue?period=all&size=100");
        JsonNode a = item(after, A);
        assertThat(a.path("priority").asText()).isEqualTo("high");
        assertThat(a.path("ackOverdue").asBoolean()).isTrue();
        // 목표 = 탐지 + High 목표(30분)
        assertThat(Instant.parse(a.path("ackDueAt").asText()))
                .isEqualTo(Instant.parse(a.path("detectedAt").asText()).plusSeconds(30 * 60));
        // B(low → medium, 탐지 1시간 전)는 Medium 목표 4시간 안이라 지연이 아니다
        JsonNode b = item(after, B);
        assertThat(b.path("priority").asText()).isEqualTo("medium");
        assertThat(b.path("ackOverdue").asBoolean()).isFalse();
        assertThat(Instant.parse(b.path("ackDueAt").asText()))
                .isEqualTo(Instant.parse(b.path("detectedAt").asText()).plusSeconds(4 * 3600));
        assertThat(after.path("summary").path("overdue").asLong()).isEqualTo(1L);
        // 띠 축 착수 지연과 운영 현황이 같은 판정을 쓴다
        JsonNode strip = getJson(analyst, "/api/incidents/queue?period=all&size=100&overdue=true");
        assertThat(ids(strip)).containsExactly(A);
        assertThat(getJson(analyst, "/api/operations").path("workload").path("ackOverdue").asLong()).isEqualTo(1L);

        // 조합 표: low → medium으로 올라간 미종결 실습망 행 가운데 탐지가 4시간 넘게·24시간 안 전이면 지연이다
        register(ruleAssets());
        MockHttpSession rule = login(UserRole.ANALYST, RULE_PATTERNS);
        Instant now = T51QueueSeed.NOW;
        int raisedOverdue = 0;
        for (JsonNode it : allItems(rule, "period=all")) {
            if (!"low".equals(nullableText(it, "priorityBase")) || !"medium".equals(nullableText(it, "priority"))
                    || !T51QueueSeed.LIVE.equals(it.path("captureId").asText())) {
                continue;
            }
            String st = it.path("zeekadStatus").asText("").trim().toLowerCase(Locale.ROOT);
            Instant detected = instant(it.path("detectedAt"));
            if (!"open".equals(st) || detected == null) continue;
            boolean expected = detected.isBefore(now.minusSeconds(4 * 3600));
            assertThat(it.path("ackOverdue").asBoolean()).as("착수 지연 %s", it.path("incidentId").asText()).isEqualTo(expected);
            if (expected && detected.isAfter(now.minusSeconds(24 * 3600))) raisedOverdue++;
        }
        assertThat(raisedOverdue).as("Low 목표(24시간)로는 지연이 아니고 Medium 목표로는 지연인 행").isPositive();
    }

    /* ───────────── 모든 화면이 같은 값 ───────────── */

    @Test
    void everyScreenUsesTheRaisedValue() throws Exception {
        register(Map.of(CRITICAL_HOST, CRITICAL_NAME));
        MockHttpSession analyst = login(UserRole.ANALYST, SCREEN);
        List<String> bodies = new ArrayList<>();

        // 큐 행: A가 high(기본 medium), 같은 우선순위 안 중요 자산 먼저. 순서 A, B, C, E, D
        String queueBody = getBody(analyst, "/api/incidents/queue?period=all&size=100");
        bodies.add(queueBody);
        JsonNode queue = objectMapper.readTree(queueBody);
        assertThat(ids(queue)).containsExactly(A, B, C, E, D);
        assertRow(item(queue, A), "high", "medium", true, CRITICAL_NAME);
        assertRow(item(queue, B), "medium", "low", true, CRITICAL_NAME);
        assertRow(item(queue, C), "medium", "medium", false, null);
        assertRow(item(queue, D), null, null, false, null);
        assertRow(item(queue, E), null, null, true, CRITICAL_NAME);
        assertThat(queue.path("summary").path("high").asLong()).isEqualTo(1L);
        assertThat(queue.path("summary").path("medium").asLong()).isEqualTo(2L);
        assertThat(queue.path("summary").path("low").asLong()).isZero();
        // 분석가 응답에 새 키가 행마다 한 번씩만 나온다(행 객체 쪽은 직렬화하지 않는다)
        int rows = queue.get("items").size();
        for (String key : List.of("assetCritical", "priorityBase", "criticalAssetName")) {
            assertThat(countOccurrences(queueBody, "\"" + key + "\"")).as("키 %s", key).isEqualTo(rows);
        }
        // 띠 축 우선순위도 올린 값으로 거른다
        assertThat(ids(getJson(analyst, "/api/incidents/queue?period=all&size=100&priority=high"))).containsExactly(A);
        assertThat(ids(getJson(analyst, "/api/incidents/queue?period=all&size=100&priority=low"))).isEmpty();

        // 이웃: 목록과 같은 순서(B는 2번째, 앞은 A)
        JsonNode neighbors = getJson(analyst, "/api/incidents/queue/neighbors?period=all&jobId=" + SCREEN_JOB + "&queueRank=2");
        assertThat(neighbors.path("position").asInt()).isEqualTo(2);
        assertThat(neighbors.path("prev").path("queueRank").asInt()).isEqualTo(1);
        assertThat(neighbors.path("next").path("queueRank").asInt()).isEqualTo(3);

        // 상세 queueMeta
        String detailBody = getBody(analyst, "/api/incidents/" + SCREEN_JOB + "/rank/1");
        bodies.add(detailBody);
        JsonNode meta = objectMapper.readTree(detailBody).path("queueMeta");
        assertRow(meta, "high", "medium", true, CRITICAL_NAME);

        // 같은 호스트 인시던트(B에서 본 A·E)
        String relatedBody = getBody(analyst, "/api/incidents/" + SCREEN_JOB + "/rank/2/related-host-incidents");
        bodies.add(relatedBody);
        JsonNode related = objectMapper.readTree(relatedBody);
        JsonNode relA = relatedItem(related, 1);
        assertRow(relA, "high", "medium", true, CRITICAL_NAME);
        assertRow(relatedItem(related, 5), null, null, true, CRITICAL_NAME);

        // 호스트 위험도: 중요 자산 호스트는 high 1(A)·medium 1(B), 다른 호스트는 표지 없음
        String hostsBody = getBody(analyst, "/api/hosts?period=all");
        bodies.add(hostsBody);
        JsonNode hosts = objectMapper.readTree(hostsBody);
        JsonNode critical = hostRow(hosts, CRITICAL_HOST);
        assertThat(critical.path("high").asLong()).isEqualTo(1L);
        assertThat(critical.path("medium").asLong()).isEqualTo(1L);
        assertThat(critical.path("low").asLong()).isZero();
        assertThat(critical.path("assetCritical").asBoolean()).isTrue();
        assertThat(critical.path("criticalAssetName").asText()).isEqualTo(CRITICAL_NAME);
        assertThat(critical.has("priorityBase")).as("호스트 줄에는 priorityBase가 없다").isFalse();
        JsonNode other = hostRow(hosts, "10.52.7.8");
        assertThat(other.path("assetCritical").asBoolean()).isFalse();
        assertThat(other.has("criticalAssetName") && other.get("criticalAssetName").isNull()).isTrue();
        // 위험도 정렬에 중요 자산 키가 없다: high 수가 같은 줄의 순서는 바뀌지 않는다(여기서는 high 1인 줄이 맨 위)
        assertThat(hosts.get("items").get(0).path("hostIp").asText()).isEqualTo(CRITICAL_HOST);

        // 현황판: 캡처 줄의 High 수와 위험 호스트(출발지: A)
        String overviewBody = getBody(analyst, "/api/dashboard/overview?period=all");
        bodies.add(overviewBody);
        JsonNode overview = objectMapper.readTree(overviewBody);
        JsonNode capture = null;
        for (JsonNode c : overview.path("captures")) {
            if (SCREEN.equals(c.path("captureId").asText())) capture = c;
        }
        assertThat(capture).isNotNull();
        assertThat(capture.path("high").asLong()).isEqualTo(1L);
        JsonNode topOriginator = null;
        for (JsonNode h : overview.path("topHosts").path("originator")) {
            if (CRITICAL_HOST.equals(h.path("hostIp").asText())) topOriginator = h;
        }
        assertThat(topOriginator).isNotNull();
        assertThat(topOriginator.path("high").asLong()).isEqualTo(1L);
        long trendHigh = 0;
        for (JsonNode bucket : overview.path("trend").path("buckets")) trendHigh += bucket.path("high").asLong();
        assertThat(trendHigh).isEqualTo(1L);

        // 운영 현황: 착수 지연 1(A, High 목표 30분)
        String opsBody = getBody(analyst, "/api/operations");
        bodies.add(opsBody);
        assertThat(objectMapper.readTree(opsBody).path("workload").path("ackOverdue").asLong()).isEqualTo(1L);

        // 자산 설명은 어떤 인시던트 응답에도 없다
        for (String body : bodies) {
            assertThat(body).doesNotContain(CRITICAL_DESCRIPTION);
        }
    }

    /* ───────────── 조회자 ───────────── */

    @Test
    void viewerGetsTheFlagAndBaseButNeverTheNameOrDescription() throws Exception {
        register(Map.of(CRITICAL_HOST, CRITICAL_NAME));
        MockHttpSession viewer = login(UserRole.VIEWER, SCREEN);
        MockHttpSession analyst = login(UserRole.ANALYST, SCREEN);
        List<String> bodies = new ArrayList<>();

        String queueBody = getBody(viewer, "/api/incidents/queue?period=all&size=100");
        bodies.add(queueBody);
        JsonNode queue = objectMapper.readTree(queueBody);
        assertThat(queue.path("maskedView").asBoolean()).isTrue();
        assertThat(queue.get("items")).hasSize(5);
        // 조회자의 incidentId는 가려져 있어 순서(A, B, C, E, D)로 본다
        JsonNode[] rows = new JsonNode[5];
        for (int i = 0; i < 5; i++) rows[i] = queue.get("items").get(i);
        assertRow(rows[0], "high", "medium", true, null);
        assertRow(rows[1], "medium", "low", true, null);
        assertRow(rows[2], "medium", "medium", false, null);
        assertRow(rows[3], null, null, true, null);
        assertRow(rows[4], null, null, false, null);
        for (String key : List.of("assetCritical", "priorityBase", "criticalAssetName")) {
            assertThat(countOccurrences(queueBody, "\"" + key + "\"")).as("키 %s", key).isEqualTo(5);
        }

        String detailBody = getBody(viewer, "/api/incidents/" + SCREEN_JOB + "/rank/1");
        bodies.add(detailBody);
        assertRow(objectMapper.readTree(detailBody).path("queueMeta"), "high", "medium", true, null);

        String relatedBody = getBody(viewer, "/api/incidents/" + SCREEN_JOB + "/rank/2/related-host-incidents");
        bodies.add(relatedBody);
        JsonNode related = objectMapper.readTree(relatedBody);
        assertThat(related.path("maskedView").asBoolean()).isTrue();
        assertRow(relatedItem(related, 1), "high", "medium", true, null);
        for (JsonNode it : related.path("items")) {
            assertThat(it.has("criticalAssetName") && it.get("criticalAssetName").isNull()).isTrue();
        }

        // 호스트 위험도: 조회자는 대역 한 줄(10.52.*.*). 그 안에 중요 자산이 있으면 표지가 참이고 이름은 없다
        String hostsBody = getBody(viewer, "/api/hosts?period=all");
        bodies.add(hostsBody);
        JsonNode hosts = objectMapper.readTree(hostsBody);
        assertThat(hosts.get("items")).hasSize(1);
        JsonNode band = hosts.get("items").get(0);
        assertThat(band.path("hostIp").asText()).isEqualTo("10.52.*.*");
        assertThat(band.path("assetCritical").asBoolean()).isTrue();
        assertThat(band.has("criticalAssetName") && band.get("criticalAssetName").isNull()).isTrue();

        for (String body : bodies) {
            assertThat(body).doesNotContain(CRITICAL_NAME).doesNotContain(CRITICAL_DESCRIPTION).doesNotContain(CRITICAL_HOST);
        }

        // 분석가는 같은 화면에서 이름을 받는다(설명은 받지 않는다)
        String analystQueue = getBody(analyst, "/api/incidents/queue?period=all&size=100");
        assertThat(analystQueue).contains(CRITICAL_NAME).doesNotContain(CRITICAL_DESCRIPTION);
        String analystHosts = getBody(analyst, "/api/hosts?period=all");
        assertThat(analystHosts).contains(CRITICAL_NAME).doesNotContain(CRITICAL_DESCRIPTION);
    }

    /* ───────────── 도우미 ───────────── */

    private static void assertRow(JsonNode n, String priority, String base, boolean critical, String name) {
        assertThat(nullableText(n, "priority")).as("priority %s", n).isEqualTo(priority);
        assertThat(n.has("priorityBase")).as("priorityBase 키 %s", n).isTrue();
        assertThat(nullableText(n, "priorityBase")).as("priorityBase %s", n).isEqualTo(base);
        assertThat(n.path("assetCritical").isBoolean()).as("assetCritical 형 %s", n).isTrue();
        assertThat(n.path("assetCritical").asBoolean()).as("assetCritical %s", n).isEqualTo(critical);
        assertThat(n.has("criticalAssetName")).as("criticalAssetName 키 %s", n).isTrue();
        assertThat(nullableText(n, "criticalAssetName")).as("criticalAssetName %s", n).isEqualTo(name);
    }

    static String nullableText(JsonNode n, String key) {
        JsonNode v = n.get(key);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static Instant instant(JsonNode v) {
        return v == null || v.isNull() || v.isMissingNode() ? null : OffsetDateTime.parse(v.asText()).toInstant();
    }

    private static List<String> keys(List<JsonNode> rows) {
        return rows.stream().map(r -> r.path("captureId").asText() + "#" + r.path("queueRank").asInt()).toList();
    }

    private static List<String> ids(JsonNode page) {
        List<String> out = new ArrayList<>();
        page.path("items").forEach(it -> out.add(it.path("incidentId").asText()));
        return out;
    }

    private static JsonNode item(JsonNode page, String incidentId) {
        for (JsonNode it : page.path("items")) {
            if (incidentId.equals(it.path("incidentId").asText())) return it;
        }
        throw new AssertionError("행 없음: " + incidentId);
    }

    private static JsonNode relatedItem(JsonNode related, int queueRank) {
        for (JsonNode it : related.path("items")) {
            if (it.path("queueRank").asInt() == queueRank) return it;
        }
        throw new AssertionError("같은 호스트 행 없음: " + queueRank);
    }

    private static JsonNode hostRow(JsonNode hosts, String hostIp) {
        for (JsonNode it : hosts.path("items")) {
            if (hostIp.equals(it.path("hostIp").asText())) return it;
        }
        throw new AssertionError("호스트 줄 없음: " + hostIp);
    }

    private static int countOccurrences(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length())) n++;
        return n;
    }

    /** period 등 조건 그대로 100건씩 모든 쪽을 읽어 잇는다 */
    private List<JsonNode> allItems(MockHttpSession s, String query) throws Exception {
        List<JsonNode> out = new ArrayList<>();
        int pageCount = 1;
        for (int p = 1; p <= pageCount; p++) {
            JsonNode page = getJson(s, "/api/incidents/queue?" + query + "&size=100&page=" + p);
            pageCount = page.get("pageCount").asInt();
            page.get("items").forEach(out::add);
        }
        Set<String> unique = new LinkedHashSet<>(keys(out));
        assertThat(unique).hasSize(out.size());
        return out;
    }

    private void register(Map<String, String> assets) {
        JdbcTemplate app = app();
        app.update("DELETE FROM critical_assets");
        for (Map.Entry<String, String> e : assets.entrySet()) {
            app.update("INSERT INTO critical_assets (host_ip, name, description, created_by, created_at, updated_by, updated_at) "
                            + "VALUES (?, ?, ?, 't52', TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z', 't52', "
                            + "TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z')",
                    e.getKey(), e.getValue(), CRITICAL_DESCRIPTION);
        }
    }

    private JdbcTemplate zeekad() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    private JdbcTemplate app() {
        return new JdbcTemplate(appDataSource);
    }

    /**
     * 화면 대조 자료(실습망 캡처 lab-t52s, 탐지 = 기준 시각 1시간 전).
     * A: 10.52.7.7 출발지, 교차 탐지 있음(medium) / B: 10.52.7.7 목적지, 교차 탐지 없음(low)
     * C: 10.52.7.8 교차 탐지 있음(medium) / D: 10.52.8.1 종결 / E: 10.52.7.7 종결
     */
    static void insertScreenRows(JdbcTemplate jdbc) {
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20 22:50:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 23:00:00Z', NULL, 5)", SCREEN_JOB, SCREEN);
        screenRow(jdbc, 1, A, CRITICAL_HOST, "originator", true, "2026-11-20 22:00:00Z");
        screenRow(jdbc, 2, B, CRITICAL_HOST, "responder", false, "2026-11-20 22:10:00Z");
        screenRow(jdbc, 3, C, "10.52.7.8", "originator", true, "2026-11-20 22:20:00Z");
        screenRow(jdbc, 4, D, "10.52.8.1", "originator", false, "2026-11-20 22:30:00Z");
        screenRow(jdbc, 5, E, CRITICAL_HOST, "originator", false, "2026-11-20 22:40:00Z");
        for (String id : new String[]{D, E}) {
            jdbc.update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                    + "VALUES (?, ?, 'closed', 'benign', TIMESTAMP WITH TIME ZONE '2026-11-20 23:10:00Z', 't52')", SCREEN_JOB, id);
        }
    }

    private static void screenRow(JdbcTemplate jdbc, int rank, String id, String host, String role, boolean also, String start) {
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-20 22:55:00Z', 'hbos', "
                        + (also ? "ARRAY['autoencoder']" : "NULL") + ", ?, NULL)",
                SCREEN_JOB, SCREEN, rank, id, host, role, start, 10L * rank);
    }

    /** host_ip가 NULL인 행: 시험 DB의 열 제약을 풀고(이 시험의 전용 DB) 넣는다. PostgreSQL 뷰의 host_ip는 NULL을 받는 TEXT다 */
    private static void insertNullHostRow(JdbcTemplate jdbc) {
        jdbc.execute("ALTER TABLE dashboard.raw_incident_queue ALTER COLUMN host_ip SET NULL");
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-20 05:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 06:00:00Z', NULL, 1)", NULL_HOST_JOB, NULL_HOST_CAPTURE);
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                        + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                        + "VALUES (?, ?, 'zeekad-fusion/1', 1, ?, NULL, 'originator', TIMESTAMP WITH TIME ZONE '2026-11-20 04:00:00Z', "
                        + "TIMESTAMP WITH TIME ZONE '2026-11-20 04:05:00Z', 'hbos', NULL, 3, NULL)",
                NULL_HOST_JOB, NULL_HOST_CAPTURE, NULL_HOST_ID);
    }

    static void deleteOwnRows(JdbcTemplate jdbc) {
        for (String table : new String[]{"raw_slack_deliveries", "raw_analyst_review_queue", "raw_send_decisions",
                "raw_incident_reports", "raw_incident_status", "raw_incident_queue", "raw_scoring_jobs"}) {
            jdbc.update("DELETE FROM dashboard." + table + " WHERE job_id IN (?, ?)", SCREEN_JOB, NULL_HOST_JOB);
        }
    }

    private MockHttpSession login(UserRole role, String patterns) throws Exception {
        String username = "t52a_u" + (++seq) + "_" + System.nanoTime() % 100000;
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
        MvcResult r = mockMvc.perform(get(URI.create(url)).session(session)).andExpect(status().isOk()).andReturn();
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        return objectMapper.readTree(getBody(session, url));
    }
}
