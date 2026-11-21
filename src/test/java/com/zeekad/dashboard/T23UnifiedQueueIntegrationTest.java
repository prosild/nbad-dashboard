package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.QueueNeighborsResponse;
import com.zeekad.dashboard.dto.QueueNewCountResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.dto.UnifiedQueueRow;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.CaptureQueueStat;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.QueueQueryException;
import com.zeekad.dashboard.service.TimeContextService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T23 통합 인시던트 큐: 우선순위(옛 computePriority와 같음), 탐지 시각, 기간 경계, 수집원, 진행 중, 정렬·쪽 나눔,
 * 허용 캡처·IDOR, VIEWER 자산 검색(가려진 값에만), 자산 검색 경로와 SQL 경로 대조, 상한, 기준 시각, new-count, neighbors.
 * 시험용 행은 시험마다 넣고 지운다(공유 H2).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T23UnifiedQueueIntegrationTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-11-21T00:00:00Z");
    private static final String PRIO_CAPTURE = "t23p-cap";
    private static final long PRIO_JOB = 9001L;
    private static final String BIG_CAPTURE = "t23big-cap";
    private static final long BIG_JOB = 9002L;
    private static final Pattern FULL_IPV4 = Pattern.compile("(?<![0-9.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![0-9.])");

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
    @Autowired private ZeekadReadMapper zeekadReadMapper;
    @Autowired private IncidentQueueService queueService;
    @Autowired private TimeContextService timeContextService;
    @Autowired private MutableTestClock clock;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;

    @AfterEach
    void cleanup() {
        clock.set(FIXED_NOW);
        deleteSyntheticRows();
    }

    /* ───────────── 우선순위·정렬 조합 표 ───────────── */

    /** 옛 화면 규칙(triage.ts computePriority)을 그대로 옮긴 기준 함수 */
    private static String refPriority(UnifiedQueueRecord r) {
        String s = r.getZeekadStatus() == null ? "" : r.getZeekadStatus().trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) s = "open";
        if ("closed".equals(s)) return null;
        if (r.isZeekadWouldSend() || r.isZeekadReviewPending()) return "high";
        List<String> also = r.getZeekadAlsoFlaggedBy() == null ? List.of() : r.getZeekadAlsoFlaggedBy();
        if (also.size() >= 1 || r.isHasReport()) return "medium";
        return "low";
    }

    private static int refStatusOrder(UnifiedQueueRecord r) {
        String s = r.getZeekadStatus() == null ? "" : r.getZeekadStatus().trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty() || "open".equals(s)) return 0;
        if ("investigating".equals(s)) return 1;
        if ("closed".equals(s)) return 3;
        return 2;
    }

    private static Comparable<?> refSortValue(UnifiedQueueRecord r, String key) {
        return switch (key) {
            case "priority" -> {
                String p = refPriority(r);
                yield p == null ? null : List.of("high", "medium", "low").indexOf(p);
            }
            case "detected" -> r.getDetectedAt() == null ? null : r.getDetectedAt().toInstant();
            case "start" -> r.getEventStart() == null ? null : r.getEventStart().toInstant();
            case "connections" -> r.getConnectionCount();
            case "status" -> refStatusOrder(r);
            default -> null;
        };
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Comparator<UnifiedQueueRecord> refComparator(String key, boolean asc) {
        Comparator<UnifiedQueueRecord> primary = (a, b) -> {
            Comparable va = refSortValue(a, key);
            Comparable vb = refSortValue(b, key);
            if (va == null && vb == null) return 0;
            if (va == null) return 1;   // 값 없음은 방향과 상관없이 맨 뒤
            if (vb == null) return -1;
            int c = va.compareTo(vb);
            return asc ? c : -c;
        };
        Comparator<UnifiedQueueRecord> detectedDesc = (a, b) -> {
            Instant da = a.getDetectedAt() == null ? null : a.getDetectedAt().toInstant();
            Instant db = b.getDetectedAt() == null ? null : b.getDetectedAt().toInstant();
            if (da == null && db == null) return 0;
            if (da == null) return 1;
            if (db == null) return -1;
            return db.compareTo(da);
        };
        Comparator<UnifiedQueueRecord> c = primary;
        if (!"detected".equals(key)) c = c.thenComparing(detectedDesc);
        return c.thenComparing(UnifiedQueueRecord::getCaptureId).thenComparing(UnifiedQueueRecord::getQueueRank);
    }

    @Test
    void serverPriorityMatchesOldComputePriorityForEveryCombination() {
        int inserted = insertPriorityCombinations();
        UnifiedQueueCriteria c = criteria(List.of(PRIO_CAPTURE));
        List<UnifiedQueueRecord> rows = zeekadReadMapper.findUnifiedQueue(c);
        assertThat(rows).hasSize(inserted);
        Map<String, Integer> seen = new HashMap<>();
        for (UnifiedQueueRecord r : rows) {
            assertThat(r.getPriority()).as("우선순위: %s status=[%s] send=%s pending=%s also=%s report=%s",
                    r.getIncidentId(), r.getZeekadStatus(), r.isZeekadWouldSend(), r.isZeekadReviewPending(),
                    r.getZeekadAlsoFlaggedBy(), r.isHasReport()).isEqualTo(refPriority(r));
            seen.merge(String.valueOf(r.getPriority()), 1, Integer::sum);
        }
        // 조합 표가 네 값을 모두 덮는다
        assertThat(seen.keySet()).contains("high", "medium", "low", "null");
        // 교차 탐지 NULL·빈 배열은 0개로 본다(보고서·발송·대기 없는 행은 low)
        assertThat(rows).filteredOn(r -> r.getIncidentId().contains("|also-null|") && r.getIncidentId().contains("|rep-none|")
                        && !refStatusClosed(r))
                .isNotEmpty().allSatisfy(r -> assertThat(r.getPriority()).isEqualTo("low"));
        assertThat(rows).filteredOn(r -> r.getIncidentId().contains("|also-empty|") && r.getIncidentId().contains("|rep-none|")
                        && !refStatusClosed(r))
                .isNotEmpty().allSatisfy(r -> assertThat(r.getPriority()).isEqualTo("low"));
    }

    private static boolean refStatusClosed(UnifiedQueueRecord r) {
        return r.getZeekadStatus() != null && "closed".equals(r.getZeekadStatus().trim().toLowerCase(Locale.ROOT));
    }

    @Test
    void sqlSortMatchesReferenceOrderForEveryKeyAndDirectionAndPagesConcatenate() {
        insertPriorityCombinations();
        for (String key : List.of("priority", "detected", "start", "connections", "status")) {
            for (boolean asc : List.of(true, false)) {
                UnifiedQueueCriteria c = criteria(List.of(PRIO_CAPTURE));
                c.setSortKey(key);
                c.setSortAsc(asc);
                List<UnifiedQueueRecord> all = zeekadReadMapper.findUnifiedQueue(c);
                List<UnifiedQueueRecord> expected = new ArrayList<>(all);
                expected.sort(refComparator(key, asc));
                assertThat(keys(all)).as("정렬 %s %s", key, asc).containsExactlyElementsOf(keys(expected));

                // 쪽 이음: 25건씩 모든 쪽을 이으면 전체 정렬 결과와 같고 겹침·빠짐이 없다
                List<String> joined = new ArrayList<>();
                for (int offset = 0; offset < all.size(); offset += 25) {
                    UnifiedQueueCriteria paged = c.copy();
                    paged.setLimit(25);
                    paged.setOffset(offset);
                    joined.addAll(keys(zeekadReadMapper.findUnifiedQueue(paged)));
                }
                assertThat(joined).as("쪽 이음 %s %s", key, asc).containsExactlyElementsOf(keys(all));
                assertThat(joined).doesNotHaveDuplicates();
            }
        }
        // 우선순위 정렬은 내림차순에서도 종결(우선순위 없음)이 맨 뒤
        UnifiedQueueCriteria desc = criteria(List.of(PRIO_CAPTURE));
        desc.setSortKey("priority");
        desc.setSortAsc(false);
        List<UnifiedQueueRecord> rows = zeekadReadMapper.findUnifiedQueue(desc);
        int firstNull = -1;
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).getPriority() == null) {
                if (firstNull < 0) firstNull = i;
            } else {
                assertThat(firstNull).as("값 없음 뒤에 값이 오면 안 된다").isLessThan(0);
            }
        }
        assertThat(firstNull).isGreaterThan(0);
    }

    @Test
    void apiPagesConcatenateToFullSortedResultForAnalyst() throws Exception {
        insertPriorityCombinations();
        MockHttpSession s = login("t23_pager", UserRole.ANALYST, "t23p-*");
        for (String sort : List.of("priority", "detected", "start", "connections", "status")) {
            JsonNode first = getJson(s, "/api/incidents/queue?period=all&size=25&sort=" + sort);
            long total = first.get("total").asLong();
            int pageCount = first.get("pageCount").asInt();
            assertThat(pageCount).isGreaterThan(1);
            List<String> joined = new ArrayList<>();
            for (int p = 1; p <= pageCount; p++) {
                JsonNode page = getJson(s, "/api/incidents/queue?period=all&size=25&sort=" + sort + "&page=" + p);
                assertThat(page.get("page").asInt()).isEqualTo(p);
                for (JsonNode it : page.get("items")) joined.add(it.get("jobId").asLong() + "/" + it.get("queueRank").asInt());
            }
            JsonNode big = getJson(s, "/api/incidents/queue?period=all&size=100&sort=" + sort);
            List<String> full = new ArrayList<>();
            int bigPages = big.get("pageCount").asInt();
            for (int p = 1; p <= bigPages; p++) {
                for (JsonNode it : getJson(s, "/api/incidents/queue?period=all&size=100&sort=" + sort + "&page=" + p).get("items")) {
                    full.add(it.get("jobId").asLong() + "/" + it.get("queueRank").asInt());
                }
            }
            assertThat(joined).hasSize((int) total).doesNotHaveDuplicates().containsExactlyElementsOf(full);
        }
    }

    /* ───────────── 탐지 시각·기간·수집원·진행 중·기준 시각 ───────────── */

    @Test
    void detectedAtIsFirstSucceededJobFinishTimeAcrossJobs() {
        UnifiedQueueCriteria c = criteria(List.of("lab-20261118", "lab-fusion-v2"));
        Map<String, UnifiedQueueRecord> byId = new HashMap<>();
        for (UnifiedQueueRecord r : zeekadReadMapper.findUnifiedQueue(c)) byId.put(r.getIncidentId(), r);
        // 작업 501(00:06)과 502(00:11)에 걸친 사건은 첫 작업 완료 시각, 502에만 있는 사건은 502 완료 시각
        assertThat(byId.get("lab-20261118|10.20.0.15|originator|1763424000").getDetectedAt().toInstant())
                .isEqualTo(Instant.parse("2026-11-18T00:06:00Z"));
        assertThat(byId.get("lab-20261118|10.20.0.15|originator|1763424000").getJobId()).isEqualTo(502L);
        assertThat(byId.get("lab-20261118|10.20.0.25|responder|1763424300").getDetectedAt().toInstant())
                .isEqualTo(Instant.parse("2026-11-18T00:11:00Z"));
        assertThat(byId.get("lab-fusion-v2|10.40.0.10|originator|1763514000").getDetectedAt().toInstant())
                .isEqualTo(Instant.parse("2026-11-19T01:02:00Z"));
        assertThat(byId.get("lab-fusion-v2|10.40.0.20|responder|1763514300").getDetectedAt().toInstant())
                .isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
    }

    @Test
    void periodBoundaryExcludesStartAndIncludesAnchor() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "lab-fusion-v2");
        // 10.40.0.20·.30 탐지 = 2026-11-19 02:05. 기준 시각이 정확히 24시간 뒤면 시작(불포함)이라 빠진다.
        clock.set(Instant.parse("2026-11-20T02:05:00Z"));
        assertThat(queueService.loadQueue(analyst, params("24h"), "127.0.0.1").total()).isZero();
        // 1초 앞이면 들어온다(시작 불포함 경계 안쪽)
        clock.set(Instant.parse("2026-11-20T02:04:59Z"));
        assertThat(ids(queueService.loadQueue(analyst, params("24h"), "127.0.0.1")))
                .containsExactlyInAnyOrder("lab-fusion-v2|10.40.0.20|responder|1763514300",
                        "lab-fusion-v2|10.40.0.30|originator|1763514600");
        // 기준 시각과 같은 탐지 시각은 들어온다(끝 포함)
        clock.set(Instant.parse("2026-11-19T02:05:00Z"));
        UnifiedQueueResponse atAnchor = queueService.loadQueue(analyst, params("1h"), "127.0.0.1");
        assertThat(atAnchor.total()).isEqualTo(2);
        assertThat(atAnchor.anchor().toInstant()).isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        // 1시간 뒤 정각이면 빠지고, 기간 밖 가장 최근 탐지 시각을 알려 준다
        clock.set(Instant.parse("2026-11-19T03:05:00Z"));
        UnifiedQueueResponse empty = queueService.loadQueue(analyst, params("1h"), "127.0.0.1");
        assertThat(empty.total()).isZero();
        assertThat(empty.newestOutsidePeriod().toInstant()).isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        // 전체는 시각 조건이 없다
        assertThat(queueService.loadQueue(analyst, params("all"), "127.0.0.1").total()).isEqualTo(3);
        assertThat(queueService.loadQueue(analyst, params("all"), "127.0.0.1").newestOutsidePeriod()).isNull();
    }

    @Test
    void sourceClassificationUsesLivePatternsSetting() {
        assertThat(timeContextService.sourceType("lab-20261118")).isEqualTo("live");
        assertThat(timeContextService.sourceType("LAB-x")).isEqualTo("live");
        assertThat(timeContextService.sourceType("cic17-wed")).isEqualTo("imported");
        assertThat(timeContextService.sourceType("syn1-tue")).isEqualTo("imported");

        DashboardProperties props = new DashboardProperties();
        props.getCaptureSources().setLivePatterns("sensor-*, cic17-wed");
        TimeContextService custom = new TimeContextService(props, zeekadReadMapper, clock);
        assertThat(custom.sourceType("sensor-a")).isEqualTo("live");
        assertThat(custom.sourceType("cic17-wed")).isEqualTo("live");
        assertThat(custom.sourceType("lab-20261118")).isEqualTo("imported");

        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "*");
        UnifiedQueueResponse live = queueService.loadQueue(analyst, withSource("all", "live"), "127.0.0.1");
        assertThat(live.items()).isNotEmpty().allSatisfy(r -> {
            assertThat(r.getSourceType()).isEqualTo("live");
            assertThat(r.getItem().getCaptureId()).startsWith("lab-");
        });
        UnifiedQueueResponse imported = queueService.loadQueue(analyst, withSource("all", "imported"), "127.0.0.1");
        assertThat(imported.items()).isNotEmpty().allSatisfy(r -> assertThat(r.getSourceType()).isEqualTo("imported"));
        assertThat(live.total() + imported.total())
                .isEqualTo(queueService.loadQueue(analyst, params("all"), "127.0.0.1").total());
        assertThat(live.sources()).extracting(UnifiedQueueResponse.Source::captureId).contains("lab-20261118", "cic17-wed");
    }

    @Test
    void ongoingRequiresAllFourConditions() {
        CaptureQueueStat stat = new CaptureQueueStat();
        stat.setCaptureId("lab-x");
        stat.setMaxEventEnd(OffsetDateTime.parse("2026-11-21T00:00:00Z"));
        OffsetDateTime anchor = OffsetDateTime.parse("2026-11-21T00:15:00Z");

        UnifiedQueueRecord ok = record("lab-x", "open", "2026-11-21T00:00:00Z");
        assertThat(queueService.isOngoing(ok, stat, anchor)).isTrue();
        // 경계 포함: 최대 event_end = 기준 시각 − 15분 정각
        assertThat(queueService.isOngoing(ok, stat, OffsetDateTime.parse("2026-11-21T00:15:00Z"))).isTrue();
        // 1) 수집원이 live가 아니면 거짓
        UnifiedQueueRecord imported = record("cic17-x", "open", "2026-11-21T00:00:00Z");
        assertThat(queueService.isOngoing(imported, stat, anchor)).isFalse();
        // 2) 종결이면 거짓(대소문자·공백 무시)
        assertThat(queueService.isOngoing(record("lab-x", " Closed ", "2026-11-21T00:00:00Z"), stat, anchor)).isFalse();
        // 3) 인시던트 event_end가 캡처 최신 최대 event_end가 아니면 거짓
        assertThat(queueService.isOngoing(record("lab-x", "open", "2026-11-20T23:55:00Z"), stat, anchor)).isFalse();
        // 4) 최대 event_end가 기준 시각 −15분보다 이르면 거짓
        assertThat(queueService.isOngoing(ok, stat, OffsetDateTime.parse("2026-11-21T00:15:01Z"))).isFalse();
        // 같은 순간이면 시간대 표기가 달라도 같다
        assertThat(queueService.isOngoing(record("lab-x", "investigating", "2026-11-21T09:00:00+09:00"), stat, anchor)).isTrue();
    }

    @Test
    void ongoingFlagOnLiveSeedRowsFollowsAnchor() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "lab-fusion-v2");
        // 최신 작업 602의 최대 event_end = 01:50. 10.40.0.20·.30이 그 값, 10.40.0.10은 01:45
        clock.set(Instant.parse("2026-11-19T02:05:00Z"));
        Map<String, Boolean> ongoing = new HashMap<>();
        for (UnifiedQueueRow r : queueService.loadQueue(analyst, params("all"), "127.0.0.1").items()) {
            ongoing.put(r.getItem().getIncidentId(), r.isOngoing());
        }
        assertThat(ongoing).containsEntry("lab-fusion-v2|10.40.0.20|responder|1763514300", true)
                .containsEntry("lab-fusion-v2|10.40.0.30|originator|1763514600", true)
                .containsEntry("lab-fusion-v2|10.40.0.10|originator|1763514000", false);
        clock.set(Instant.parse("2026-11-19T02:05:01Z"));
        assertThat(queueService.loadQueue(analyst, params("all"), "127.0.0.1").items())
                .allSatisfy(r -> assertThat(r.isOngoing()).isFalse());
    }

    @Test
    void latestDataAnchorUsesOnlyAllowedCapturesAndInvalidSettingsFailStartup() {
        DashboardProperties props = new DashboardProperties();
        props.setTimeAnchor("latest-data");
        TimeContextService snapshot = new TimeContextService(props, zeekadReadMapper, clock);
        assertThat(snapshot.isSnapshot()).isTrue();
        // cic17-wed 성공 작업 최대 완료 = 2026-11-16 03:08. 더 늦은 lab-fusion-v2(11-19)가 숨겨져 있어도 섞이지 않는다.
        assertThat(snapshot.anchorFor(List.of("cic17-wed")).toInstant()).isEqualTo(Instant.parse("2026-11-16T03:08:00Z"));
        assertThat(snapshot.anchorFor(List.of("cic17-wed", "lab-fusion-v2")).toInstant())
                .isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        // 허용 캡처가 없으면 현재 시각
        assertThat(snapshot.anchorFor(List.of()).toInstant()).isEqualTo(FIXED_NOW);
        // now 모드는 현재 시각
        assertThat(timeContextService.isSnapshot()).isFalse();
        assertThat(timeContextService.anchorFor(List.of("cic17-wed")).toInstant()).isEqualTo(FIXED_NOW);

        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withUserConfiguration(TimeContextOnlyConfig.class);
        runner.withPropertyValues("dashboard.time-anchor=bogus")
                .run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.capture-sources.live-patterns=lab-*x")
                .run(ctx -> assertThat(ctx).hasFailed());
        runner.withPropertyValues("dashboard.time-anchor=latest-data")
                .run(ctx -> assertThat(ctx).hasNotFailed());
        runner.run(ctx -> assertThat(ctx.getBean(TimeContextService.class).mode()).isEqualTo("now"));
    }

    @EnableConfigurationProperties(DashboardProperties.class)
    static class TimeContextOnlyConfig {
        @Bean
        ZeekadReadMapper zeekadReadMapper() {
            return Mockito.mock(ZeekadReadMapper.class);
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        TimeContextService timeContextService(DashboardProperties p, ZeekadReadMapper m, Clock c) {
            return new TimeContextService(p, m, c);
        }
    }

    /* ───────────── 권한·마스킹·자산 검색 ───────────── */

    @Test
    void queueShowsOnlyAllowedCapturesAndDeniedCaptureIs403WithAudit() throws Exception {
        MockHttpSession viewer = login("t23_viewer_scope", UserRole.VIEWER, "cic17-*");
        JsonNode body = getJson(viewer, "/api/incidents/queue?period=all&size=100");
        assertThat(body.get("total").asLong()).isEqualTo(3);
        for (JsonNode it : body.get("items")) assertThat(it.get("captureId").asText()).startsWith("cic17-");
        assertThat(body.get("sources")).hasSize(1);
        assertThat(body.get("sources").get(0).get("captureId").asText()).isEqualTo("cic17-wed");
        assertThat(body.get("sources").get(0).get("sourceType").asText()).isEqualTo("imported");
        assertThat(body.get("sources").get(0).get("latestJobId").asLong()).isEqualTo(101L);
        assertThat(body.get("maskedView").asBoolean()).isTrue();
        assertThat(body.toString()).doesNotContain("syn1-", "lab-");

        mockMvc.perform(get("/api/incidents/queue").param("captureId", "syn1-tue").session(viewer))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/queue/new-count").param("captureId", "lab-20261118")
                        .param("since", "2000-01-01T00:00:00Z").session(viewer))
                .andExpect(status().isForbidden());
        // 숨긴 캡처의 작업(201 = syn1-tue)으로 neighbors를 부르면 403
        mockMvc.perform(get("/api/incidents/queue/neighbors").param("jobId", "201").param("queueRank", "1").session(viewer))
                .andExpect(status().isForbidden());
        assertThat(auditLogMapper.findFiltered(AuditActionType.ACCESS_DENIED_IDOR.name(), "t23_viewer_scope", 20))
                .hasSize(3);

        // 숨긴 캡처는 수·시각 어디에도 흔적이 없다(new-count는 허용 캡처만 센다)
        JsonNode nc = getJson(viewer, "/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z");
        assertThat(nc.get("count").asLong()).isEqualTo(3);
        assertThat(OffsetDateTime.parse(nc.get("latestDetectedAt").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-16T03:08:00Z"));
        JsonNode tc = getJson(viewer, "/api/time-context");
        assertThat(tc.get("anchorMode").asText()).isEqualTo("now");
        assertThat(tc.get("snapshot").asBoolean()).isFalse();
    }

    @Test
    void invalidParametersReturn400() throws Exception {
        MockHttpSession s = login("t23_bad", UserRole.ANALYST, "*");
        for (String q : List.of("period=2d", "source=cloud", "sort=rank", "dir=up", "priority=critical")) {
            mockMvc.perform(get("/api/incidents/queue?" + q).session(s))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        }
        mockMvc.perform(get("/api/incidents/queue/new-count?since=yesterday").session(s))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/incidents/queue")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/time-context")).andExpect(status().isUnauthorized());
    }

    @Test
    void viewerAssetSearchMatchesOnlyMaskedValuesAndResponseHasNoFullIpv4() throws Exception {
        MockHttpSession viewer = login("t23_viewer_asset", UserRole.VIEWER, "*");
        JsonNode all = getJson(viewer, "/api/incidents/queue?period=all&size=100");
        assertNoFullIpv4(all);

        // 가려지지 않은 IP 뒤 두 옥텟(192.168.10.50의 "10.50")으로는 찾지 못한다
        assertThat(getJson(viewer, "/api/incidents/queue?period=all&asset=10.50").get("total").asLong()).isZero();
        assertThat(getJson(viewer, "/api/incidents/queue?period=all&asset=.50").get("total").asLong()).isZero();
        assertThat(getJson(viewer, "/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z&asset=10.50")
                .get("count").asLong()).isZero();
        // 가려진 앞부분·호스트 이름으로는 찾아진다
        JsonNode masked = getJson(viewer, "/api/incidents/queue?period=all&size=100&asset=192.168");
        assertThat(masked.get("total").asLong()).isGreaterThanOrEqualTo(1);
        List<String> hosts = new ArrayList<>();
        for (JsonNode it : masked.get("items")) hosts.add(it.get("hostIp").asText());
        assertThat(hosts).contains("192.168.*.*").allSatisfy(h -> assertThat(h).startsWith("192.168."));
        assertNoFullIpv4(masked);
        assertThat(getJson(viewer, "/api/incidents/queue?period=all&asset=dc01.corp").get("total").asLong()).isEqualTo(1);

        MockHttpSession analyst = login("t23_analyst_asset", UserRole.ANALYST, "*");
        assertThat(getJson(analyst, "/api/incidents/queue?period=all&asset=10.50").get("total").asLong()).isEqualTo(1);
    }

    @Test
    void assetSearchPathMatchesSqlPathForSummaryAndOrder() {
        insertPriorityCombinations();
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "*");
        // "." 은 모든 행의 IP에 맞으므로 자산 검색 경로(Java)와 SQL 경로가 같은 집합을 본다
        for (String sort : List.of("priority", "detected", "start", "connections", "status")) {
            for (String dir : List.of("asc", "desc")) {
                for (String[] strip : List.of(new String[]{null, null, null}, new String[]{"medium", null, null},
                        new String[]{null, "true", null}, new String[]{null, null, "true"})) {
                    QueueParams sql = new QueueParams("all", null, null, strip[0], null, strip[1], strip[2],
                            null, null, null, null, null, sort, dir, "1", "100");
                    QueueParams java = new QueueParams("all", null, null, strip[0], null, strip[1], strip[2],
                            null, null, null, null, ".", sort, dir, "1", "100");
                    UnifiedQueueResponse a = queueService.loadQueue(analyst, sql, "127.0.0.1");
                    UnifiedQueueResponse b = queueService.loadQueue(analyst, java, "127.0.0.1");
                    assertThat(b.summary()).as("summary %s %s", sort, dir).isEqualTo(a.summary());
                    assertThat(b.total()).isEqualTo(a.total());
                    assertThat(b.latestDetectedAt()).isEqualTo(a.latestDetectedAt());
                    List<String> ka = new ArrayList<>();
                    List<String> kb = new ArrayList<>();
                    for (int p = 1; p <= a.pageCount(); p++) {
                        QueueParams pa = new QueueParams("all", null, null, strip[0], null, strip[1], strip[2],
                                null, null, null, null, null, sort, dir, String.valueOf(p), "100");
                        QueueParams pb = new QueueParams("all", null, null, strip[0], null, strip[1], strip[2],
                                null, null, null, null, ".", sort, dir, String.valueOf(p), "100");
                        queueService.loadQueue(analyst, pa, "127.0.0.1").items()
                                .forEach(r -> ka.add(r.getItem().getJobId() + "/" + r.getItem().getQueueRank()));
                        queueService.loadQueue(analyst, pb, "127.0.0.1").items()
                                .forEach(r -> kb.add(r.getItem().getJobId() + "/" + r.getItem().getQueueRank()));
                    }
                    assertThat(kb).as("순서 %s %s", sort, dir).containsExactlyElementsOf(ka);
                }
            }
        }
        // 띠를 눌러 걸러도 띠의 수(summary)는 무너지지 않는다
        UnifiedQueueResponse none = queueService.loadQueue(analyst, params("all"), "127.0.0.1");
        UnifiedQueueResponse high = queueService.loadQueue(analyst,
                new QueueParams("all", null, null, "high", null, null, null, null, null, null, null, null, null, null, null, null),
                "127.0.0.1");
        assertThat(high.summary()).isEqualTo(none.summary());
        assertThat(high.total()).isEqualTo(none.summary().high());
        assertThat(none.summary().total()).isEqualTo(none.total());
        assertThat(none.summary().byStatus().values().stream().mapToLong(Long::longValue).sum()).isEqualTo(none.total());
    }

    @Test
    void assetSearchOverCapIs400QueryTooBroad() throws Exception {
        JdbcTemplate jdbc = jdbc();
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-01-01 00:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-01-01 00:01:00Z', NULL, 5001)", BIG_JOB, BIG_CAPTURE);
        jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, zeekad_role, "
                + "event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                + "SELECT CAST(? AS BIGINT), CAST(? AS VARCHAR), 'zeekad-fusion/1', CAST(\"X\" AS INT), CONCAT(CAST(? AS VARCHAR), '|10.9.0.1|originator|', \"X\"), '10.9.0.1', 'originator', "
                + "TIMESTAMP WITH TIME ZONE '2026-01-01 00:00:00Z', TIMESTAMP WITH TIME ZONE '2026-01-01 00:05:00Z', 'hbos', NULL, 1, NULL "
                + "FROM SYSTEM_RANGE(1, 5001)", BIG_JOB, BIG_CAPTURE, BIG_CAPTURE);
        MockHttpSession s = login("t23_big", UserRole.ANALYST, "t23big-*");
        mockMvc.perform(get("/api/incidents/queue").param("period", "all").param("asset", "10.9").session(s))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("QUERY_TOO_BROAD"))
                .andExpect(jsonPath("$.message").value("기간이나 수집원을 좁혀 주세요"));
        // 자산 검색이 없으면 SQL 쪽 나눔이라 상한이 없다
        JsonNode ok = getJson(s, "/api/incidents/queue?period=all&size=100");
        assertThat(ok.get("total").asLong()).isEqualTo(5001);
        assertThat(ok.get("items")).hasSize(100);
        assertThatThrownBy(() -> queueService.loadQueue(principal(UserRole.ANALYST, "t23big-*"),
                new QueueParams("all", null, null, null, null, null, null, null, null, null, null, "10.9", null, null, null, null),
                "127.0.0.1")).isInstanceOf(QueueQueryException.class);
    }

    /* ───────────── new-count·neighbors·상세 메타데이터 ───────────── */

    @Test
    void newCountIsStrictlyAfterSinceWithoutPeriod() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "lab-fusion-v2");
        // 10.40.0.20·.30 탐지 = 02:05:00. 같은 시각을 since로 주면 0건(엄격 비교), 1초 앞이면 2건
        QueueNewCountResponse same = queueService.countNew(analyst, params("all"), "2026-11-19T02:05:00Z", "127.0.0.1");
        assertThat(same.count()).isZero();
        assertThat(same.latestDetectedAt()).isNull();
        QueueNewCountResponse before = queueService.countNew(analyst, params("all"), "2026-11-19T02:04:59Z", "127.0.0.1");
        assertThat(before.count()).isEqualTo(2);
        assertThat(before.latestDetectedAt().toInstant()).isEqualTo(Instant.parse("2026-11-19T02:05:00Z"));
        // 기간 조건은 쓰지 않는다(기준 시각이 한참 뒤여도 센다)
        clock.set(Instant.parse("2027-06-01T00:00:00Z"));
        assertThat(queueService.countNew(analyst, params("1h"), "2026-11-19T01:00:00Z", "127.0.0.1").count()).isEqualTo(3);
        // 거르기를 적용한다
        QueueParams responder = new QueueParams("all", null, null, null, null, null, null, null, "responder",
                null, null, null, null, null, null, null);
        assertThat(queueService.countNew(analyst, responder, "2026-11-19T01:00:00Z", "127.0.0.1").count()).isEqualTo(1);
        // 시간대 표기가 달라도 같은 순간이면 같다
        assertThat(queueService.countNew(analyst, params("all"), "2026-11-19T11:04:59+09:00", "127.0.0.1").count())
                .isEqualTo(2);
    }

    @Test
    void neighborsFollowServerOrderAndResolveStaleJobToLatestRow() {
        DashboardUserPrincipal analyst = principal(UserRole.ANALYST, "*");
        QueueParams byDetected = new QueueParams("all", null, null, null, null, null, null, null, null, null, null,
                null, "detected", "desc", null, null);
        List<UnifiedQueueRow> ordered = new ArrayList<>();
        UnifiedQueueResponse first = queueService.loadQueue(analyst, byDetected, "127.0.0.1");
        for (int p = 1; p <= first.pageCount(); p++) {
            ordered.addAll(queueService.loadQueue(analyst, new QueueParams("all", null, null, null, null, null, null,
                    null, null, null, null, null, "detected", "desc", String.valueOf(p), null), "127.0.0.1").items());
        }
        UnifiedQueueRow middle = ordered.get(1);
        QueueNeighborsResponse n = queueService.neighbors(analyst, middle.getItem().getJobId(),
                middle.getItem().getQueueRank(), byDetected, "127.0.0.1");
        assertThat(n.position()).isEqualTo(2);
        assertThat(n.total()).isEqualTo(ordered.size());
        assertThat(n.prev().jobId()).isEqualTo(ordered.get(0).getItem().getJobId());
        assertThat(n.prev().queueRank()).isEqualTo(ordered.get(0).getItem().getQueueRank());
        assertThat(n.next().jobId()).isEqualTo(ordered.get(2).getItem().getJobId());
        assertThat(n.current().jobId()).isEqualTo(middle.getItem().getJobId());

        // 낡은 작업(501, 1위 = lab-20261118|10.20.0.15)을 보고 있으면 current는 같은 incident_id의 최신 행(502, 2위)
        QueueNeighborsResponse stale = queueService.neighbors(analyst, 501L, 1, byDetected, "127.0.0.1");
        assertThat(stale.current().jobId()).isEqualTo(502L);
        assertThat(stale.current().queueRank()).isEqualTo(2);
        assertThat(stale.position()).isNotNull();

        // 거르기 결과에 없으면 위치 없음
        QueueParams closedOnly = new QueueParams("all", null, null, null, "closed", null, null, null, null, null, null,
                null, null, null, null, null);
        QueueNeighborsResponse missing = queueService.neighbors(analyst, 502L, 2, closedOnly, "127.0.0.1");
        assertThat(missing.position()).isNull();
        assertThat(missing.prev()).isNull();
        assertThat(missing.next()).isNull();
        assertThat(missing.current().jobId()).isEqualTo(502L);

        // 최신 큐에 없는 사건(작업 100은 실패 작업)은 current 없음
        DashboardUserPrincipal viewer = principal(UserRole.VIEWER, "cic17-*");
        assertThat(queueService.neighbors(viewer, 100L, 1, byDetected, "127.0.0.1").current()).isNull();
        // 허용 밖 작업은 403(AccessDeniedException)
        assertThatThrownBy(() -> queueService.neighbors(viewer, 201L, 1, byDetected, "127.0.0.1"))
                .isInstanceOf(AccessDeniedException.class);
        // VIEWER 이동 키의 호스트는 가려진 값
        QueueNeighborsResponse vn = queueService.neighbors(viewer, 101L, 2, byDetected, "127.0.0.1");
        for (QueueNeighborsResponse.Key k : new QueueNeighborsResponse.Key[]{vn.current(), vn.prev(), vn.next()}) {
            if (k != null) assertThat(k.hostIp()).endsWith(".*.*");
        }
    }

    @Test
    void detailIncludesQueueMetaForViewerWithoutLeakingIp() throws Exception {
        MockHttpSession viewer = login("t23_viewer_detail", UserRole.VIEWER, "lab-*");
        JsonNode body = getJson(viewer, "/api/incidents/501/rank/1");
        JsonNode meta = body.get("queueMeta");
        assertThat(meta.get("sourceType").asText()).isEqualTo("live");
        assertThat(OffsetDateTime.parse(meta.get("detectedAt").asText()).toInstant())
                .isEqualTo(Instant.parse("2026-11-18T00:06:00Z"));
        assertThat(meta.get("latestJobId").asLong()).isEqualTo(502L);
        assertThat(meta.get("latestQueueRank").asInt()).isEqualTo(2);
        assertThat(meta.get("priority").asText()).isEqualTo("high");
        assertThat(meta.toString()).doesNotContain("10.20.0.15");
    }

    /* ───────────── 도우미 ───────────── */

    private static UnifiedQueueRecord record(String capture, String status, String eventEnd) {
        UnifiedQueueRecord r = new UnifiedQueueRecord();
        r.setCaptureId(capture);
        r.setZeekadStatus(status);
        r.setEventEnd(OffsetDateTime.parse(eventEnd));
        return r;
    }

    private static QueueParams params(String period) {
        return new QueueParams(period, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "100");
    }

    private static QueueParams withSource(String period, String source) {
        return new QueueParams(period, source, null, null, null, null, null, null, null, null, null, null, null, null, null, "100");
    }

    private static List<String> ids(UnifiedQueueResponse res) {
        return res.items().stream().map(r -> r.getItem().getIncidentId()).toList();
    }

    private static List<String> keys(List<UnifiedQueueRecord> rows) {
        return rows.stream().map(r -> r.getCaptureId() + "#" + r.getQueueRank()).toList();
    }

    private static UnifiedQueueCriteria criteria(List<String> captures) {
        UnifiedQueueCriteria c = new UnifiedQueueCriteria();
        c.setCaptureIds(captures);
        return c;
    }

    private static DashboardUserPrincipal principal(UserRole role, String pattern) {
        DashboardUser u = new DashboardUser();
        u.setId(-1L);
        u.setUsername("t23-principal");
        u.setDisplayName("t23");
        u.setRole(role);
        u.setEnabled(true);
        return new DashboardUserPrincipal(u, List.of(pattern), FIXED_NOW);
    }

    private void assertNoFullIpv4(JsonNode node) {
        var m = FULL_IPV4.matcher(node.toString());
        while (m.find()) {
            boolean valid = true;
            for (int g = 1; g <= 4; g++) {
                if (Integer.parseInt(m.group(g)) > 255) valid = false;
            }
            assertThat(valid).as("가려지지 않은 IPv4: %s", m.group()).isFalse();
        }
    }

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(zeekadReadDataSource);
    }

    /**
     * 우선순위 조합 표: 상태 6 × 교차 탐지 3 × 리포트 상태 6 = 108행(작업 9001, 캡처 t23p-cap).
     * 상태: 없음(NULL) / 빈 값 / open / INVESTIGATING / " Closed " / 등록 안 된 값
     * 리포트: 없음 / 리포트만 / 리포트+발송 보류 / 리포트+발송 / 리포트+에스컬레이션 대기 / 리포트+에스컬레이션 결정됨
     */
    private int insertPriorityCombinations() {
        JdbcTemplate jdbc = jdbc();
        jdbc.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-10 00:00:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-10 00:10:00Z', NULL, 108)", PRIO_JOB, PRIO_CAPTURE);
        String[] statuses = {null, "", "open", "INVESTIGATING", " Closed ", "archived"};
        String[] also = {"null", "empty", "one"};
        String[] reports = {"none", "only", "hold", "send", "pending", "decided"};
        int rank = 0;
        for (int si = 0; si < statuses.length; si++) {
            for (String a : also) {
                for (String rep : reports) {
                    rank++;
                    String ip = "10.77." + si + "." + rank;
                    String id = PRIO_CAPTURE + "|" + ip + "|st" + si + "|also-" + a + "|rep-" + rep + "|";
                    String alsoSql = switch (a) {
                        case "null" -> "NULL";
                        case "empty" -> "ARRAY[]::VARCHAR ARRAY";
                        default -> "ARRAY['autoencoder']";
                    };
                    // 시작 시각·세션 수는 같은 값이 겹치게 둬서 2차 정렬을 시험한다. 일부는 세션 수 NULL 대신 0
                    String start = String.format("2026-11-09 %02d:00:00Z", rank % 5);
                    jdbc.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                            + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                            + "VALUES (?, ?, 'zeekad-fusion/1', ?, ?, ?, ?, CAST(? AS TIMESTAMP WITH TIME ZONE), "
                            + "TIMESTAMP WITH TIME ZONE '2026-11-09 06:00:00Z', 'hbos', " + alsoSql + ", ?, ARRAY['t23-host-" + rank + "'])",
                            PRIO_JOB, PRIO_CAPTURE, rank, id, ip, rank % 2 == 0 ? "originator" : "responder", start, (long) (rank % 7) * 10);
                    if (statuses[si] != null) {
                        jdbc.update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                                + "VALUES (?, ?, ?, NULL, TIMESTAMP WITH TIME ZONE '2026-11-10 01:00:00Z', 't23')", PRIO_JOB, id, statuses[si]);
                    }
                    if (!"none".equals(rep)) {
                        jdbc.update("INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version, "
                                + "zeekad_report, created_at) VALUES (?, ?, 'template', 'template.v1', '{}' FORMAT JSON, "
                                + "TIMESTAMP WITH TIME ZONE '2026-11-10 00:11:00Z')", PRIO_JOB, id);
                    }
                    if ("hold".equals(rep) || "send".equals(rep)) {
                        jdbc.update("INSERT INTO dashboard.raw_send_decisions (job_id, incident_id, zeekad_would_send, zeekad_decided_by, created_at) "
                                + "VALUES (?, ?, ?, 'policy', TIMESTAMP WITH TIME ZONE '2026-11-10 00:12:00Z')", PRIO_JOB, id, "send".equals(rep));
                    }
                    if ("pending".equals(rep) || "decided".equals(rep)) {
                        jdbc.update("INSERT INTO dashboard.raw_analyst_review_queue (job_id, incident_id, queue_rank, host_ip, zeekad_role, "
                                + "zeekad_review_reason, requested_at, zeekad_review_action) VALUES (?, ?, ?, ?, 'originator', 't23', "
                                + "TIMESTAMP WITH TIME ZONE '2026-11-10 00:12:00Z', ?)", PRIO_JOB, id, rank, ip,
                                "decided".equals(rep) ? "confirm" : null);
                    }
                }
            }
        }
        return rank;
    }

    private void deleteSyntheticRows() {
        JdbcTemplate jdbc = jdbc();
        for (long job : new long[]{PRIO_JOB, BIG_JOB}) {
            jdbc.update("DELETE FROM dashboard.raw_analyst_review_queue WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_send_decisions WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_status WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE job_id = ?", job);
            jdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id = ?", job);
        }
    }

    private JsonNode getJson(MockHttpSession session, String url) throws Exception {
        MvcResult r = mockMvc.perform(get(url).session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8));
    }

    private MockHttpSession login(String username, UserRole role, String patterns) throws Exception {
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

    @SuppressWarnings("unused")
    private static boolean same(Object a, Object b) {
        return Objects.equals(a, b);
    }
}
