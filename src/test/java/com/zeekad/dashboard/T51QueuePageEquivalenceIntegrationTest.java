package com.zeekad.dashboard;

import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.dto.UnifiedQueueRow;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueuePeriodSplit;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueSummaryRow;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.IncidentRefService;
import com.zeekad.dashboard.service.MaskingService;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import com.zeekad.dashboard.testsupport.T51QueueSeed;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import javax.sql.DataSource;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T51 H2 대조: 같은 요청을 옛 문장 조합(건수 또는 기간 나눔 + 목록 + 요약 + 최댓값, 옛 쪽 보정)으로 낸 값과
 * 새 경로(목록 한 문장을 쓰는 loadQueue)의 값을 필드별로 견준다. 옛 문장들은 매퍼에 남아 있어 기준으로 쓴다.
 * 조건은 서비스가 새 문장에 넘긴 것을 그대로 붙잡아 옛 문장에 준다(조건 조립을 시험이 흉내 내지 않는다).
 * 자료: 기존 시드(zeekad-read-sample-data.sql) + T23 조합 표를 실습망 캡처에 탐지 시각을 갈라 넣은 {@link T51QueueSeed}.
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t51b_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t51b_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t51b_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
@ActiveProfiles("test")
class T51QueuePageEquivalenceIntegrationTest {

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(T51QueueSeed.NOW);
        }
    }

    @Autowired private IncidentQueueService queueService;
    @Autowired private IncidentRefService refService;
    @Autowired private MaskingService maskingService;
    @Autowired private UserAdminService userAdminService;
    @Autowired private MutableTestClock clock;
    @MockitoSpyBean private ZeekadReadMapper zeekadReadMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @Autowired @Qualifier("appDataSource") private DataSource appDataSource;

    private static int seq = 0;
    private DashboardUserPrincipal analyst;
    private DashboardUserPrincipal viewer;
    private String threadNo;

    /** 견준 결과를 세어 조합이 빈 결과만 견주지 않았다는 것을 끝에 확인한다 */
    private final Map<String, Integer> seen = new LinkedHashMap<>();

    /* ───────────── 축 ───────────── */

    /** 띠 축: 우선순위, 에스컬레이션 대기, 경보 발송, 착수 지연 = {priority, reviewPending, alerted, overdue} */
    private static final String[][] STRIP = {
            {null, null, null, null},
            {"high", null, null, null},
            {"medium", null, null, null},
            {"low", null, null, null},
            {null, "true", null, null},
            {null, null, "true", null},
            {null, null, null, "true"},
            // 아래 셋은 여러 띠 축을 함께 건 것(표본 시험에서만 쓴다)
            {"high", null, "true", null},
            {"low", null, null, "true"},
            {"medium", "true", "true", "true"},
    };
    /** 띠 축을 하나씩만 건 것(없음 포함)의 수 */
    private static final int SINGLE_STRIPS = 7;

    /** 기간: {period, start, end}. null = 기본(24시간) */
    private static final String[][] PERIOD = {
            {null, null, null},
            {"1h", null, null},
            {"24h", null, null},
            {"7d", null, null},
            {"30d", null, null},
            {"all", null, null},
            // 지정 구간: 건수가 있는 것(11-05·11-16 탐지를 포함)과 0건인 것
            {"custom", "2026-11-01T00:00:00Z", "2026-11-17T00:00:00+09:00"},
            {"custom", "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"},
    };

    private static final String[] SORT = {null, "priority", "detected", "start", "connections", "status"};
    private static final String[] DIR = {null, "asc", "desc"};
    /** 쪽: 생략, 첫, 가운데, 끝(25건씩 125행이면 5), 범위 밖, 잘못된 값(0, 음수, 숫자 아님, int 최대, int 범위 밖) */
    private static final String[] PAGE = {null, "1", "2", "3", "5", "6", "999", "0", "-1", "abc", "2147483647", "2147483648"};
    /** 크기: 셋과 허용 밖 값(50으로 읽는다) */
    private static final String[] SIZE = {"25", "50", "100", "7"};

    /** 일반 조건 하나를 QueueParams에 얹는다 */
    private record General(String name, String status, String pickedBy, String role, String hasReport, String wouldSend,
                           String source, String captureId, String assignee, String hostIp, String attack, boolean thread) {
        static General of(String name) {
            return new General(name, null, null, null, null, null, null, null, null, null, null, false);
        }
    }

    private List<General> generals() {
        List<General> g = new ArrayList<>();
        g.add(General.of("없음"));
        g.add(new General("status=open", "open", null, null, null, null, null, null, null, null, null, false));
        g.add(new General("status=investigating", "investigating", null, null, null, null, null, null, null, null, null, false));
        g.add(new General("status=closed", "closed", null, null, null, null, null, null, null, null, null, false));
        g.add(new General("pickedBy", null, "iforest", null, null, null, null, null, null, null, null, false));
        g.add(new General("role", null, null, "responder", null, null, null, null, null, null, null, false));
        g.add(new General("hasReport=true", null, null, null, "true", null, null, null, null, null, null, false));
        g.add(new General("hasReport=false", null, null, null, "false", null, null, null, null, null, null, false));
        g.add(new General("wouldSend=true", null, null, null, null, "true", null, null, null, null, null, false));
        g.add(new General("wouldSend=false", null, null, null, null, "false", null, null, null, null, null, false));
        g.add(new General("source=live", null, null, null, null, null, "live", null, null, null, null, false));
        g.add(new General("source=imported", null, null, null, null, null, "imported", null, null, null, null, false));
        g.add(new General("captureId", null, null, null, null, null, null, T51QueueSeed.LIVE, null, null, null, false));
        g.add(new General("captureId+source", null, null, null, null, null, "live", T51QueueSeed.LIVE, null, null, null, false));
        g.add(new General("assignee=me", null, null, null, null, null, null, null, "me", null, null, false));
        g.add(new General("assignee=none", null, null, null, null, null, null, null, "none", null, null, false));
        g.add(new General("hostIp 대역", null, null, null, null, null, null, null, null, "10.51.*.*", null, false));
        g.add(new General("hostIp 정확", null, null, null, null, null, null, null, null, T51QueueSeed.liveHost(8), null, false));
        g.add(new General("attack", null, null, null, null, null, null, null, null, null, "T1059", false));
        g.add(new General("thread", null, null, null, null, null, null, null, null, null, null, true));
        g.add(new General("여러 조건", "open", "hbos", "originator", "true", null, null, null, "none", null, null, false));
        return g;
    }

    @BeforeEach
    void setUp() {
        clock.set(T51QueueSeed.NOW);
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        T51QueueSeed.delete(jdbc);
        T51QueueSeed.insert(jdbc);
        analyst = principal(UserRole.ANALYST);
        viewer = principal(UserRole.VIEWER);
        JdbcTemplate app = new JdbcTemplate(appDataSource);
        app.update("DELETE FROM incident_assignments WHERE assigned_by = 't51'");
        // 담당: 분석가에게 순위 5의 배수 행(조합 표 108행 중 21행)
        for (int rank = 5; rank <= T51QueueSeed.COMBINATIONS; rank += 5) {
            app.update("INSERT INTO incident_assignments (incident_id, capture_id, assignee_user_id, assigned_at, assigned_by, version) "
                            + "VALUES (?, ?, ?, TIMESTAMP WITH TIME ZONE '2026-11-20 23:45:00Z', 't51', 1)",
                    T51QueueSeed.liveId(rank), T51QueueSeed.LIVE, analyst.getId());
        }
        refService.syncAll();
        threadNo = String.valueOf(refService.numbersFor(List.of(T51QueueSeed.liveId(8))).get(T51QueueSeed.liveId(8)));
        seen.clear();
    }

    @AfterEach
    void cleanup() {
        new JdbcTemplate(appDataSource).update("DELETE FROM incident_assignments WHERE assigned_by = 't51'");
        T51QueueSeed.delete(new JdbcTemplate(zeekadReadDataSource));
        Mockito.reset(zeekadReadMapper);
    }

    /* ───────────── 시험 ───────────── */

    /**
     * 띠 축(없음과 넷) × 일반 조건 × 기간(프리셋 넷·전체·지정 구간 둘)의 모든 조합. 정렬·쪽은 기본값.
     * 기간 생략(= 24시간)과 띠 축 여럿은 표본 시험이 덮는다(전체 검사 시간을 늘리지 않으려고 여기서는 뺐다).
     */
    @Test
    void everyStripGeneralPeriodCombinationMatchesTheOldStatements() {
        // 일반 조건 가운데 같은 SQL 꼴의 다른 값(상태 분석 중, 실습망 수집원, 캡처 + 수집원, 호스트 대역)은 표본 시험이 덮는다
        List<General> gs = generals().stream()
                .filter(g -> !List.of("status=investigating", "source=live", "captureId+source", "hostIp 대역").contains(g.name()))
                .toList();
        assertThat(gs).hasSize(generals().size() - 4);
        int n = 0;
        for (int si = 0; si < SINGLE_STRIPS; si++) {
            for (General g : gs) {
                for (int pi = 1; pi < PERIOD.length; pi++) {
                    compare(analyst, params(PERIOD[pi], g, STRIP[si], null, null, null, null));
                    n++;
                }
            }
        }
        assertThat(n).isEqualTo(SINGLE_STRIPS * gs.size() * (PERIOD.length - 1));
        assertCoverage();
        // 반드시 있어야 하는 두 경계
        assertThat(seen).containsKeys("목록 0건 · 요약 0 아님", "기간 안 0건 · 기간 밖 0 초과");
    }

    /**
     * 정렬·쪽·크기(한 맥락: 전체 기간, 실습망 캡처 108행. 25건씩이면 5쪽이라 가운데·끝·범위 밖이 모두 나온다).
     * 네 축을 다 곱하면 H2에서 한 건에 0.1초라 전체 검사가 곱절로 늘어, 세 묶음의 모든 조합으로 나눴다:
     * (정렬 키 다섯 × 방향 셋 × 쪽 열, 크기 25) + (정렬 키 × 방향 × 크기 넷, 2쪽) + (쪽 × 크기, 기본 정렬).
     * 네 축이 함께 바뀌는 조합과 정렬 생략·다른 조건 맥락은 표본 시험이 덮는다.
     */
    @Test
    void sortDirectionPageSizeCombinationsMatchTheOldStatements() {
        General liveOnly = generals().stream().filter(g -> "captureId".equals(g.name())).findFirst().orElseThrow();
        // 쪽: 생략, 첫, 가운데, 끝, 바로 다음(범위 밖), 먼 범위 밖, 0, 음수, 숫자 아님, int 최대
        String[] pages = {null, "1", "2", "5", "6", "999", "0", "-1", "abc", "2147483647"};
        int n = 0;
        for (int ki = 1; ki < SORT.length; ki++) {
            for (String dir : DIR) {
                for (String page : pages) {
                    compare(analyst, params(PERIOD[5], liveOnly, STRIP[0], SORT[ki], dir, page, "25"));
                    n++;
                }
                for (String size : SIZE) {
                    compare(analyst, params(PERIOD[5], liveOnly, STRIP[0], SORT[ki], dir, "2", size));
                    n++;
                }
            }
        }
        for (String page : pages) {
            for (String size : SIZE) {
                compare(analyst, params(PERIOD[5], liveOnly, STRIP[0], null, null, page, size));
                n++;
            }
        }
        assertThat(n).isEqualTo((SORT.length - 1) * DIR.length * (pages.length + SIZE.length) + pages.length * SIZE.length);
        assertCoverage();
        assertThat(seen).containsKeys("범위 밖 쪽이 마지막 쪽으로", "가운데 쪽", "쪽 수 2 이상");
    }
    /** 모든 축을 한꺼번에 곱한 공간에서 고정 씨앗으로 뽑은 표본(분석가·조회자) */
    @Test
    void seededSampleOfTheFullProductMatchesTheOldStatementsForAnalystAndViewer() {
        Random rnd = new Random(20261126L);
        List<General> gs = generals();
        for (int i = 0; i < 400; i++) {
            DashboardUserPrincipal who = rnd.nextInt(3) == 0 ? viewer : analyst;
            compare(who, params(PERIOD[rnd.nextInt(PERIOD.length)], gs.get(rnd.nextInt(gs.size())),
                    STRIP[rnd.nextInt(STRIP.length)], SORT[rnd.nextInt(SORT.length)], DIR[rnd.nextInt(DIR.length)],
                    PAGE[rnd.nextInt(PAGE.length)], SIZE[rnd.nextInt(SIZE.length)]));
        }
        assertCoverage();
        assertThat(seen).containsKeys("조회자", "목록 0건 · 요약 0 아님", "기간 안 0건 · 기간 밖 0 초과", "범위 밖 쪽이 마지막 쪽으로");
    }

    /* ───────────── 대조 ───────────── */

    private void compare(DashboardUserPrincipal who, QueueParams p) {
        String label = who.getRole() + " " + p;
        Mockito.clearInvocations(zeekadReadMapper);
        UnifiedQueueResponse res = queueService.loadQueue(who, p, "127.0.0.1");
        ArgumentCaptor<UnifiedQueueCriteria> criteria = ArgumentCaptor.forClass(UnifiedQueueCriteria.class);
        ArgumentCaptor<Integer> pageArg = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> sizeArg = ArgumentCaptor.forClass(Integer.class);
        Mockito.verify(zeekadReadMapper, Mockito.atMost(1))
                .findUnifiedQueuePage(criteria.capture(), pageArg.capture(), sizeArg.capture());
        // 새 경로는 옛 문장을 부르지 않는다
        Mockito.verify(zeekadReadMapper, Mockito.never()).countUnifiedQueue(Mockito.any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).summarizeUnifiedQueue(Mockito.any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findMaxUnifiedDetectedAt(Mockito.any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).splitUnifiedQueueByPeriod(Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.verify(zeekadReadMapper, Mockito.never()).findUnifiedQueue(Mockito.any());
        if (criteria.getAllValues().isEmpty()) {
            // 범위가 빈 요청(내 담당 없음, 고른 호스트 없음 등): 문장을 부르지 않고 빈 결과다(이 경로는 고치지 않았다)
            assertThat(res.total()).as(label).isZero();
            assertThat(res.items()).as(label).isEmpty();
            count("범위가 빈 요청");
            return;
        }
        UnifiedQueueCriteria c = criteria.getValue();
        int size = sizeArg.getValue();
        assertThat(res.size()).as(label).isEqualTo(size);

        // ── 옛 문장 조합과 옛 쪽 보정(T51 앞 loadQueue의 SQL 경로 그대로) ──
        boolean periodApplied = !"all".equals(res.period());
        boolean custom = "custom".equals(res.period());
        long total;
        Long outside = 0L;
        OffsetDateTime latest;
        OffsetDateTime newest = null;
        if (periodApplied) {
            UnifiedQueueCriteria noPeriod = c.copy();
            noPeriod.setDetectedAfter(null);
            noPeriod.setDetectedUntil(null);
            UnifiedQueuePeriodSplit split = zeekadReadMapper.splitUnifiedQueueByPeriod(
                    noPeriod, c.getDetectedAfter(), c.getDetectedUntil());
            total = split.getInPeriod();
            outside = split.getTotalAll() - total;
            latest = split.getLatestInPeriod();
            newest = custom ? null : split.getNewestBeforePeriod();
        } else {
            total = zeekadReadMapper.countUnifiedQueue(c);
            latest = total > 0 ? zeekadReadMapper.findMaxUnifiedDetectedAt(c) : null;
        }
        int pageCount = (int) Math.max(1, (total + size - 1) / size);
        int page = Math.min(oldRequestedPage(p.page()), pageCount);
        UnifiedQueueCriteria paged = c.copy();
        paged.setLimit(size);
        paged.setOffset((page - 1) * size);
        List<UnifiedQueueRecord> oldRows = zeekadReadMapper.findUnifiedQueue(paged);
        UnifiedQueueCriteria summaryCriteria = c.copy();
        summaryCriteria.setApplyStripFilters(false);
        UnifiedQueueSummaryRow sum = zeekadReadMapper.summarizeUnifiedQueue(summaryCriteria);

        // ── 필드별 대조 ──
        assertThat(res.total()).as("total %s", label).isEqualTo(total);
        assertThat(res.pageCount()).as("pageCount %s", label).isEqualTo(pageCount);
        assertThat(res.page()).as("page %s", label).isEqualTo(page);
        assertThat(res.latestDetectedAt()).as("latestDetectedAt %s", label).isEqualTo(latest);
        assertThat(res.outsidePeriod()).as("outsidePeriod %s", label).isEqualTo(outside);
        assertThat(res.newestOutsidePeriod()).as("newestOutsidePeriod %s", label).isEqualTo(newest);
        UnifiedQueueResponse.Summary s = res.summary();
        assertThat(List.of(s.total(), s.high(), s.medium(), s.low(), s.reviewPending(), s.alerted(),
                s.byStatus().get("open"), s.byStatus().get("investigating"), s.byStatus().get("closed"),
                s.byStatus().get("other"), s.overdue()))
                .as("summary %s", label)
                .containsExactly(sum.getTotal(), sum.getHigh(), sum.getMedium(), sum.getLow(), sum.getReviewPending(),
                        sum.getAlerted(), sum.getStatusOpen(), sum.getStatusInvestigating(), sum.getStatusClosed(),
                        sum.getStatusOther(), sum.getOverdue());
        assertThat(s.byStatus().keySet()).as(label).containsExactly("open", "investigating", "closed", "other");
        assertThat(res.items()).as("행 수 %s", label).hasSize(oldRows.size());
        for (int i = 0; i < oldRows.size(); i++) {
            UnifiedQueueRecord old = oldRows.get(i);
            UnifiedQueueRow now = res.items().get(i);
            IncidentQueueItem expected = maskingService.maskIncidentQueueItem(old, who.getRole());
            // 응답에 실리는 객체의 형까지 같다(형이 다르면 직렬화되는 필드가 달라진다)
            assertThat(now.getItem().getClass()).as("행 %d 형 %s", i, label).isEqualTo(expected.getClass());
            assertThat(beanValues(now.getItem())).as("행 %d %s", i, label).isEqualTo(beanValues(expected));
            assertThat(now.getDetectedAt()).as("행 %d detectedAt %s", i, label).isEqualTo(old.getDetectedAt());
            assertThat(now.getPriority()).as("행 %d priority %s", i, label).isEqualTo(old.getPriority());
        }

        count("견준 요청");
        if (who.getRole() == UserRole.VIEWER) count("조회자");
        if (total > 0) count("total 0 초과");
        if (!oldRows.isEmpty()) count("행 있음");
        if (total == 0 && sum.getTotal() > 0) count("목록 0건 · 요약 0 아님");
        if (periodApplied && total == 0 && outside > 0) count("기간 안 0건 · 기간 밖 0 초과");
        if (newest != null) count("기간 시작 이하 최근 탐지 있음");
        if (pageCount >= 2) count("쪽 수 2 이상");
        if (page > 1 && page < pageCount) count("가운데 쪽");
        if (page == pageCount && pageCount > 1) count("마지막 쪽");
        if (oldRequestedPage(p.page()) > pageCount && !oldRows.isEmpty()) count("범위 밖 쪽이 마지막 쪽으로");
        if (sum.getOverdue() > 0) count("착수 지연 0 초과");
        if (oldRows.stream().anyMatch(r -> r.getDetectedAt() == null)) count("탐지 시각 없는 행");
        if (oldRows.stream().anyMatch(r -> r.getHostName() != null && !r.getHostName().isEmpty())) count("host_name 있는 행");
    }

    private void assertCoverage() {
        assertThat(seen).as("견준 결과의 분포: %s", seen)
                .containsKeys("견준 요청", "total 0 초과", "행 있음", "쪽 수 2 이상", "착수 지연 0 초과", "host_name 있는 행");
        assertThat(seen.get("행 있음")).isGreaterThan(seen.get("견준 요청") / 4);
    }

    private void count(String key) {
        seen.merge(key, 1, Integer::sum);
    }

    /** T51 앞 clampPage의 앞부분: 숫자가 아니면 1, 1보다 작으면 1 */
    private static int oldRequestedPage(String raw) {
        int page;
        try {
            page = Integer.parseInt(raw == null ? "" : raw.trim());
        } catch (NumberFormatException e) {
            page = 1;
        }
        return Math.max(page, 1);
    }

    /** 객체의 모든 읽기 속성 값(이름 → 값). 형이 가진 속성 전부를 견준다 */
    private static Map<String, Object> beanValues(Object bean) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            for (PropertyDescriptor pd : Introspector.getBeanInfo(bean.getClass(), Object.class).getPropertyDescriptors()) {
                if (pd.getReadMethod() != null) {
                    out.put(pd.getName(), pd.getReadMethod().invoke(bean));
                }
            }
        } catch (ReflectiveOperationException | java.beans.IntrospectionException e) {
            throw new IllegalStateException(e);
        }
        assertThat(out).containsKeys("jobId", "queueRank", "hostName", "zeekadStatus", "alerted");
        return out;
    }

    private QueueParams params(String[] period, General g, String[] strip, String sort, String dir, String page, String size) {
        return new QueueParams(period[0], g.source(), g.captureId(), strip[0], g.status(), strip[1], strip[2],
                g.pickedBy(), g.role(), g.hasReport(), g.wouldSend(), null, sort, dir, page, size,
                g.assignee(), strip[3], period[1], period[2], g.thread() ? threadNo : null, g.hostIp(), g.attack());
    }

    private DashboardUserPrincipal principal(UserRole role) {
        String username = "t51b_u" + (++seq) + "_" + System.nanoTime() % 100000;
        DashboardUser user = userAdminService.createUser(username, "표시 " + username, "Pass1234!", role, "*", "seed", "ADMIN", "127.0.0.1");
        return new DashboardUserPrincipal(user, List.of("*"), T51QueueSeed.NOW);
    }
}
