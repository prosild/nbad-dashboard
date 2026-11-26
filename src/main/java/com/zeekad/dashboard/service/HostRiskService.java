package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.HostRiskResponse;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.mapper.zeekad.read.HostReadMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 호스트 위험도 목록(T46, GET /api/hosts). 현황판과 같은 조건(IncidentQueueService.resolveCondition)의 최신 큐 행을
 * 기존 큐 질의(findUnifiedQueue)로 한 번 읽어 Java에서 호스트로 묶는다.
 * <ul>
 *   <li>묶는 단위: 분석가·관리자는 원문 host_ip, 조회자는 가려진 주소(A.B.*.*)다. 조회자 묶음을 원문으로 계산한 뒤 가리지 않는다
 *       (줄 수와 순서로 원문 호스트 수가 드러난다). 여러 캡처의 같은 주소는 한 줄이다.</li>
 *   <li>위험도는 새 점수가 아니라 미종결 우선순위 건수로 줄 세운 순서다. 우선순위·탐지 시각은 큐 식이 계산한 값을 그대로 쓴다.</li>
 *   <li>질의 수는 호스트 수와 무관하다: 큐 행 한 번, asset_names 한 번, 그 밖에 조건 조립용 조회.</li>
 *   <li>정상 조회는 감사 로그를 남기지 않는다(허용 밖 captureId만 resolveCondition이 403과 IDOR 감사를 남긴다).</li>
 *   <li>T52: 중요 자산은 줄 표지(assetCritical)와 이름(분석가·관리자만)으로만 싣는다. 위험도 정렬의 키가 아니다.</li>
 * </ul>
 */
@Service
public class HostRiskService {

    /** 읽는 큐 행 상한. 넘으면 400 QUERY_TOO_BROAD(큐 자산 검색과 같은 응답) */
    public static final int ROW_CAP = IncidentQueueService.ASSET_SEARCH_CAP;
    /** 줄에 싣는 호스트 이름·계정 수(전체 수는 따로 준다) */
    public static final int NAME_LIMIT = 5;
    /** 검색어 길이 상한 */
    public static final int QUERY_MAX_LENGTH = 100;

    static final String SORT_RISK = "risk";
    static final String SORT_INCIDENTS = "incidents";
    static final String SORT_CONNECTIONS = "connections";
    static final String SORT_LAST_DETECTED = "lastDetected";
    static final String SORT_HOST_IP = "hostIp";
    /** 소문자로 바꾼 요청 값 → 정렬 키 */
    private static final Map<String, String> SORT_KEYS = Map.of(
            "risk", SORT_RISK,
            "incidents", SORT_INCIDENTS,
            "connections", SORT_CONNECTIONS,
            "lastdetected", SORT_LAST_DETECTED,
            "hostip", SORT_HOST_IP);

    private final ZeekadReadMapper zeekadReadMapper;
    private final HostReadMapper hostReadMapper;
    private final IncidentQueueService incidentQueueService;
    private final MaskingService maskingService;
    private final TimeContextService timeContextService;

    public HostRiskService(ZeekadReadMapper zeekadReadMapper,
                           HostReadMapper hostReadMapper,
                           IncidentQueueService incidentQueueService,
                           MaskingService maskingService,
                           TimeContextService timeContextService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.hostReadMapper = hostReadMapper;
        this.incidentQueueService = incidentQueueService;
        this.maskingService = maskingService;
        this.timeContextService = timeContextService;
    }

    /** 요청 값(문자열 그대로). 해석은 이 서비스가 한다. */
    public record HostParams(String period, String start, String end, String source, String captureId,
                             String sort, String dir, String roleTransitionOnly, String q, String page, String size) {
    }

    public HostRiskResponse load(DashboardUserPrincipal principal, HostParams p, String clientIp) {
        // 큐와 같은 순서: 조건(허용 밖 captureId의 403 포함)을 먼저 보고 그 뒤에 이 API의 값을 본다
        IncidentQueueService.Condition cond = incidentQueueService.resolveCondition(
                principal, p.period(), p.start(), p.end(), p.source(), p.captureId(), clientIp);
        String sortKey = parseSort(p.sort());
        boolean asc = parseDir(p.dir(), sortKey);
        boolean transitionOnly = parseTransitionOnly(p.roleTransitionOnly());
        String needle = parseQuery(p.q());
        int size = IncidentQueueService.parseSize(p.size());

        UserRole role = principal != null ? principal.getRole() : UserRole.VIEWER;
        boolean masked = maskingService.shouldMask(role);

        List<Group> groups;
        if (cond.captureIds().isEmpty() || (masked && transitionOnly)) {
            // 조회자의 가려진 대역은 호스트 하나가 아니어서 전환을 판정하지 않는다(늘 false, 전환만 보기는 빈 목록)
            groups = List.of();
        } else {
            groups = aggregate(readRows(cond.criteria()), role, masked);
        }

        List<Group> filtered = new ArrayList<>();
        for (Group g : groups) {
            if (transitionOnly && !g.roleTransition) {
                continue;
            }
            // 검색은 줄에 싣지 않는 6번째부터의 이름·계정에도 맞는다. 조회자는 가린 뒤의 글에만 맞는다
            if (needle != null && !g.matches(needle)) {
                continue;
            }
            filtered.add(g);
        }
        filtered.sort(comparator(sortKey, asc));

        long total = filtered.size();
        int pageCount = (int) Math.max(1, (total + size - 1) / size);
        int page = clampPage(p.page(), pageCount);
        int from = Math.min(filtered.size(), (page - 1) * size);
        int to = Math.min(filtered.size(), from + size);
        // T52 중요 자산 이름: 조건을 만든 같은 스냅샷에서 붙인다(분석가·관리자의 원문 주소 줄만. 조회자 대역 줄은 null)
        CriticalAssetService.Snapshot assets = cond.assets();
        List<HostRiskResponse.Item> items = filtered.subList(from, to).stream()
                .map(g -> g.toItem(g.assetCritical ? assets.nameFor(g.hostIp, masked) : null))
                .toList();

        List<UnifiedQueueResponse.Source> sources = cond.allowed().stream()
                .map(c -> new UnifiedQueueResponse.Source(c, timeContextService.sourceType(c), null, null))
                .toList();
        return new HostRiskResponse(items, total, page, size, pageCount,
                cond.anchor(), timeContextService.mode(), timeContextService.isSnapshot(), cond.period(),
                cond.after(), cond.until(), sources, masked);
    }

    /* ───────────────────────── 읽기 ───────────────────────── */

    /** 큐 목록과 같은 식·거르기로 조건 안의 행을 읽는다(같은 집합). 상한을 넘으면 400이다. */
    private List<UnifiedQueueRecord> readRows(UnifiedQueueCriteria criteria) {
        UnifiedQueueCriteria c = criteria.copy();
        c.setLimit(ROW_CAP + 1);
        c.setOffset(null);
        List<UnifiedQueueRecord> rows = zeekadReadMapper.findUnifiedQueue(c);
        if (rows.size() > ROW_CAP) {
            throw new QueueQueryException("QUERY_TOO_BROAD", "기간이나 수집원을 좁혀 주세요");
        }
        return rows;
    }

    /* ───────────────────────── 묶기 ───────────────────────── */

    private List<Group> aggregate(List<UnifiedQueueRecord> rows, UserRole role, boolean masked) {
        Map<String, Group> byKey = new LinkedHashMap<>();
        /* (캡처, 원문 주소) 쌍 → 묶음. asset_names 행을 제 묶음에 붙이는 데 쓴다 */
        Map<Pair, Group> byPair = new HashMap<>();
        Set<String> captures = new TreeSet<>();
        Set<String> rawHosts = new TreeSet<>();
        for (UnifiedQueueRecord r : rows) {
            String rawHost = r.getHostIp() == null ? "" : r.getHostIp();
            String key = masked ? maskingService.maskIp(rawHost) : rawHost;
            Group g = byKey.computeIfAbsent(key, Group::new);
            g.add(r, masked, maskingService);
            if (r.getCaptureId() != null && !rawHost.isEmpty()) {
                byPair.put(new Pair(r.getCaptureId(), rawHost), g);
                captures.add(r.getCaptureId());
                rawHosts.add(rawHost);
            }
        }
        if (!byPair.isEmpty()) {
            // 관측 계정: 캡처 목록으로 한 번 읽고 (캡처, 주소) 쌍이 맞는 행만 그 묶음에 붙인다. 가린 뒤의 이름을 쓴다
            List<Map<String, Object>> assetRows = hostReadMapper.findRawAssetNamesForHosts(
                    List.copyOf(captures), rawHosts.toArray(new String[0]));
            for (Map<String, Object> raw : assetRows) {
                AssetNameRecord asset = AssetNameRecord.fromRawMap(raw);
                Group g = byPair.get(new Pair(asset.getCaptureId(), asset.getHostIp()));
                if (g != null) {
                    g.accounts.addAll(accountNames(maskingService.maskAssetNameRecord(asset, role)));
                }
            }
        }
        if (!masked) {
            for (Group g : byKey.values()) {
                g.roleTransition = g.hasRoleTransition();
            }
        }
        return new ArrayList<>(byKey.values());
    }

    private record Pair(String captureId, String hostIp) {
    }

    /**
     * 화면(증적 탭 '관측 계정')과 같은 순서로 계정 이름을 뽑는다: zeekad_name이 있으면 그 값, 없으면 kerberosUser와 ntlmUser.
     * 받는 값은 이미 역할에 맞게 가려진 행이다.
     */
    static List<String> accountNames(AssetNameRecord asset) {
        List<String> names = new ArrayList<>();
        Object value = null;
        for (Map.Entry<String, Object> e : asset.getExtraAttributes().entrySet()) {
            if (e.getKey() != null && MaskingService.ASSET_ACCOUNT_NAME_KEY.equalsIgnoreCase(e.getKey())) {
                value = e.getValue();
                break;
            }
        }
        if (value instanceof List<?> list) {
            for (Object elem : list) {
                addName(names, elem);
            }
        } else {
            addName(names, value);
        }
        if (!names.isEmpty()) {
            return names;
        }
        addName(names, asset.getKerberosUser());
        addName(names, asset.getNtlmUser());
        return names;
    }

    private static void addName(List<String> out, Object value) {
        if (value == null) {
            return;
        }
        String text = String.valueOf(value).trim();
        if (!text.isEmpty()) {
            out.add(text);
        }
    }

    /** 한 호스트(조회자는 한 대역)의 누적 값 */
    private static final class Group {
        final String hostIp;
        final Set<String> hostNames = new TreeSet<>();
        final Set<String> accounts = new TreeSet<>();
        final Map<String, Long> models = new HashMap<>();
        /* 전환 판정(같은 캡처 안): 캡처별 가장 이른 목적지 발생 시각과 가장 늦은 출발지 발생 시각 */
        final Map<String, Instant> earliestResponder = new HashMap<>();
        final Map<String, Instant> latestOriginator = new HashMap<>();
        long high;
        long medium;
        long low;
        long incidents;
        long connections;
        OffsetDateTime lastDetectedAt;
        boolean roleTransition;
        /** T52 이 줄의 행 가운데 중요 자산이 하나라도 있는지(조회자 대역 줄은 대역 안의 호스트 하나라도) */
        boolean assetCritical;

        Group(String hostIp) {
            this.hostIp = hostIp;
        }

        void add(UnifiedQueueRecord r, boolean masked, MaskingService masking) {
            incidents++;
            if (r.isAssetCritical()) {
                assetCritical = true;
            }
            if ("high".equals(r.getPriority())) {
                high++;
            } else if ("medium".equals(r.getPriority())) {
                medium++;
            } else if ("low".equals(r.getPriority())) {
                low++;
            }
            connections += r.getConnectionCount() == null ? 0 : r.getConnectionCount();
            if (r.getZeekadPickedBy() != null && !r.getZeekadPickedBy().isBlank()) {
                models.merge(r.getZeekadPickedBy(), 1L, Long::sum);
            }
            if (r.getHostName() != null) {
                for (String name : r.getHostName()) {
                    if (name != null && !name.isBlank()) {
                        hostNames.add(masked ? masking.maskIpsInText(name) : name);
                    }
                }
            }
            OffsetDateTime detected = r.getDetectedAt();
            if (detected != null && (lastDetectedAt == null || detected.toInstant().isAfter(lastDetectedAt.toInstant()))) {
                lastDetectedAt = detected;
            }
            if (masked || r.getEventStart() == null || r.getCaptureId() == null || isDismissed(r)) {
                return;
            }
            Instant start = r.getEventStart().toInstant();
            String direction = norm(r.getZeekadRole());
            if ("responder".equals(direction)) {
                earliestResponder.merge(r.getCaptureId(), start, (a, b) -> a.isBefore(b) ? a : b);
            } else if ("originator".equals(direction)) {
                latestOriginator.merge(r.getCaptureId(), start, (a, b) -> a.isAfter(b) ? a : b);
            }
        }

        /** 같은 캡처에서 가장 이른 목적지 발생 시각보다 엄격히 뒤인 출발지 발생 시각이 있는지 */
        boolean hasRoleTransition() {
            for (Map.Entry<String, Instant> e : earliestResponder.entrySet()) {
                Instant originator = latestOriginator.get(e.getKey());
                if (originator != null && originator.isAfter(e.getValue())) {
                    return true;
                }
            }
            return false;
        }

        boolean matches(String needle) {
            if (contains(hostIp, needle)) {
                return true;
            }
            for (String name : hostNames) {
                if (contains(name, needle)) {
                    return true;
                }
            }
            for (String account : accounts) {
                if (contains(account, needle)) {
                    return true;
                }
            }
            return false;
        }

        HostRiskResponse.Item toItem(String criticalAssetName) {
            List<String> modelIds = models.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                            .thenComparing(Map.Entry.comparingByKey()))
                    .map(Map.Entry::getKey)
                    .toList();
            return new HostRiskResponse.Item(hostIp,
                    hostNames.stream().limit(NAME_LIMIT).toList(), hostNames.size(),
                    accounts.stream().limit(NAME_LIMIT).toList(), accounts.size(),
                    high, medium, low, incidents, connections, modelIds, lastDetectedAt, roleTransition,
                    assetCritical, criticalAssetName);
        }
    }

    /** 오탐·정상으로 종결된 인시던트(전환 판정에서 뺀다) */
    private static boolean isDismissed(UnifiedQueueRecord r) {
        if (!"closed".equals(norm(r.getZeekadStatus()))) {
            return false;
        }
        String resolution = norm(r.getZeekadResolution());
        return "false_positive".equals(resolution) || "benign".equals(resolution);
    }

    private static String norm(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean contains(String text, String needle) {
        return text != null && text.toLowerCase(Locale.ROOT).contains(needle);
    }

    /* ───────────────────────── 순서 ───────────────────────── */

    /**
     * risk: high → medium → low → incidents → lastDetectedAt(값 없음은 뒤) → hostIp 오름차순. dir은 hostIp를 뺀 앞의 키들에 걸린다.
     * 다른 키: 그 값(dir) 다음에 risk 기본 순서를 붙인다. hostIp는 글자 순이다(조회자 키 A.B.*.*와 같은 규칙).
     */
    private static Comparator<Group> comparator(String sortKey, boolean asc) {
        Comparator<Group> hostAsc = Comparator.comparing(g -> g.hostIp);
        if (SORT_RISK.equals(sortKey)) {
            return riskChain(asc).thenComparing(hostAsc);
        }
        Comparator<Group> primary = switch (sortKey) {
            case SORT_INCIDENTS -> directed(Comparator.comparingLong(g -> g.incidents), asc);
            case SORT_CONNECTIONS -> directed(Comparator.comparingLong(g -> g.connections), asc);
            case SORT_LAST_DETECTED -> lastDetected(asc);
            default -> directed(hostAsc, asc);
        };
        return primary.thenComparing(riskChain(false)).thenComparing(hostAsc);
    }

    private static Comparator<Group> riskChain(boolean asc) {
        return directed(Comparator.<Group>comparingLong(g -> g.high), asc)
                .thenComparing(directed(Comparator.comparingLong(g -> g.medium), asc))
                .thenComparing(directed(Comparator.comparingLong(g -> g.low), asc))
                .thenComparing(directed(Comparator.comparingLong(g -> g.incidents), asc))
                .thenComparing(lastDetected(asc));
    }

    /** 값이 없는 마지막 탐지는 방향과 상관없이 뒤다(큐의 값 없음 맨 뒤와 같다) */
    private static Comparator<Group> lastDetected(boolean asc) {
        Comparator<Instant> order = asc ? Comparator.naturalOrder() : Comparator.reverseOrder();
        return Comparator.comparing(g -> g.lastDetectedAt == null ? null : g.lastDetectedAt.toInstant(),
                Comparator.nullsLast(order));
    }

    private static Comparator<Group> directed(Comparator<Group> c, boolean asc) {
        return asc ? c : c.reversed();
    }

    /* ───────────────────────── 요청 값 ───────────────────────── */

    private static String parseSort(String raw) {
        String clean = trimToNull(raw);
        if (clean == null) {
            return SORT_RISK;
        }
        String key = SORT_KEYS.get(clean.toLowerCase(Locale.ROOT));
        if (key == null) {
            throw invalid("정렬 값이 올바르지 않습니다.");
        }
        return key;
    }

    /** 기본 방향: hostIp만 오름, 나머지는 내림 */
    private static boolean parseDir(String raw, String sortKey) {
        String clean = trimToNull(raw);
        if (clean == null) {
            return SORT_HOST_IP.equals(sortKey);
        }
        if ("asc".equalsIgnoreCase(clean)) {
            return true;
        }
        if ("desc".equalsIgnoreCase(clean)) {
            return false;
        }
        throw invalid("정렬 방향 값이 올바르지 않습니다.");
    }

    private static boolean parseTransitionOnly(String raw) {
        String clean = trimToNull(raw);
        if (clean == null || "false".equalsIgnoreCase(clean)) {
            return false;
        }
        if ("true".equalsIgnoreCase(clean)) {
            return true;
        }
        throw invalid("전환 거르기 값이 올바르지 않습니다.");
    }

    /** 검색어(소문자). 빈 값이면 null(조건 없음), 100자를 넘으면 400 */
    private static String parseQuery(String raw) {
        String clean = trimToNull(raw);
        if (clean == null) {
            return null;
        }
        if (clean.length() > QUERY_MAX_LENGTH) {
            throw invalid("검색어는 100자를 넘을 수 없습니다.");
        }
        return clean.toLowerCase(Locale.ROOT);
    }

    /** 큐와 같은 규칙: 숫자가 아니거나 1보다 작으면 1쪽, 범위 밖이면 마지막 쪽 */
    private static int clampPage(String raw, int pageCount) {
        int page;
        try {
            page = Integer.parseInt(raw == null ? "" : raw.trim());
        } catch (NumberFormatException e) {
            page = 1;
        }
        if (page < 1) {
            page = 1;
        }
        return Math.min(page, pageCount);
    }

    private static QueueQueryException invalid(String message) {
        return new QueueQueryException("INVALID_REQUEST", message);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
