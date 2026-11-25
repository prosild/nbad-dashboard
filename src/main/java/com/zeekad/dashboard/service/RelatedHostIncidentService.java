package com.zeekad.dashboard.service;

import com.zeekad.dashboard.dto.RelatedHostIncidentsResponse;
import com.zeekad.dashboard.mapper.zeekad.read.HostReadMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.IncidentRef;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 상세의 같은 호스트 인시던트(T46, GET /api/incidents/{jobId}/rank/{queueRank}/related-host-incidents).
 * <ul>
 *   <li>권한은 상세와 같은 검사다(허용 밖이면 403과 IDOR 감사). 상세 열람 때 이미 남는 INCIDENT_VIEW_UNMASKED는 여기서 남기지 않는다.</li>
 *   <li>대상: 허용 캡처 전체의 최신 큐. 분석가·관리자는 원문 host_ip가 같은 것, 조회자는 가린 주소(A.B.*.*)가 같은 것이다.
 *       조회 키는 가린 값이 아니라 권한 검사가 돌려준 원본 행에서 읽는다.</li>
 *   <li>자기 자신은 원문 incident_id로 뺀다(상세가 옛 작업 행을 보고 있어도 최신 큐의 자신이 남지 않는다).</li>
 *   <li>읽기 질의는 정해진 횟수다: 분석가·관리자 1회, 조회자는 대역의 원문 주소를 고르는 조회까지 2회. 번호는 읽기만 한다.</li>
 * </ul>
 */
@Service
public class RelatedHostIncidentService {

    /** 응답에 싣는 최대 건수 */
    public static final int ITEM_LIMIT = 10;

    private final CaptureAccessService captureAccessService;
    private final HostReadMapper hostReadMapper;
    private final ZeekadReadMapper zeekadReadMapper;
    private final MaskingService maskingService;
    private final IncidentRefService incidentRefService;

    public RelatedHostIncidentService(CaptureAccessService captureAccessService,
                                      HostReadMapper hostReadMapper,
                                      ZeekadReadMapper zeekadReadMapper,
                                      MaskingService maskingService,
                                      IncidentRefService incidentRefService) {
        this.captureAccessService = captureAccessService;
        this.hostReadMapper = hostReadMapper;
        this.zeekadReadMapper = zeekadReadMapper;
        this.maskingService = maskingService;
        this.incidentRefService = incidentRefService;
    }

    public RelatedHostIncidentsResponse load(DashboardUserPrincipal principal, Long jobId, Integer queueRank,
                                             String clientIp) {
        IncidentQueueItem rawIncident = captureAccessService.requireIncidentAccessByRank(
                principal, jobId, queueRank, clientIp);
        UserRole role = principal != null ? principal.getRole() : UserRole.VIEWER;
        boolean masked = maskingService.shouldMask(role);
        String rawHost = rawIncident.getHostIp();
        String shownHost = masked ? maskingService.maskIp(rawHost) : rawHost;

        List<String> allowed = captureAccessService.listAllowedCaptures(principal);
        if (allowed.isEmpty() || rawHost == null || rawHost.isBlank()) {
            return new RelatedHostIncidentsResponse(shownHost, 0, List.of(), masked);
        }
        String[] hostIps = masked ? sameRangeHosts(allowed, shownHost) : new String[]{rawHost};
        if (hostIps.length == 0) {
            return new RelatedHostIncidentsResponse(shownHost, 0, List.of(), masked);
        }

        UnifiedQueueCriteria c = new UnifiedQueueCriteria();
        c.setCaptureIds(List.copyOf(allowed));
        List<UnifiedQueueRecord> rows = hostReadMapper.findLatestQueueByHostIps(c, hostIps, rawIncident.getIncidentId());

        Instant self = instant(rawIncident.getEventStart());
        List<UnifiedQueueRecord> picked = rows.stream()
                .sorted(pickOrder(self))
                .limit(ITEM_LIMIT)
                .sorted(SHOW_ORDER)
                .toList();

        // 번호는 읽기만 한다(없으면 null). 동기화·쓰기를 일으키는 numbersFor·numberFor는 쓰지 않는다
        Map<String, IncidentRef> refs = incidentRefService.readRefsOnly(
                picked.stream().map(UnifiedQueueRecord::getIncidentId).toList());
        List<RelatedHostIncidentsResponse.Item> items = new ArrayList<>(picked.size());
        for (UnifiedQueueRecord r : picked) {
            IncidentRef ref = refs.get(r.getIncidentId());
            items.add(new RelatedHostIncidentsResponse.Item(
                    ref == null ? null : ref.getIncidentNo(),
                    r.getJobId(),
                    r.getQueueRank(),
                    r.getCaptureId(),
                    masked ? maskingService.maskIp(r.getHostIp()) : r.getHostIp(),
                    r.getZeekadRole(),
                    r.getEventStart(),
                    r.getDetectedAt(),
                    r.getPriority(),
                    r.getZeekadStatus(),
                    r.getZeekadResolution(),
                    r.getZeekadPickedBy(),
                    r.getConnectionCount()));
        }
        return new RelatedHostIncidentsResponse(shownHost, rows.size(), items, masked);
    }

    /**
     * 조회자: 허용 캡처 최신 큐의 호스트 주소(큐 hostIp 조건과 같은 조회) 가운데 가린 꼴이 같은 원문 주소들.
     * 가린 값끼리 Java에서 견준다(원문 주소를 요청 값과 SQL로 견주지 않는다).
     */
    private String[] sameRangeHosts(List<String> allowed, String maskedHost) {
        List<String> out = new ArrayList<>();
        for (String ip : zeekadReadMapper.findDistinctLatestHostIps(allowed)) {
            if (ip != null && maskedHost.equals(maskingService.maskIp(ip))) {
                out.add(ip);
            }
        }
        return out.toArray(new String[0]);
    }

    /**
     * 고르는 순서: 이 인시던트 발생 시각과의 차 절댓값 오름차순(어느 한쪽 발생 시각이 없으면 맨 뒤) → 탐지 시각 최근(없음은 뒤)
     * → 캡처 ID → 캡처 안 순위.
     */
    static Comparator<UnifiedQueueRecord> pickOrder(Instant self) {
        Comparator<UnifiedQueueRecord> byGap = Comparator.comparing(
                r -> self == null || r.getEventStart() == null
                        ? null : Duration.between(self, r.getEventStart().toInstant()).abs(),
                Comparator.nullsLast(Comparator.naturalOrder()));
        return byGap
                .thenComparing(r -> instant(r.getDetectedAt()), Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(UnifiedQueueRecord::getCaptureId, Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparing(UnifiedQueueRecord::getQueueRank, Comparator.nullsLast(Comparator.naturalOrder()));
    }

    /** 응답 순서: 발생 시각 최근(없음은 뒤) → 캡처 ID → 캡처 안 순위 */
    static final Comparator<UnifiedQueueRecord> SHOW_ORDER = Comparator
            .comparing((UnifiedQueueRecord r) -> instant(r.getEventStart()), Comparator.nullsLast(Comparator.reverseOrder()))
            .thenComparing(UnifiedQueueRecord::getCaptureId, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(UnifiedQueueRecord::getQueueRank, Comparator.nullsLast(Comparator.naturalOrder()));

    private static Instant instant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }
}
