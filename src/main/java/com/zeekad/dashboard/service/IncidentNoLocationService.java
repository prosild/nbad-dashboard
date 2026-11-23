package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.IncidentRef;
import com.zeekad.dashboard.model.zeekad.IncidentLocation;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

/**
 * T27 번호 API(GET /api/incidents/no/{incidentNo}): 인시던트 번호 → 지금 위치(작업·순위).
 * 성공한 조회는 감사하지 않는다(가리지 않은 보기 감사는 상세 API가 남긴다). 모든 역할이 쓴다.
 */
@Service
public class IncidentNoLocationService {

    private static final Pattern DIGITS = Pattern.compile("[0-9]{1,19}");

    private final IncidentRefService incidentRefService;
    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;

    public IncidentNoLocationService(IncidentRefService incidentRefService,
                                     ZeekadReadMapper zeekadReadMapper,
                                     CaptureAccessService captureAccessService) {
        this.incidentRefService = incidentRefService;
        this.zeekadReadMapper = zeekadReadMapper;
        this.captureAccessService = captureAccessService;
    }

    /** latest = 최신 큐 위치인지(false면 그 인시던트가 든 가장 최근 성공 작업 위치) */
    public record Location(long incidentNo, long jobId, int queueRank, boolean latest) {
    }

    public Location locate(DashboardUserPrincipal principal, String rawNo, String clientIp) {
        long no = parse(rawNo);
        IncidentRef ref = incidentRefService.findByNo(no);
        if (ref == null) {
            captureAccessService.denyIncidentNo(principal, null, no, "incident_no_not_found", clientIp);
        }
        if (principal == null || !principal.isCaptureAllowed(ref.getCaptureId())) {
            captureAccessService.denyIncidentNo(principal, ref.getCaptureId(), no, "incident_no_capture_denied", clientIp);
        }
        IncidentLocation latest = zeekadReadMapper.findLatestLocationByIncidentId(ref.getIncidentId());
        if (isComplete(latest)) {
            return new Location(no, latest.getJobId(), latest.getQueueRank(), true);
        }
        IncidentLocation last = zeekadReadMapper.findLastSucceededLocationByIncidentId(ref.getIncidentId());
        if (isComplete(last)) {
            return new Location(no, last.getJobId(), last.getQueueRank(), false);
        }
        captureAccessService.denyIncidentNo(principal, ref.getCaptureId(), no, "incident_no_not_in_zeekad", clientIp);
        throw new IllegalStateException("unreachable");
    }

    /** T40 큐 thread 조건의 번호: 번호 API와 같은 형식 검사(400, 감사 없음) */
    public static long parseThreadNo(String raw) {
        return parse(raw);
    }

    /** 양의 정수(Long 범위)만. 숫자가 아님·0 이하·범위 초과는 400(감사 없음) */
    static long parse(String raw) {
        String s = raw == null ? "" : raw.trim();
        if (!DIGITS.matcher(s).matches()) {
            throw invalid();
        }
        long n;
        try {
            n = Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw invalid();
        }
        if (n <= 0) {
            throw invalid();
        }
        return n;
    }

    private static boolean isComplete(IncidentLocation l) {
        return l != null && l.getJobId() != null && l.getQueueRank() != null;
    }

    private static QueueQueryException invalid() {
        return new QueueQueryException("INVALID_REQUEST", "인시던트 번호 형식이 올바르지 않습니다.");
    }
}
