package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * GET /api/incidents/queue 응답(T23).
 * summary는 띠 축(우선순위·에스컬레이션 대기·경보 발송)을 뺀 거르기를 적용한 집합의 수, total은 모든 거르기를 적용한 수다.
 */
public record UnifiedQueueResponse(
        List<UnifiedQueueRow> items,
        long total,
        int page,
        int size,
        int pageCount,
        Summary summary,
        OffsetDateTime anchor,
        String anchorMode,
        boolean snapshot,
        String period,
        OffsetDateTime latestDetectedAt,
        OffsetDateTime newestOutsidePeriod,
        List<Source> sources,
        boolean maskedView,
        List<String> availableModels,
        List<String> availableRoles
) {
    /** overdue(T25): 착수 지연 수. 다른 띠 축과 같이 띠 축을 뺀 집합에서 센다. */
    public record Summary(long total, long high, long medium, long low, long reviewPending, long alerted,
                          Map<String, Long> byStatus, long overdue) {
    }

    public record Source(String captureId, String sourceType, Long latestJobId) {
    }
}
