package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * GET /api/incidents/queue 응답(T23).
 * summary는 띠 축(우선순위·에스컬레이션 대기·경보 발송)을 뺀 거르기를 적용한 집합의 수, total은 모든 거르기를 적용한 수다.
 * T29: outsidePeriod는 지금 조건(띠 축 포함)에서 기간만 전체로 넓히면 더 보이는 수(기간 전체 total − total)다.
 * 탐지 시각 없음·기준 시각 뒤 행도 들어간다. 기간이 전체면 0, 자산 검색 상한을 넘어 알 수 없으면 null이다.
 * newestOutsidePeriod는 기간 시작 이하에 탐지된 행(같은 조건)의 가장 늦은 탐지 시각이다(결과가 있어도 준다).
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
        Long outsidePeriod,
        List<Source> sources,
        boolean maskedView,
        List<String> availableModels,
        List<String> availableRoles
) {
    /** overdue(T25): 착수 지연 수. 다른 띠 축과 같이 띠 축을 뺀 집합에서 센다. */
    public record Summary(long total, long high, long medium, long low, long reviewPending, long alerted,
                          Map<String, Long> byStatus, long overdue) {
    }

    /** lastDetectedAt(T29): 그 수집원 최신 큐 인시던트의 가장 늦은 탐지 시각(없으면 null) */
    public record Source(String captureId, String sourceType, Long latestJobId, OffsetDateTime lastDetectedAt) {
    }
}
