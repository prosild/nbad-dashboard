package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * GET /api/dashboard/overview 응답(T24). 기간·수집원 조건 안의 탐지 추이, 센서·캡처 상태, 경보 발송 상태.
 * 수(summary)는 넣지 않는다: 화면은 같은 조건 큐 API의 summary를 쓴다.
 * 불변식: buckets 합 + unbucketed 합 = 같은 조건 큐 summary.total = captures[].total 합, 센서 total = 그 센서 캡처 행 합.
 */
public record DashboardOverviewResponse(
        OffsetDateTime anchor,
        String anchorMode,
        boolean snapshot,
        String period,
        String timeZone,
        long staleAfterSeconds,
        long downAfterSeconds,
        Trend trend,
        List<SensorRow> sensors,
        List<CaptureRow> captures,
        Alerting alerting,
        boolean maskedView
) {
    /** bucket = 5m·1h·6h·1d·1w */
    public record Trend(String bucket, List<Bucket> buckets, Unbucketed unbucketed) {
    }

    /** 구간 (start, end], UTC. partial = 구간 일부만 기간 안 */
    public record Bucket(OffsetDateTime start, OffsetDateTime end, boolean partial,
                         long high, long medium, long low, long none, long total) {
    }

    /** 구간에 들지 않는 행(기간 all에서만 생긴다): 탐지 시각 없음, 기준 시각 뒤 */
    public record Unbucketed(long noDetectedAt, long afterAnchor) {
    }

    /** 탐지 작업 요약. VIEWER면 error의 IPv4가 가려진다 */
    public record JobRef(Long jobId, String captureId, String bundleId, String status,
                         OffsetDateTime startedAt, OffsetDateTime finishedAt, String error) {
    }

    /** health = ok·stale·down·failed·none */
    public record SensorRow(String sensorKey,
                            String label,
                            String health,
                            JobRef latestJob,
                            String activeCaptureId,
                            OffsetDateTime lastScoredAt,
                            OffsetDateTime lastActivityAt,
                            long total,
                            long high,
                            long alerted,
                            long failedJobs,
                            int captureCount) {
    }

    /** state = active·ended·imported·failed·none */
    public record CaptureRow(String captureId,
                             String sourceType,
                             String sensorKey,
                             String state,
                             JobRef latestJob,
                             OffsetDateTime lastScoredAt,
                             OffsetDateTime lastActivityAt,
                             long total,
                             long high,
                             long alerted,
                             long failedJobs) {
    }

    /** 가장 최근 일일 요약(기간 무관, 같은 조건 수집원)과 기간 안 일일 요약 수 */
    public record Alerting(String latestDeliveryMode,
                           String latestDeliveryStatus,
                           boolean latestDryRun,
                           OffsetDateTime latestCreatedAt,
                           OffsetDateTime latestDeliveredAt,
                           String latestCaptureId,
                           long summariesInPeriod) {
    }
}
