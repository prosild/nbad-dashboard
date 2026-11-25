package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * GET /api/dashboard/overview 응답(T24). 기간·수집원 조건 안의 탐지 추이, 센서·캡처 상태, 경보 발송 상태.
 * 수(summary)는 넣지 않는다: 화면은 같은 조건 큐 API의 summary를 쓴다.
 * 불변식: buckets 합 + unbucketed 합 = 같은 조건 큐 summary.total = captures[].total 합, 센서 total = 그 센서 캡처 행 합.
 * T34: periodStart·periodEnd는 큐 응답과 같다(UTC, 전체면 null).
 * T45b: 같은 조건의 큐 행에서 센 ATT&amp;CK 전술·기법 후보 분포(attack), 통신 방향별 위험 호스트 상위(topHosts),
 * 주요 알림 묶음 상위(topThreads). 각 수는 눌러서 가는 같은 조건 큐(attack·role+hostIp·thread 조건)의 total과 같다.
 * VIEWER 응답의 호스트는 가려진 값(A.B.*.*)이고 그 값으로 묶는다.
 */
public record DashboardOverviewResponse(
        OffsetDateTime anchor,
        String anchorMode,
        boolean snapshot,
        String period,
        OffsetDateTime periodStart,
        OffsetDateTime periodEnd,
        String timeZone,
        long staleAfterSeconds,
        long downAfterSeconds,
        Trend trend,
        List<SensorRow> sensors,
        List<CaptureRow> captures,
        Alerting alerting,
        boolean maskedView,
        Attack attack,
        TopHosts topHosts,
        List<ThreadRow> topThreads,
        boolean topThreadsOmitted
) {
    /**
     * ATT&amp;CK 후보 분포. 수는 모두 큐 행 수다. incidentsWithCandidates = 아래에서 센 전술·기법이 하나라도 있는 인시던트 수,
     * tactics = 전부(count DESC, tactic ASC), techniques = 상위 10개(count DESC, attackId ASC), techniqueCount = 고유 기법 수 전체.
     */
    public record Attack(long incidentsWithCandidates, List<TacticCount> tactics, List<TechniqueCount> techniques,
                         int techniqueCount) {
    }

    /** tactic = 전술 슬러그. count = 같은 조건 큐 attack=슬러그의 total */
    public record TacticCount(String tactic, long count) {
    }

    /** attackId = 대문자 기법 ID, name = 그 ID에 가장 많이 붙은 후보 이름(없으면 null). count = 같은 조건 큐 attack=ID의 total */
    public record TechniqueCount(String attackId, String name, long count) {
    }

    /** 통신 방향(zeekad_role)별 상위 5 */
    public record TopHosts(List<HostRow> originator, List<HostRow> responder) {
    }

    /**
     * high·medium·low = 미종결 우선순위별 건수, total = 종결 포함 전체(같은 조건 큐 role=방향&amp;hostIp=hostIp의 total).
     * hostIp는 VIEWER면 가려진 값이고 그 값이 묶는 단위다.
     */
    public record HostRow(String hostIp, long high, long medium, long low, long total, OffsetDateTime lastDetectedAt) {
    }

    /**
     * 알림 묶음(Slack 스레드) 한 줄. periodIncidentCount = 조건 안 구성원 행 수, totalMemberCount = 허용 캡처 전체 최신 큐의
     * 구성원 수(큐 period=all&amp;thread=headIncidentNo의 total). headHostIp·headPickedBy는 머리의 최신 큐 행이 없으면 null.
     */
    public record ThreadRow(long headIncidentNo, String headHostIp, String headPickedBy, long periodIncidentCount,
                            long totalMemberCount, OffsetDateTime latestDetectedAt) {
    }

    /** bucket = 5m·1h·6h·1d·1w */
    public record Trend(String bucket, List<Bucket> buckets, Unbucketed unbucketed) {
    }

    /** 구간 (start, end], UTC. partial = 구간 일부만 기간 안 */
    public record Bucket(OffsetDateTime start, OffsetDateTime end, boolean partial,
                         long high, long medium, long low, long none, long total) {
    }

    /** 구간에 들지 않는 행(기간 all, 또는 끝이 기준 시각 뒤인 T34 지정 기간에서 생긴다): 탐지 시각 없음, 기준 시각 뒤 */
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
