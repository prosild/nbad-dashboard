package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;

/**
 * 상세 헤더 메타데이터(T23): 수집원 종류, 탐지 시각, 서버 우선순위, 진행 중, 같은 incident_id의 최신 큐 행 키.
 * 최신 큐에 그 인시던트가 없으면 detectedAt·priority·latest*는 null이다.
 */
public record IncidentQueueMeta(String sourceType,
                                OffsetDateTime detectedAt,
                                String priority,
                                boolean ongoing,
                                Long latestJobId,
                                Integer latestQueueRank) {
}
