package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;

/**
 * 상세 헤더 메타데이터(T23): 수집원 종류, 탐지 시각, 서버 우선순위, 진행 중, 같은 incident_id의 최신 큐 행 키.
 * 최신 큐에 그 인시던트가 없으면 detectedAt·priority·latest*는 null이다.
 * T52: priorityBase(기본 규칙 값), assetCritical(중요 자산 여부), criticalAssetName(분석가·관리자만. 조회자는 늘 null).
 */
public record IncidentQueueMeta(String sourceType,
                                OffsetDateTime detectedAt,
                                String priority,
                                boolean ongoing,
                                Long latestJobId,
                                Integer latestQueueRank,
                                /* T25: 경과를 셀 기준 시각, 착수 목표 시각(대상이 아니면 null), 착수 지연 */
                                OffsetDateTime anchor,
                                OffsetDateTime ackDueAt,
                                boolean ackOverdue,
                                /* T52 */
                                boolean assetCritical,
                                String priorityBase,
                                String criticalAssetName) {
}
