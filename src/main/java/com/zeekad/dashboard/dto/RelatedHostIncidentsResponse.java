package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * GET /api/incidents/{jobId}/rank/{queueRank}/related-host-incidents 응답(T46).
 * 허용 캡처 전체의 최신 큐에서 같은 호스트(조회자는 같은 대역 A.B.*.*)의 다른 인시던트다.
 * hostIp는 이 인시던트의 호스트(조회자는 가린 값), total은 자신을 뺀 전체 건수, items는 발생 시각이 가까운 최대 10건을
 * 발생 시각 최근 순으로 준다. 원문 incident_id는 싣지 않는다(주소가 들어 있다).
 */
public record RelatedHostIncidentsResponse(
        String hostIp,
        long total,
        List<Item> items,
        boolean maskedView
) {
    /**
     * incidentNo는 번호 행이 있을 때만(없으면 null이고 화면은 jobId·queueRank로 잇는다). priority는 종결이면 null.
     * T52: assetCritical·priorityBase는 두 역할 모두에게, criticalAssetName은 분석가·관리자에게만(조회자는 null).
     */
    public record Item(
            Long incidentNo,
            Long jobId,
            Integer queueRank,
            String captureId,
            String hostIp,
            String zeekadRole,
            OffsetDateTime eventStart,
            OffsetDateTime detectedAt,
            String priority,
            String zeekadStatus,
            String zeekadResolution,
            String zeekadPickedBy,
            Long connectionCount,
            boolean assetCritical,
            String priorityBase,
            String criticalAssetName
    ) {
    }
}
