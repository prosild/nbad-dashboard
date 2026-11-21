package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.service.IncidentDetailView;

/**
 * 사건 상세 API 응답 DTO.
 */
public record IncidentDetailApiResponse(
        boolean maskedView,
        boolean canDecideReview,
        IncidentDetailView detail,
        /* T23: 수집원·탐지 시각·서버 우선순위·진행 중 */
        IncidentQueueMeta queueMeta
) {
}
