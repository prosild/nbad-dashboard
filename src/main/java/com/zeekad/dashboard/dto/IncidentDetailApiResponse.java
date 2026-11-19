package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.service.IncidentDetailView;

/**
 * 사건 상세 API 응답 DTO.
 */
public record IncidentDetailApiResponse(
        boolean maskedView,
        boolean canDecideReview,
        IncidentDetailView detail
) {
}
