package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;

import java.util.List;

/**
 * 분석가 승인 대기 목록 API 응답 DTO.
 */
public record ReviewsApiResponse(
        boolean maskedView,
        boolean canDecideReview,
        List<String> allowedCaptures,
        String selectedCaptureId,
        boolean pendingOnly,
        List<AnalystReviewItem> reviews
) {
}
