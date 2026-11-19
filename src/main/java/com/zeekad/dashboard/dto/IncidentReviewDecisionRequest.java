package com.zeekad.dashboard.dto;

/**
 * 사건 상세 내 분석가 검토 결정 요청 DTO.
 */
public record IncidentReviewDecisionRequest(String action, String note) {
}
