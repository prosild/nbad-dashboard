package com.zeekad.dashboard.dto;

/**
 * 승인 대기 목록 분석가 검토 결정 요청 DTO.
 */
public record ReviewDecideRequest(Long jobId, String incidentId, String action, String note) {
}
