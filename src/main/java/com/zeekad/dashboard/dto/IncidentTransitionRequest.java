package com.zeekad.dashboard.dto;

/**
 * 사건 상태 전이 요청 DTO.
 */
public record IncidentTransitionRequest(String toStatus, String resolution, String reason) {
}
