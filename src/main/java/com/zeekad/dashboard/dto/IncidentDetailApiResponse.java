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
        IncidentQueueMeta queueMeta,
        /* T25: 현재 담당, 담당 이력(시간 역순), 담당을 바꿀 수 있는지(ANALYST·ADMIN이고 종결이 아님) */
        AssignmentDtos.Assignment assignment,
        java.util.List<AssignmentDtos.HistoryItem> assignmentHistory,
        boolean canAssign,
        /* T27: 인시던트 번호(매기지 못했으면 null) */
        Long incidentNo
) {
}
