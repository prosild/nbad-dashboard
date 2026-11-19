package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;

import java.util.List;

/**
 * 관리자 감사 로그 목록 응답 DTO.
 */
public record AdminAuditLogsResponse(
        List<AuditLog> logs,
        List<AuditActionType> actionTypes,
        String selectedActionType,
        String selectedActorUsername,
        int selectedLimit
) {
}
