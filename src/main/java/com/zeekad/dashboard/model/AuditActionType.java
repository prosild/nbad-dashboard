package com.zeekad.dashboard.model;

/**
 * 감사 로그 액션 유형.
 */
public enum AuditActionType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ACCOUNT_LOCKED,
    TOTP_VERIFIED,
    ACCESS_DENIED_IDOR,
    INCIDENT_VIEW_UNMASKED,
    INCIDENT_STATUS_TRANSITION,
    USER_ADMIN_CHANGE
}
