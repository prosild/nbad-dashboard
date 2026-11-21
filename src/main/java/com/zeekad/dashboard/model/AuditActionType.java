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
    ANALYST_REVIEW_DECISION,
    /** T25 담당자 지정·변경·해제(조사 시작 때 자동 지정 포함) */
    INCIDENT_ASSIGNMENT,
    USER_ADMIN_CHANGE
}
