package com.zeekad.dashboard.model;

/**
 * 감사 로그 액션 유형.
 */
public enum AuditActionType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ACCOUNT_LOCKED,
    TOTP_VERIFIED,
    /** T60 관리자 TOTP 확인 실패: 틀린 코드(reason invalid_code)와 잠긴 계정의 확인 시도(reason account_locked) */
    TOTP_FAILURE,
    ACCESS_DENIED_IDOR,
    INCIDENT_VIEW_UNMASKED,
    INCIDENT_STATUS_TRANSITION,
    ANALYST_REVIEW_DECISION,
    /** T25 담당자 지정·변경·해제(조사 시작 때 자동 지정 포함) */
    INCIDENT_ASSIGNMENT,
    /** T56 대응 조치 기록(상세 {action, note}) */
    INCIDENT_RESPONSE_ACTION,
    USER_ADMIN_CHANGE,
    /**
     * T58 보관 기한이 지난 감사 행 삭제. 앱은 이 값을 쓰지 않는다(조회와 화면 필터에만 쓴다).
     * 행은 DB 함수 purge_expired_audit_logs가 남긴다(행위자 audit-retention, 역할 SYSTEM).
     */
    AUDIT_RETENTION_PURGE
}
