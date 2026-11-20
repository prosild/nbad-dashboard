package com.zeekad.dashboard.service;

import java.sql.SQLException;

/**
 * PostgreSQL/H2 함수 호출 예외에서 SQLSTATE를 추출하고 사용자에게 노출할 메시지를 안전하게 정제한다.
 */
final class SqlErrorSanitizer {

    static final String REFRESH_GUIDE = " 화면을 새로고침하여 최신 상태를 확인해 주세요.";

    private SqlErrorSanitizer() {
    }

    static SQLException findSqlException(Throwable ex) {
        SQLException fallback = null;
        Throwable current = ex;
        while (current != null) {
            if (current instanceof SQLException sqlEx) {
                String state = sqlEx.getSQLState();
                if ("22023".equals(state) || "02000".equals(state)) {
                    return sqlEx;
                }
                if (fallback == null) {
                    fallback = sqlEx;
                }
                if (sqlEx.getNextException() != null) {
                    SQLException next = findInChain(sqlEx.getNextException());
                    if (next != null) {
                        return next;
                    }
                }
            }
            current = current.getCause();
        }
        return fallback;
    }

    private static SQLException findInChain(SQLException sqlEx) {
        SQLException current = sqlEx;
        while (current != null) {
            if ("22023".equals(current.getSQLState()) || "02000".equals(current.getSQLState())) {
                return current;
            }
            current = current.getNextException();
        }
        return null;
    }

    /**
     * 메시지에 새로고침 안내가 없을 때만 {@link #REFRESH_GUIDE}를 한 번 붙인다(DB 함수 문구에 이미 안내가 있으면 그대로 둔다).
     */
    static String withRefreshGuide(String message) {
        if (message.contains("새로고침")) {
            return message;
        }
        return message + REFRESH_GUIDE;
    }

    static String sanitizeSqlMessage(String rawMessage, String fallbackMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return fallbackMessage;
        }
        String cleaned = rawMessage;
        int sqlIdx = cleaned.indexOf("; SQL statement:");
        if (sqlIdx >= 0) {
            cleaned = cleaned.substring(0, sqlIdx);
        }
        int whereIdx = cleaned.indexOf("\n  Where:");
        if (whereIdx >= 0) {
            cleaned = cleaned.substring(0, whereIdx);
        }
        int lineIdx = cleaned.indexOf('\n');
        if (lineIdx >= 0) {
            cleaned = cleaned.substring(0, lineIdx);
        }
        cleaned = cleaned.replaceFirst("^ERROR:\\s*", "");
        cleaned = cleaned.replaceFirst("^Exception calling user-defined function:\\s*\"?[^\"]*\"?:\\s*", "");
        cleaned = cleaned.replaceFirst("\\s*\\[\\d+-\\d+]\\s*$", "");
        cleaned = cleaned.trim();

        if (cleaned.isEmpty()
                || cleaned.contains("java.")
                || cleaned.contains("org.springframework.")
                || cleaned.contains("org.h2.")
                || cleaned.contains("SELECT ")
                || cleaned.contains("Exception")) {
            return fallbackMessage;
        }
        return cleaned;
    }
}
