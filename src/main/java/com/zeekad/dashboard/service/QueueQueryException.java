package com.zeekad.dashboard.service;

/**
 * 통합 인시던트 큐(T23) 요청 값 오류. 400과 code로 응답한다(INVALID_REQUEST, QUERY_TOO_BROAD).
 */
public class QueueQueryException extends RuntimeException {

    private final String code;

    public QueueQueryException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
