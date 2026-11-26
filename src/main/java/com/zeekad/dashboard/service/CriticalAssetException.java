package com.zeekad.dashboard.service;

/**
 * T52 중요 자산 관리 요청의 오류(상태 코드와 오류 코드). 메시지에 입력 값을 넣지 않는다.
 */
public class CriticalAssetException extends RuntimeException {

    private final int status;
    private final String code;

    public CriticalAssetException(int status, String code, String message) {
        super(message, null, false, false);
        this.status = status;
        this.code = code;
    }

    public int getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }
}
