package com.zeekad.dashboard.dto;

/**
 * T53 종결한 인시던트 다시 열기 요청 DTO. expectedResolution은 화면이 보고 있는 판정(필수)이다.
 * 그사이 다른 사람이 다시 열어 다른 판정으로 다시 종결했으면 zeek_AD 함수가 거부한다(오래된 화면이 새 판정을 지우지 않게).
 */
public record IncidentReopenRequest(String reason, String expectedResolution) {
}
