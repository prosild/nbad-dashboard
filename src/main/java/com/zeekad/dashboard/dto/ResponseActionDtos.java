package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;

/**
 * 대응 조치 기록(T56) API 모양.
 */
public final class ResponseActionDtos {

    private ResponseActionDtos() {
    }

    /** POST .../response-actions 본문. action은 일곱 값 가운데 하나, note는 none·other일 때 필수 */
    public record RecordRequest(String action, String note) {
    }

    /**
     * 상세의 조치 기록 한 행. recordedAt은 조치한 시각이 아니라 기록한 시각이다.
     * note는 분석가·관리자에게만 내린다(조회자는 null. 서버에서 뺀다).
     */
    public record Item(String action, String note, String actorDisplay, OffsetDateTime recordedAt) {
    }
}
