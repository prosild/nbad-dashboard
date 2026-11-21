package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;

/** GET /api/time-context 응답(T23). 기준 시각은 그 사용자의 허용 캡처로 센다. */
public record TimeContextResponse(OffsetDateTime anchor, String anchorMode, boolean snapshot) {
}
