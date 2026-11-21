package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;

/** GET /api/incidents/queue/new-count 응답(T23): since보다 탐지 시각이 엄격히 늦은 인시던트 수와 그 최대 탐지 시각. */
public record QueueNewCountResponse(long count, OffsetDateTime latestDetectedAt, OffsetDateTime since) {
}
