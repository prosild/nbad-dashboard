package com.zeekad.dashboard.dto;

/**
 * GET /api/incidents/queue/neighbors 응답(T23).
 * current = 같은 incident_id의 최신 큐 행(없으면 null). position은 1부터, 거르기 결과에 없으면 null.
 */
public record QueueNeighborsResponse(Key current, Integer position, long total, Key prev, Key next) {

    /** 상세 주소 키. hostIp는 이동 버튼 툴팁용이며 VIEWER에게는 마스킹된 값이다. */
    public record Key(long jobId, int queueRank, String hostIp) {
    }
}
