package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * GET /api/hosts 응답(T46). 현황판과 같은 조건(기간·수집원·캡처)의 최신 큐 행을 호스트로 묶은 목록이다.
 * 분석가·관리자는 원문 host_ip 단위, 조회자는 가려진 주소(A.B.*.*) 단위로 묶는다(조회자 한 줄은 같은 대역의 호스트 전부다).
 * total은 검색·전환 거르기를 적용한 뒤의 줄 수다. anchor·period·periodStart·periodEnd는 현황판·운영 현황 응답과 같은 뜻이고
 * sources는 조건 줄의 수집원 선택지(허용 캡처 전체)다.
 * 불변식: 거르지 않은 줄들의 incidents 합 = 같은 조건 큐 summary.total.
 */
public record HostRiskResponse(
        List<Item> items,
        long total,
        int page,
        int size,
        int pageCount,
        OffsetDateTime anchor,
        String anchorMode,
        boolean snapshot,
        String period,
        OffsetDateTime periodStart,
        OffsetDateTime periodEnd,
        List<UnifiedQueueResponse.Source> sources,
        boolean maskedView
) {
    /**
     * 한 호스트(조회자는 한 대역).
     * hostNames·accounts는 글자 순 앞 5개이고 hostNameCount·accountCount가 전체 수다.
     * high·medium·low는 미종결 우선순위별 건수(종결은 우선순위가 없다), incidents는 종결 포함 전체다.
     * models는 탐지 모델 식별자(건수 많은 순, 같으면 식별자 오름차순)다.
     * roleTransition은 같은 캡처에서 목적지로 탐지된 뒤 출발지로 탐지됐는지다(조회자는 늘 false).
     */
    public record Item(
            String hostIp,
            List<String> hostNames,
            int hostNameCount,
            List<String> accounts,
            int accountCount,
            long high,
            long medium,
            long low,
            long incidents,
            long connections,
            List<String> models,
            OffsetDateTime lastDetectedAt,
            boolean roleTransition
    ) {
    }
}
