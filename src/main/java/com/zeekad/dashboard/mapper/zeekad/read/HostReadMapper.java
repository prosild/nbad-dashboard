package com.zeekad.dashboard.mapper.zeekad.read;

import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

/**
 * 호스트 위험도 화면과 상세의 같은 호스트 인시던트(T46)가 쓰는 읽기 전용 질의.
 * 모든 값은 바인드 변수로만 넘긴다. captureIds·c.captureIds·hostIps가 비어 있으면 부르지 않는다(호출 쪽이 막는다).
 */
@Mapper
public interface HostReadMapper {

    /**
     * 캡처 목록 안에서 주어진 호스트 주소의 dashboard.asset_names 행(모든 열).
     * 캡처와 주소를 따로 거르므로 (캡처, 주소) 쌍이 맞는지는 호출 쪽이 다시 본다.
     */
    List<Map<String, Object>> findRawAssetNamesForHosts(@Param("captureIds") List<String> captureIds,
                                                        @Param("hostIps") String[] hostIps);

    /** 캡처 목록의 최신 큐에 나오는 호스트 주소(중복 없이) */
    List<String> findDistinctLatestHostIps(@Param("captureIds") List<String> captureIds);

    /**
     * 허용 캡처(c.captureIds) 최신 큐에서 host_ip가 hostIps 안인 행. 우선순위·탐지 시각은 통합 큐와 같은 식(unifiedQueueBase)에서 읽는다.
     * excludeIncidentId가 있으면 그 incident_id 행을 뺀다. c의 다른 조건(기간·정렬·쪽)은 쓰지 않는다.
     */
    List<UnifiedQueueRecord> findLatestQueueByHostIps(@Param("c") UnifiedQueueCriteria criteria,
                                                      @Param("hostIps") String[] hostIps,
                                                      @Param("excludeIncidentId") String excludeIncidentId);
}
