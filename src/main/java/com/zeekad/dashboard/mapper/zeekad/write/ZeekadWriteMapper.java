package com.zeekad.dashboard.mapper.zeekad.write;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * zeekad 쓰기 전용 DataSource 상태 전이·분석가 검토 결정 함수 호출 매퍼.
 * 모든 파라미터 바인딩에 #{}만 사용한다.
 */
@Mapper
public interface ZeekadWriteMapper {

    String transitionIncident(@Param("jobId") Long jobId,
                              @Param("incidentId") String incidentId,
                              @Param("toStatus") String toStatus,
                              @Param("loginUser") String loginUser,
                              @Param("reason") String reason,
                              @Param("resolution") String resolution);

    String decideReview(@Param("jobId") Long jobId,
                        @Param("incidentId") String incidentId,
                        @Param("action") String action,
                        @Param("analyst") String analyst,
                        @Param("note") String note);

    /**
     * T53 종결한 사건 다시 열기(zeek_AD migration 018, dashboard.reopen_incident). closed일 때만 investigating으로 돌리고
     * 판정을 비우며 이력에 closed → investigating 한 행을 남긴다. expectedResolution이 지금 판정과 다르면 22023.
     */
    String reopenIncident(@Param("jobId") Long jobId,
                          @Param("incidentId") String incidentId,
                          @Param("loginUser") String loginUser,
                          @Param("reason") String reason,
                          @Param("expectedResolution") String expectedResolution);
}
