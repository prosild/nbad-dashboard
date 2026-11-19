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
}
