package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.IncidentRef;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 인시던트 번호(T27) 매퍼. 대시보드 자체 DB만 읽고 쓴다. 추가만 한다(UPDATE·DELETE는 트리거가 막는다).
 */
@Mapper
public interface IncidentRefMapper {

    /** incident_id 배열 하나(= ANY)로 읽는다. 목록이 크면 서비스가 나눠 부른다. */
    List<IncidentRef> findByIncidentIds(@Param("incidentIds") String[] incidentIds);

    IncidentRef findByNo(@Param("incidentNo") long incidentNo);

    /** 같은 incident_id가 이미 있으면 아무것도 하지 않고 0을 돌려준다(PostgreSQL 트랜잭션을 깨지 않는다). */
    int insertIfAbsent(@Param("incidentId") String incidentId,
                       @Param("captureId") String captureId,
                       @Param("detectedAt") OffsetDateTime detectedAt,
                       @Param("createdAt") OffsetDateTime createdAt);
}
