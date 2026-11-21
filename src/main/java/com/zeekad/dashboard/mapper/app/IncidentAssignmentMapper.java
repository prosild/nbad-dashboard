package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.IncidentAssignment;
import com.zeekad.dashboard.model.IncidentAssignmentHistory;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 인시던트 담당(T25) 매퍼. 대시보드 자체 DB만 읽고 쓴다.
 */
@Mapper
public interface IncidentAssignmentMapper {

    IncidentAssignment findByIncidentId(@Param("incidentId") String incidentId);

    /** 담당자가 있는 행만(해제된 행 제외), users를 붙여서. 목록이 크면 서비스가 나눠 부른다. */
    List<IncidentAssignment> findAssignedByIncidentIds(@Param("incidentIds") List<String> incidentIds);

    /** 담당자가 있는 모든 행(incident_id·capture_id·assignee_user_id). userId가 있으면 그 사용자 것만. */
    List<IncidentAssignment> findAssignedRows(@Param("userId") Long userId);

    /** 첫 지정. 같은 incident_id 행이 이미 있으면 아무것도 하지 않고 0을 돌려준다(PK 위반 예외 없음). */
    int insertIfAbsent(@Param("incidentId") String incidentId,
                       @Param("captureId") String captureId,
                       @Param("assigneeUserId") Long assigneeUserId,
                       @Param("assignedAt") OffsetDateTime assignedAt,
                       @Param("assignedBy") String assignedBy);

    /** version이 같을 때만 바꾸고 version을 1 올린다. 바뀐 행 수(0이면 그 사이 다른 변경). */
    int updateIfVersion(@Param("incidentId") String incidentId,
                        @Param("assigneeUserId") Long assigneeUserId,
                        @Param("assignedAt") OffsetDateTime assignedAt,
                        @Param("assignedBy") String assignedBy,
                        @Param("expectedVersion") int expectedVersion);

    void insertHistory(IncidentAssignmentHistory history);

    /** 한 인시던트의 이력(시간 역순), users를 붙여서 */
    List<IncidentAssignmentHistory> findHistory(@Param("incidentId") String incidentId);
}
