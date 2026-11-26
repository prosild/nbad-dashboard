package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.IncidentResponseAction;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 대응 조치 기록(T56) 매퍼. 대시보드 자체 DB만 읽고 쓴다. 넣기와 읽기만 있다(고치거나 지우는 문장을 만들지 않는다).
 */
@Mapper
public interface IncidentResponseActionMapper {

    void insert(IncidentResponseAction action);

    /** 한 인시던트의 기록(시간 역순) */
    List<IncidentResponseAction> findByIncidentId(@Param("incidentId") String incidentId);

    int countByIncidentId(@Param("incidentId") String incidentId);
}
