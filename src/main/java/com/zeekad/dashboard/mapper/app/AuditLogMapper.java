package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.AuditLog;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 불변 감사 로그 매퍼 (INSERT 및 SELECT 전용).
 */
@Mapper
public interface AuditLogMapper {

    void insertAuditLog(AuditLog log);

    List<AuditLog> findFiltered(@Param("actionType") String actionType,
                                @Param("actorUsername") String actorUsername,
                                @Param("limit") int limit);
}
