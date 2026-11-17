package com.zeekad.dashboard.mapper.zeekad.write;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

/**
 * zeekad 쓰기 전용 DataSource 연결 확인용 기본 매퍼.
 */
@Mapper
public interface ZeekadWriteProbeMapper {

    @Select("SELECT 1")
    int selectOne();
}
