package com.zeekad.dashboard.mapper.zeekad.read;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

/**
 * zeekad 읽기 전용 DataSource 연결 확인용 기본 매퍼.
 */
@Mapper
public interface ZeekadReadProbeMapper {

    @Select("SELECT 1")
    int selectOne();
}
