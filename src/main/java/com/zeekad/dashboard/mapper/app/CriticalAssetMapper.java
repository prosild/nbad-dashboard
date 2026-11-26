package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.CriticalAsset;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * T52 중요 자산 매퍼. 대시보드 자체 DB만 읽고 쓴다.
 */
@Mapper
public interface CriticalAssetMapper {

    /** 관리자 목록(설명 포함) */
    List<CriticalAsset> findAll();

    /**
     * 인시던트 응답이 쓰는 스냅샷: 주소와 이름만 읽는다(설명은 읽지 않는다).
     * 요청 하나에 한 번만 부른다(CriticalAssetService.snapshot).
     */
    List<CriticalAsset> findHostNames();

    CriticalAsset findById(@Param("id") long id);

    CriticalAsset findByHostIp(@Param("hostIp") String hostIp);

    long countAll();

    /** 같은 주소가 이미 있으면 아무것도 하지 않고 0을 돌려준다(UNIQUE 위반 예외 없음) */
    int insertIfAbsent(CriticalAsset asset);

    int updateNameAndDescription(@Param("id") long id,
                                 @Param("name") String name,
                                 @Param("description") String description,
                                 @Param("updatedBy") String updatedBy,
                                 @Param("updatedAt") OffsetDateTime updatedAt);

    int deleteById(@Param("id") long id);
}
