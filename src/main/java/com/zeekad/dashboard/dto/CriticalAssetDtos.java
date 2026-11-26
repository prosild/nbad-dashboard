package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.CriticalAsset;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * T52 중요 자산 관리자 API의 요청·응답(GET·POST /api/admin/critical-assets, PUT /{id}, POST /{id}/delete).
 */
public final class CriticalAssetDtos {

    private CriticalAssetDtos() {
    }

    /** 추가 요청: 주소(IPv4 하나), 이름, 설명(선택) */
    public record CreateRequest(String hostIp, String name, String description) {
    }

    /** 고치기 요청: 이름과 설명만(본문에 주소가 와도 쓰지 않는다) */
    public record UpdateRequest(String name, String description) {
    }

    public record Item(Long id,
                       String hostIp,
                       String name,
                       String description,
                       String createdBy,
                       OffsetDateTime createdAt,
                       String updatedBy,
                       OffsetDateTime updatedAt) {
        public static Item from(CriticalAsset a) {
            return new Item(a.getId(), a.getHostIp(), a.getName(), a.getDescription(), a.getCreatedBy(),
                    a.getCreatedAt(), a.getUpdatedBy(), a.getUpdatedAt());
        }
    }

    /** 목록과 등록 상한 */
    public record ListResponse(List<Item> items, int limit) {
    }

    public record MutationResponse(String message, Item item) {
    }
}
