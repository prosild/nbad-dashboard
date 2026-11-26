package com.zeekad.dashboard.model;

import java.time.OffsetDateTime;

/**
 * T52 중요 자산(앱 DB critical_assets 한 행). 관리자 API에만 그대로 나간다.
 * 인시던트 응답에는 이름만(분석가·관리자) 붙이고 설명은 어떤 역할에도 싣지 않는다.
 */
public class CriticalAsset {

    private Long id;
    /** IPv4 한 주소(정확한 꼴. 대역·IPv6·호스트 이름은 받지 않는다) */
    private String hostIp;
    private String name;
    private String description;
    private String createdBy;
    private OffsetDateTime createdAt;
    private String updatedBy;
    private OffsetDateTime updatedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getHostIp() { return hostIp; }
    public void setHostIp(String hostIp) { this.hostIp = hostIp; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }
    public String getUpdatedBy() { return updatedBy; }
    public void setUpdatedBy(String updatedBy) { this.updatedBy = updatedBy; }
    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }
}
