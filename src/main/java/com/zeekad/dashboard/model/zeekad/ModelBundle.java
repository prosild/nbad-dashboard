package com.zeekad.dashboard.model.zeekad;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * dashboard.model_bundles 뷰 DTO.
 */
public class ModelBundle {

    private String bundleId;
    private String registryName;
    private String registryVersion;
    private String manifestSha256;
    private OffsetDateTime registeredAt;
    private JsonNode thresholds;

    public String getBundleId() {
        return bundleId;
    }

    public void setBundleId(String bundleId) {
        this.bundleId = bundleId;
    }

    public String getRegistryName() {
        return registryName;
    }

    public void setRegistryName(String registryName) {
        this.registryName = registryName;
    }

    public String getRegistryVersion() {
        return registryVersion;
    }

    public void setRegistryVersion(String registryVersion) {
        this.registryVersion = registryVersion;
    }

    public String getManifestSha256() {
        return manifestSha256;
    }

    public void setManifestSha256(String manifestSha256) {
        this.manifestSha256 = manifestSha256;
    }

    public OffsetDateTime getRegisteredAt() {
        return registeredAt;
    }

    public void setRegisteredAt(OffsetDateTime registeredAt) {
        this.registeredAt = registeredAt;
    }

    public JsonNode getThresholds() {
        return thresholds;
    }

    public void setThresholds(JsonNode thresholds) {
        this.thresholds = thresholds;
    }

    public Map<String, String> getThresholdEntries() {
        if (thresholds == null || !thresholds.isObject()) {
            return Collections.emptyMap();
        }
        Map<String, String> map = new LinkedHashMap<>();
        thresholds.fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
        return Collections.unmodifiableMap(map);
    }
}
