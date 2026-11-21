package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.service.MaskingService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final MaskingService maskingService = new MaskingService(objectMapper);

    @Test
    void masksIpUsernamePseudonymsSlackPayloadAndEvidenceForViewer() throws Exception {
        assertThat(maskingService.maskIp("192.168.10.50")).isEqualTo("192.168.*.*");
        assertThat(maskingService.maskIpsInText("출발지 10.20.30.40 -> 목적지 203.0.113.45"))
                .isEqualTo("출발지 10.20.*.* -> 목적지 203.0.*.*");

        assertThat(maskingService.maskUsername("admin")).isEqualTo("a***");
        assertThat(maskingService.maskUsername("x")).isEqualTo("***");
        assertThat(maskingService.maskUsername(null)).isNull();

        AssetNameRecord rawAsset = new AssetNameRecord();
        rawAsset.setCaptureId("cic17-wed");
        rawAsset.setHostIp("192.168.10.50");
        rawAsset.setKerberosUser("admin");
        rawAsset.setNtlmUser("backup_op");

        AssetNameRecord viewerAsset = maskingService.maskAssetNameRecord(rawAsset, UserRole.VIEWER);
        assertThat(viewerAsset.getHostIp()).isEqualTo("192.168.*.*");
        assertThat(viewerAsset.getKerberosUser()).isEqualTo("a***");
        assertThat(viewerAsset.getNtlmUser()).isEqualTo("b***");

        JsonNode pseudonyms = objectMapper.readTree("{\"H\":\"192.168.10.50\",\"X1\":\"203.0.113.45\"}");
        JsonNode maskedPseudonyms = maskingService.maskPseudonyms(pseudonyms, UserRole.VIEWER);
        assertThat(maskedPseudonyms.get("H").asText()).isEqualTo("192.168.*.*");
        assertThat(maskedPseudonyms.get("X1").asText()).isEqualTo("203.0.*.*");

        SlackSummary summary = new SlackSummary();
        summary.setCaptureId("cic17-wed");
        summary.setSlackPayload(objectMapper.readTree("{\"channel\":\"#sec\",\"text\":\"호스트 192.168.10.50 경보\"}"));
        SlackSummary maskedSummary = maskingService.maskSlackSummary(summary, UserRole.VIEWER);
        assertThat(maskedSummary.getPayloadTextPreview()).isEqualTo("호스트 192.168.*.* 경보");

        EvidenceData evidence = new EvidenceData();
        evidence.setAvailable(true);
        evidence.setTopPeers(List.of(Map.of("ip", "203.0.113.45", "count", 210)));
        evidence.setRepresentativeConnections(List.of(Map.of("orig_h", "192.168.10.50", "resp_h", "203.0.113.45")));
        EvidenceData maskedEvidence = maskingService.maskEvidence(evidence, UserRole.VIEWER);
        assertThat(maskedEvidence.getTopPeers().get(0)).containsEntry("ip", "203.0.*.*");
        assertThat(maskedEvidence.getRepresentativeConnections().get(0))
                .containsEntry("orig_h", "192.168.*.*")
                .containsEntry("resp_h", "203.0.*.*");
    }

    @Test
    void preservesOriginalValuesForAnalystAndAdmin() throws Exception {
        AssetNameRecord rawAsset = new AssetNameRecord();
        rawAsset.setHostIp("192.168.10.50");
        rawAsset.setKerberosUser("admin");
        rawAsset.setNtlmUser("backup_op");

        for (UserRole role : List.of(UserRole.ANALYST, UserRole.ADMIN)) {
            AssetNameRecord unmasked = maskingService.maskAssetNameRecord(rawAsset, role);
            assertThat(unmasked.getHostIp()).isEqualTo("192.168.10.50");
            assertThat(unmasked.getKerberosUser()).isEqualTo("admin");
            assertThat(unmasked.getNtlmUser()).isEqualTo("backup_op");

            JsonNode pseudonyms = objectMapper.readTree("{\"H\":\"192.168.10.50\"}");
            assertThat(maskingService.maskPseudonyms(pseudonyms, role).get("H").asText())
                    .isEqualTo("192.168.10.50");
        }
    }

    @SuppressWarnings("unchecked")
    /** T21: VIEWER 증적 추가 필드 host는 허용 하위 키 ip(마스킹)만 남긴다. 문자열은 마스킹, 그 밖의 형태는 뺀다. */
    @Test
    void viewerEvidenceHostKeepsOnlyMaskedIpSubkey() {
        Map<String, Object> host = new java.util.LinkedHashMap<>();
        host.put("ip", "192.168.10.50");
        host.put("name", List.of("dc01.corp.local"));
        host.put("hostname", "dc01");
        EvidenceData evidence = new EvidenceData();
        evidence.setAvailable(true);
        evidence.setAdditionalFields(Map.of("host", host, "version", "evidence.v1"));

        EvidenceData viewer = maskingService.maskEvidence(evidence, UserRole.VIEWER);
        assertThat(viewer.getAdditionalFields()).containsEntry("version", "evidence.v1");
        assertThat((Map<String, Object>) viewer.getAdditionalFields().get("host"))
                .containsOnlyKeys("ip")
                .containsEntry("ip", "192.168.*.*");

        for (UserRole role : List.of(UserRole.ANALYST, UserRole.ADMIN)) {
            assertThat((Map<String, Object>) maskingService.maskEvidence(evidence, role).getAdditionalFields().get("host"))
                    .containsOnlyKeys("ip", "name", "hostname");
        }

        // 하위 키 ip가 없는 객체 → 빈 객체
        evidence.setAdditionalFields(Map.of("host", Map.of("name", "dc01.corp.local")));
        assertThat((Map<String, Object>) maskingService.maskEvidence(evidence, UserRole.VIEWER).getAdditionalFields().get("host"))
                .isEmpty();

        // 문자열 → IPv4 마스킹
        evidence.setAdditionalFields(Map.of("host", "10.20.30.40 dc01"));
        assertThat(maskingService.maskEvidence(evidence, UserRole.VIEWER).getAdditionalFields())
                .containsEntry("host", "10.20.*.* dc01");

        // 배열·숫자·null → 뺀다
        Map<String, Object> others = new java.util.HashMap<>();
        others.put("host", List.of("10.20.30.40", "dc01"));
        evidence.setAdditionalFields(others);
        assertThat(maskingService.maskEvidence(evidence, UserRole.VIEWER).getAdditionalFields()).doesNotContainKey("host");
        others.put("host", 42);
        assertThat(maskingService.maskEvidence(evidence, UserRole.VIEWER).getAdditionalFields()).doesNotContainKey("host");
        others.put("host", null);
        assertThat(maskingService.maskEvidence(evidence, UserRole.VIEWER).getAdditionalFields()).doesNotContainKey("host");
    }
}
