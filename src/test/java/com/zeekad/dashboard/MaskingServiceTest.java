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
}
