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

    /** T37: 경계는 숫자로만 본다. 영문자·밑줄·점·한글에 붙은 IPv4와 문장 끝 IPv4도 가리고, 더 긴 숫자열은 그대로 둔다. */
    @Test
    void masksIpv4AdjacentToLettersUnderscoreDotAndSentenceEnd() {
        assertThat(maskingService.maskIpsInText("name_198.51.100.13")).isEqualTo("name_198.51.*.*");
        assertThat(maskingService.maskIpsInText("peer.198.51.100.13")).isEqualTo("peer.198.51.*.*");
        assertThat(maskingService.maskIpsInText("host198.51.100.13x")).isEqualTo("host198.51.*.*x");
        assertThat(maskingService.maskIpsInText("접속 주소는 10.0.0.1.")).isEqualTo("접속 주소는 10.0.*.*.");
        assertThat(maskingService.maskIpsInText("10.0.0.1에서 10.0.0.2로")).isEqualTo("10.0.*.*에서 10.0.*.*로");
        assertThat(maskingService.maskIpsInText("X1(203.0.113.45)")).isEqualTo("X1(203.0.*.*)");
        assertThat(maskingService.maskIpsInText("cic17-wed|192.168.10.50|originator|1700000000"))
                .isEqualTo("cic17-wed|192.168.*.*|originator|1700000000");
        // 더 긴 숫자열(다섯 마디, 앞뒤에 숫자)과 범위 밖 옥텟은 IP가 아니다
        assertThat(maskingService.maskIpsInText("1.198.51.100.13")).isEqualTo("1.198.51.100.13");
        assertThat(maskingService.maskIpsInText("198.51.100.13.7")).isEqualTo("198.51.100.13.7");
        assertThat(maskingService.maskIpsInText("1234.5.6.7")).isEqualTo("1234.5.6.7");
        assertThat(maskingService.maskIpsInText("999.1.1.1")).isEqualTo("999.1.1.1");
        assertThat(maskingService.maskIpsInText("버전 evidence.v1, 2.5초")).isEqualTo("버전 evidence.v1, 2.5초");
    }

    /** T37: 객체 키까지 가리는 마스킹. 키가 겹치면 null. 기존 maskJsonIps(가명 맵·Slack 페이로드)는 키를 그대로 둔다(바꾸지 않음). */
    @Test
    void maskJsonIpsIncludingKeysMasksKeysAndReturnsNullOnCollisionWhileMaskJsonIpsKeepsKeys() throws Exception {
        JsonNode node = objectMapper.readTree(
                "{\"10.1.2.3\":{\"k\":[\"10.1.2.4\",{\"10.9.8.7\":\"x 10.1.2.5\"}]},\"n\":1,\"b\":true,\"z\":null}");
        JsonNode masked = maskingService.maskJsonIpsIncludingKeys(node);
        assertThat(masked.toString()).isEqualTo(
                "{\"10.1.*.*\":{\"k\":[\"10.1.*.*\",{\"10.9.*.*\":\"x 10.1.*.*\"}]},\"n\":1,\"b\":true,\"z\":null}");
        assertThat(node.toString()).contains("10.1.2.3");
        assertThat(maskingService.maskJsonIpsIncludingKeys(
                objectMapper.readTree("{\"a\":{\"10.1.1.1\":1,\"10.1.2.2\":2}}"))).isNull();
        assertThat(maskingService.maskJsonIpsIncludingKeys(objectMapper.readTree("[\"10.1.1.1\"]")).toString())
                .isEqualTo("[\"10.1.*.*\"]");
        assertThat(maskingService.maskJsonIpsIncludingKeys(null)).isNull();
        assertThat(maskingService.maskJsonIps(node).toString()).isEqualTo(
                "{\"10.1.2.3\":{\"k\":[\"10.1.*.*\",{\"10.9.8.7\":\"x 10.1.*.*\"}]},\"n\":1,\"b\":true,\"z\":null}");
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

    /* ───────────── T46 관측 계정 이름(zeekad_name) ───────────── */

    private static AssetNameRecord assetWithExtras(Map<String, Object> extras) {
        AssetNameRecord asset = new AssetNameRecord();
        asset.setCaptureId("lab-x");
        asset.setHostIp("10.20.0.15");
        asset.setKerberosUser("admin");
        asset.setNtlmUser("backup_op");
        asset.setExtraAttributes(extras);
        return asset;
    }

    @Test
    void viewerZeekadNameIsMaskedForStringListAndMixedCaseKey() {
        Map<String, Object> extras = new java.util.LinkedHashMap<>();
        extras.put("zeekad_name", "alice.kim");
        extras.put("zeekad_name_kind", "kerberos_client");
        extras.put("source_log", "kerberos 10.20.0.15");
        extras.put("observation_count", 14);
        AssetNameRecord masked = maskingService.maskAssetNameRecord(assetWithExtras(extras), UserRole.VIEWER);
        assertThat(masked.getExtraAttributes()).containsEntry("zeekad_name", "a***");
        // 나머지 키는 지금과 같다: 글은 IPv4만 가리고 숫자는 그대로
        assertThat(masked.getExtraAttributes()).containsEntry("zeekad_name_kind", "kerberos_client");
        assertThat(masked.getExtraAttributes()).containsEntry("source_log", "kerberos 10.20.*.*");
        assertThat(masked.getExtraAttributes()).containsEntry("observation_count", 14);
        assertThat(masked.getKerberosUser()).isEqualTo("a***");
        assertThat(masked.getNtlmUser()).isEqualTo("b***");
        assertThat(masked.getHostIp()).isEqualTo("10.20.*.*");

        // 컴퓨터 계정, 한 글자, 주소가 든 이름, 빈 글
        assertThat(maskedName("WS-01$")).isEqualTo("W***");
        assertThat(maskedName("x")).isEqualTo("***");
        assertThat(maskedName("10.20.0.15")).isEqualTo("1***");
        assertThat(maskedName("svc@10.20.0.15")).isEqualTo("s***");
        assertThat(maskedName("")).isEqualTo("");

        // 리스트 원소마다, 문자열이 아닌 원소도 글로 바꿔 가린다. null 원소는 null
        Map<String, Object> listExtras = new java.util.LinkedHashMap<>();
        listExtras.put("zeekad_name", java.util.Arrays.asList("bob", "WS-02$", 4711, null, List.of("carol", "dave")));
        Object list = maskingService.maskAssetNameRecord(assetWithExtras(listExtras), UserRole.VIEWER)
                .getExtraAttributes().get("zeekad_name");
        assertThat(list).isEqualTo(java.util.Arrays.asList("b***", "W***", "4***", null, "[***"));

        // 대소문자가 다른 키도 같은 규칙(키 글자는 그대로 둔다)
        Map<String, Object> upper = new java.util.LinkedHashMap<>();
        upper.put("ZeekAD_Name", "erin");
        assertThat(maskingService.maskAssetNameRecord(assetWithExtras(upper), UserRole.VIEWER).getExtraAttributes())
                .containsEntry("ZeekAD_Name", "e***");
    }

    @Test
    void viewerZeekadNameOfUnknownTypeIsStringifiedAndMaskedAndNullStaysNull() {
        // 숫자, 맵, 배열 객체처럼 모르는 타입을 그대로 내보내지 않는다
        assertThat(maskedNameObject(90210)).isEqualTo("9***");
        assertThat(maskedNameObject(Map.of("user", "frank"))).isEqualTo("{***");
        Object arrayLike = new Object() {
            @Override
            public String toString() {
                return "{grace,heidi}";
            }
        };
        assertThat(maskedNameObject(arrayLike)).isEqualTo("{***");
        assertThat(maskedNameObject(new String[]{"ivan"})).asString().endsWith("***").doesNotContain("ivan");

        Map<String, Object> nullExtras = new java.util.LinkedHashMap<>();
        nullExtras.put("zeekad_name", null);
        Map<String, Object> out = maskingService.maskAssetNameRecord(assetWithExtras(nullExtras), UserRole.VIEWER)
                .getExtraAttributes();
        assertThat(out).containsKey("zeekad_name");
        assertThat(out.get("zeekad_name")).isNull();
    }

    @Test
    void analystAndAdminKeepZeekadNameAsIs() {
        Map<String, Object> extras = new java.util.LinkedHashMap<>();
        extras.put("zeekad_name", List.of("alice.kim", "WS-01$"));
        AssetNameRecord raw = assetWithExtras(extras);
        for (UserRole role : List.of(UserRole.ANALYST, UserRole.ADMIN)) {
            AssetNameRecord same = maskingService.maskAssetNameRecord(raw, role);
            assertThat(same).isSameAs(raw);
            assertThat(same.getExtraAttributes().get("zeekad_name")).isEqualTo(List.of("alice.kim", "WS-01$"));
        }
    }

    private Object maskedNameObject(Object value) {
        Map<String, Object> extras = new java.util.LinkedHashMap<>();
        extras.put("zeekad_name", value);
        return maskingService.maskAssetNameRecord(assetWithExtras(extras), UserRole.VIEWER)
                .getExtraAttributes().get("zeekad_name");
    }

    private String maskedName(String value) {
        return (String) maskedNameObject(value);
    }
}
