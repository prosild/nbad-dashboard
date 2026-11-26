package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceData;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.service.MaskingService;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T63 조회자 가림: 숨은 문자가 끼어도 지금보다 약해지지 않는다.
 * 주소가 들 수 있는 글은 maskIps(strip(maskIps(raw))), 계정 이름은 지운 값에 maskUsername(첫 코드 포인트가 BMP 밖이면 ***),
 * 지운 것이 있으면 끝에 " [보이지 않는 문자 N개 제거]". 숨은 문자가 없는 값은 지금과 같다(MaskingServiceTest가 고치지 않은 채 통과).
 */
class MaskingServiceT63Test {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final MaskingService maskingService = new MaskingService(objectMapper);

    private List<String> viewerHostNames(String... names) {
        IncidentQueueItem item = new IncidentQueueItem();
        item.setIncidentId("cap|10.0.0.1|originator|1");
        item.setHostIp("10.0.0.1");
        item.setHostName(List.of(names));
        return maskingService.maskIncidentQueueItem(item, UserRole.VIEWER).getHostName();
    }

    @Test
    void counterexamplesThatOnlyTheRawMaskCatchesStayMasked() {
        // 지우면 다섯 마디 숫자열(10.0.0.1.5)이 되어 지운 뒤 가림만으로는 드러난다. 원문 가림이 먼저 잡는다.
        assertThat(viewerHostNames("10.0.0.1\u200b.5")).containsExactly("10.0.*.*.5 [보이지 않는 문자 1개 제거]");
        // 지우면 앞에 "숫자."가 붙는다(7.10.0.0.1)
        assertThat(viewerHostNames("7.\u200b10.0.0.1")).containsExactly("7.10.0.*.* [보이지 않는 문자 1개 제거]");
    }

    @Test
    void splitAddressesAreMaskedAfterStripping() {
        assertThat(viewerHostNames("10.0\u200b.0.1")).containsExactly("10.0.*.* [보이지 않는 문자 1개 제거]");
        assertThat(viewerHostNames("srv-192.168\u202e.10\u2060.50")).containsExactly("srv-192.168.*.* [보이지 않는 문자 2개 제거]");
        ScoringJob job = new ScoringJob();
        job.setError("연결 실패 203.0\u200b.113.45\r\n재시도");
        // 글(여러 줄) 칸: \r\n은 \n으로, 숨은 문자는 지우고 가린다
        assertThat(maskingService.maskScoringJob(job, UserRole.VIEWER).getError())
                .isEqualTo("연결 실패 203.0.*.*\n재시도 [보이지 않는 문자 1개 제거]");
    }

    @Test
    void accountNamesAreMaskedAfterStrippingAndNeverLeaveHalfASurrogate() {
        AssetNameRecord raw = new AssetNameRecord();
        raw.setCaptureId("cap");
        raw.setHostIp("10.0.0.1");
        raw.setKerberosUser("\u202eadmin");
        raw.setNtlmUser("😀bob");
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("zeekad_name", List.of("\u200b\u200bkim", "😀x\u200b"));
        extras.put("zeekad_source_log", "kerb\u202eeros");
        raw.setExtraAttributes(extras);
        AssetNameRecord masked = maskingService.maskAssetNameRecord(raw, UserRole.VIEWER);
        assertThat(masked.getKerberosUser()).isEqualTo("a*** [보이지 않는 문자 1개 제거]");
        assertThat(masked.getNtlmUser()).isEqualTo("***");
        assertThat(masked.getExtraAttributes().get("zeekad_name"))
                .isEqualTo(List.of("k*** [보이지 않는 문자 2개 제거]", "*** [보이지 않는 문자 1개 제거]"));
        assertThat(masked.getExtraAttributes().get("zeekad_source_log")).isEqualTo("kerberos [보이지 않는 문자 1개 제거]");
        // 숨은 문자가 없는 값은 지금과 같다
        assertThat(maskingService.maskUsername("admin")).isEqualTo("a***");
        assertThat(maskingService.maskUsername("😀bob")).isEqualTo("***");
    }

    @Test
    void slackPayloadLeavesAndEvidenceAreProcessedForViewer() throws Exception {
        SlackSummary summary = new SlackSummary();
        summary.setSlackPayload(objectMapper.readTree("{\"channel\":\"#sec\",\"text\":\"호스트 10.0\\u200b.0.1 경보\\u202e\"}"));
        SlackSummary masked = maskingService.maskSlackSummary(summary, UserRole.VIEWER);
        assertThat(masked.getPayloadTextPreview()).isEqualTo("호스트 10.0.*.* 경보 [보이지 않는 문자 2개 제거]");

        EvidenceData evidence = new EvidenceData();
        evidence.setAvailable(true);
        evidence.setLimits(List.of("관측 10.0\u200b.0.2"));
        evidence.setTopPeers(List.of(Map.of("ip", "203.0.113\u200b.45")));
        EvidenceData maskedEvidence = maskingService.maskEvidence(evidence, UserRole.VIEWER);
        assertThat(maskedEvidence.getLimits()).containsExactly("관측 10.0.*.* [보이지 않는 문자 1개 제거]");
        assertThat(maskedEvidence.getTopPeers().get(0)).containsEntry("ip", "203.0.*.* [보이지 않는 문자 1개 제거]");
    }

    /**
     * 지운 뒤 Map 키가 겹치면 지금 동작을 유지한다(새는 쪽은 아니다):
     * 근거 Map은 뒤의 값이 앞의 값을 덮는다(LinkedHashMap.put), 구조 값(maskJsonIpsIncludingKeys)은 통째로 null이다.
     */
    @Test
    void keyCollisionsAfterStrippingKeepTheCurrentBehavior() throws Exception {
        Map<String, Object> logs = new LinkedHashMap<>();
        logs.put("d\u200bns", Map.of("queries", 1));
        logs.put("d\u200cns", Map.of("queries", 2));
        EvidenceData evidence = new EvidenceData();
        evidence.setAvailable(true);
        evidence.setProtocolLogs(logs);
        Map<String, Object> maskedLogs = maskingService.maskEvidence(evidence, UserRole.VIEWER).getProtocolLogs();
        assertThat(maskedLogs).hasSize(1);
        assertThat(maskedLogs.values().iterator().next()).isEqualTo(Map.of("queries", 2));
        assertThat(maskedLogs.keySet().iterator().next()).isEqualTo("dns [보이지 않는 문자 1개 제거]");

        JsonNode structured = objectMapper.readTree("{\"a\\u200bb\":\"1\",\"a\\u200cb\":\"2\"}");
        assertThat(maskingService.maskJsonIpsIncludingKeys(structured)).isNull();
    }

    @Test
    void analystAndAdminStillGetTheSameObjects() {
        IncidentQueueItem item = new IncidentQueueItem();
        item.setHostName(List.of("10.0\u200b.0.1"));
        AssetNameRecord asset = new AssetNameRecord();
        asset.setKerberosUser("\u202eadmin");
        for (UserRole role : List.of(UserRole.ANALYST, UserRole.ADMIN)) {
            assertThat(maskingService.maskIncidentQueueItem(item, role)).isSameAs(item);
            assertThat(maskingService.maskAssetNameRecord(asset, role)).isSameAs(asset);
        }
    }
}
