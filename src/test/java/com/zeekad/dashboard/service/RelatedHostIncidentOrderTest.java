package com.zeekad.dashboard.service;

import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T46 같은 호스트 인시던트의 고르는 순서·응답 순서와 관측 계정 이름 뽑기(H2 스키마로는 만들 수 없는 값 없음 경우 포함).
 */
class RelatedHostIncidentOrderTest {

    private static final Instant SELF = Instant.parse("2026-11-20T06:00:00Z");

    private static UnifiedQueueRecord row(String key, String capture, int rank, String eventStart, String detectedAt) {
        UnifiedQueueRecord r = new UnifiedQueueRecord();
        r.setIncidentId(key);
        r.setCaptureId(capture);
        r.setQueueRank(rank);
        r.setEventStart(eventStart == null ? null : OffsetDateTime.parse(eventStart));
        r.setDetectedAt(detectedAt == null ? null : OffsetDateTime.parse(detectedAt));
        return r;
    }

    private static List<String> ids(List<UnifiedQueueRecord> rows) {
        return rows.stream().map(UnifiedQueueRecord::getIncidentId).toList();
    }

    @Test
    void pickOrderIsGapThenDetectedDescThenCaptureThenRankAndMissingEventStartIsLast() {
        List<UnifiedQueueRecord> rows = new ArrayList<>(List.of(
                row("no-start", "cap-a", 1, null, "2026-11-20T23:00:00Z"),
                row("far", "cap-a", 2, "2026-11-20T09:00:00Z", "2026-11-20T10:00:00Z"),
                row("near-after", "cap-b", 1, "2026-11-20T06:10:00Z", "2026-11-20T10:00:00Z"),
                row("near-before-late-detect", "cap-b", 9, "2026-11-20T05:50:00Z", "2026-11-20T11:00:00Z"),
                row("near-before", "cap-a", 7, "2026-11-20T05:50:00Z", "2026-11-20T10:00:00Z"),
                row("near-no-detect", "cap-a", 3, "2026-11-20T06:10:00Z", null),
                row("near-after-rank2", "cap-b", 2, "2026-11-20T06:10:00+00:00", "2026-11-20T19:00:00+09:00"),
                row("same-time", "cap-c", 1, "2026-11-20T15:00:00+09:00", "2026-11-20T10:00:00Z")));
        rows.sort(RelatedHostIncidentService.pickOrder(SELF));
        // 차 0(시간대가 달라도 같은 순간) → 차 10분: 탐지 최근 → 캡처 → 순위, 탐지 시각 없음은 그 뒤 → 먼 것 → 발생 시각 없음
        assertThat(ids(rows)).containsExactly("same-time", "near-before-late-detect", "near-before", "near-after",
                "near-after-rank2", "near-no-detect", "far", "no-start");

        // 이 인시던트의 발생 시각이 없으면 모두 "시간 차 없음"이라 탐지 시각 최근 → 캡처 → 순위다
        rows.sort(RelatedHostIncidentService.pickOrder(null));
        assertThat(ids(rows)).containsExactly("no-start", "near-before-late-detect", "far", "near-before", "near-after",
                "near-after-rank2", "same-time", "near-no-detect");
    }

    @Test
    void showOrderIsEventStartDescThenCaptureThenRankAndMissingEventStartIsLast() {
        List<UnifiedQueueRecord> rows = new ArrayList<>(List.of(
                row("no-start", "cap-a", 1, null, null),
                row("old", "cap-a", 2, "2026-11-19T00:00:00Z", null),
                row("new-b2", "cap-b", 2, "2026-11-20T00:00:00Z", null),
                row("new-b1", "cap-b", 1, "2026-11-20T00:00:00Z", null),
                row("new-a9", "cap-a", 9, "2026-11-20T09:00:00+09:00", null)));
        rows.sort(RelatedHostIncidentService.SHOW_ORDER);
        assertThat(ids(rows)).containsExactly("new-a9", "new-b1", "new-b2", "old", "no-start");
    }

    @Test
    void accountNamesPreferZeekadNameThenKerberosAndNtlm() {
        AssetNameRecord named = new AssetNameRecord();
        named.setKerberosUser("krb.user");
        named.setNtlmUser("NTLM_USER");
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("ZEEKAD_NAME", "  alice.kim ");
        named.setExtraAttributes(extras);
        assertThat(HostRiskService.accountNames(named)).containsExactly("alice.kim");

        // 리스트 값은 원소마다(빈 값·null은 뺀다), 문자열이 아닌 값은 글로
        Map<String, Object> listExtras = new LinkedHashMap<>();
        listExtras.put("zeekad_name", Arrays.asList("bob", " ", null, 4711));
        named.setExtraAttributes(listExtras);
        assertThat(HostRiskService.accountNames(named)).containsExactly("bob", "4711");

        // zeekad_name이 없거나 비면 Kerberos·NTLM 이름
        Map<String, Object> blank = new LinkedHashMap<>();
        blank.put("zeekad_name", "");
        named.setExtraAttributes(blank);
        assertThat(HostRiskService.accountNames(named)).containsExactly("krb.user", "NTLM_USER");
        named.setExtraAttributes(Map.of("source_log", "kerberos"));
        named.setNtlmUser(null);
        assertThat(HostRiskService.accountNames(named)).containsExactly("krb.user");
        assertThat(HostRiskService.accountNames(new AssetNameRecord())).isEmpty();
    }
}
