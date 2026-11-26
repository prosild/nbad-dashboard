package com.zeekad.dashboard.service;

import com.zeekad.dashboard.audit.AuditService;
import com.zeekad.dashboard.mapper.app.CriticalAssetMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.CriticalAsset;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * T52 중요 자산. 관리자가 등록한 주소(IPv4 하나)가 호스트인 미종결 인시던트는 자동 분류 우선순위를 한 단계 올린다.
 * <ul>
 *   <li>규칙은 읽기 SQL(ZeekadReadMapper.unifiedQueueBase) 한 곳에 있다. 이 서비스는 주소 배열과 이름을 담은 스냅샷을 준다.</li>
 *   <li>스냅샷은 요청 하나에 한 번만 읽는다: 요청의 입구(큐 조건 조립, 상세 메타, 같은 호스트 인시던트)가 한 번 읽어
 *       criteria의 주소 배열과 응답의 이름에 같은 것을 쓴다(그 사이 관리자가 바꿔도 한 응답 안의 값이 어긋나지 않는다).
 *       캐시는 두지 않는다.</li>
 *   <li>이름은 분석가·관리자 응답에만 싣는다(조회자는 늘 null: 이름이 주소를 가린 뜻을 무너뜨린다). 설명은 관리자 API에만 있다.</li>
 *   <li>주소 검증은 큐 hostIp 조건의 정확한 꼴(HostIpFilter EXACT)을 다시 쓴다. 앞뒤 공백·줄바꿈도 받지 않고 이름을 풀어 보지 않는다.</li>
 *   <li>변경은 감사 CRITICAL_ASSET_CHANGE와 같은 트랜잭션이다(감사를 남기지 못하면 변경도 없다).</li>
 * </ul>
 */
@Service
public class CriticalAssetService {

    /** 등록 상한. 동시 요청으로 한둘 넘는 것은 받아들인다(잠그지 않는다) */
    public static final int MAX_ASSETS = 200;
    public static final int NAME_MAX = 100;
    public static final int DESCRIPTION_MAX = 300;

    private final CriticalAssetMapper criticalAssetMapper;
    private final AuditService auditService;
    private final Clock clock;

    public CriticalAssetService(CriticalAssetMapper criticalAssetMapper, AuditService auditService, Clock clock) {
        this.criticalAssetMapper = criticalAssetMapper;
        this.auditService = auditService;
        this.clock = clock;
    }

    /** 요청 하나의 중요 자산(주소 → 이름). 읽은 뒤에는 바뀌지 않는다 */
    public static final class Snapshot {

        public static final Snapshot EMPTY = new Snapshot(Map.of());

        private final Map<String, String> nameByHost;
        private final String[] hostIps;

        private Snapshot(Map<String, String> nameByHost) {
            this.nameByHost = Collections.unmodifiableMap(new LinkedHashMap<>(nameByHost));
            this.hostIps = this.nameByHost.keySet().toArray(new String[0]);
        }

        public static Snapshot of(Map<String, String> nameByHost) {
            return nameByHost.isEmpty() ? EMPTY : new Snapshot(nameByHost);
        }

        /** criteria에 넘길 주소 배열(복사본). 비었으면 빈 배열이고 SQL은 배열을 묶지 않는다 */
        public String[] hostIps() {
            return hostIps.clone();
        }

        public boolean isEmpty() {
            return hostIps.length == 0;
        }

        public boolean isCritical(String hostIp) {
            return hostIp != null && nameByHost.containsKey(hostIp);
        }

        /** 역할에 맞춘 이름: 가리는 역할(조회자)은 늘 null, 중요 자산이 아니면 null */
        public String nameFor(String hostIp, boolean masked) {
            return masked || hostIp == null ? null : nameByHost.get(hostIp);
        }
    }

    /** 스냅샷을 한 번 읽는다(주소와 이름만, 설명은 읽지 않는다). 요청의 입구에서만 부른다 */
    public Snapshot snapshot() {
        Map<String, String> byHost = new LinkedHashMap<>();
        for (CriticalAsset a : criticalAssetMapper.findHostNames()) {
            if (a != null && a.getHostIp() != null) {
                byHost.put(a.getHostIp(), a.getName());
            }
        }
        return Snapshot.of(byHost);
    }

    /* ───────────────────────── 관리자 ───────────────────────── */

    /** 관리자 목록: 주소 순(옥텟 수 값) */
    public List<CriticalAsset> list() {
        List<CriticalAsset> all = new ArrayList<>(criticalAssetMapper.findAll());
        all.sort(Comparator.comparingLong((CriticalAsset a) -> ipv4Value(a.getHostIp())).thenComparing(CriticalAsset::getId));
        return all;
    }

    @Transactional
    public CriticalAsset create(String rawHostIp, String rawName, String rawDescription,
                                String actorUsername, String actorRole, String clientIp) {
        String hostIp = requireIpv4(rawHostIp);
        String name = requireName(rawName);
        String description = cleanDescription(rawDescription);
        if (criticalAssetMapper.findByHostIp(hostIp) != null) {
            throw exists();
        }
        if (criticalAssetMapper.countAll() >= MAX_ASSETS) {
            throw new CriticalAssetException(400, "CRITICAL_ASSET_LIMIT",
                    "중요 자산은 " + MAX_ASSETS + "개까지 등록할 수 있습니다.");
        }
        OffsetDateTime now = now();
        CriticalAsset asset = new CriticalAsset();
        asset.setHostIp(hostIp);
        asset.setName(name);
        asset.setDescription(description);
        asset.setCreatedBy(actorUsername);
        asset.setCreatedAt(now);
        asset.setUpdatedBy(actorUsername);
        asset.setUpdatedAt(now);
        int inserted;
        try {
            inserted = criticalAssetMapper.insertIfAbsent(asset);
        } catch (DuplicateKeyException e) {
            inserted = 0;
        }
        if (inserted == 0) {
            // 확인과 넣기 사이에 다른 요청이 같은 주소를 넣었다
            throw exists();
        }
        CriticalAsset saved = criticalAssetMapper.findByHostIp(hostIp);
        audit(actorUsername, actorRole, "CREATE", saved, clientIp);
        return saved;
    }

    /** 이름·설명만 고친다. 주소를 바꾸려면 지우고 새로 만든다 */
    @Transactional
    public CriticalAsset update(long id, String rawName, String rawDescription,
                                String actorUsername, String actorRole, String clientIp) {
        requireAsset(id);
        String name = requireName(rawName);
        String description = cleanDescription(rawDescription);
        if (criticalAssetMapper.updateNameAndDescription(id, name, description, actorUsername, now()) == 0) {
            throw notFound();
        }
        CriticalAsset saved = criticalAssetMapper.findById(id);
        if (saved == null) {
            throw notFound();
        }
        audit(actorUsername, actorRole, "UPDATE", saved, clientIp);
        return saved;
    }

    @Transactional
    public CriticalAsset delete(long id, String actorUsername, String actorRole, String clientIp) {
        CriticalAsset current = requireAsset(id);
        if (criticalAssetMapper.deleteById(id) == 0) {
            throw notFound();
        }
        audit(actorUsername, actorRole, "DELETE", current, clientIp);
        return current;
    }

    /* ───────────────────────── 검증 ───────────────────────── */

    /** IPv4 한 주소의 정확한 꼴만(HostIpFilter EXACT: 옥텟 0~255, 앞자리 0 없음, ASCII 숫자). 다듬지 않고 본다 */
    static String requireIpv4(String raw) {
        if (raw == null || HostIpFilter.kindOf(raw) != HostIpFilter.Kind.EXACT) {
            throw invalid("주소는 IPv4 한 주소(예: 192.0.2.10)만 받습니다. 대역·범위·IPv6·호스트 이름과 앞뒤 공백은 받지 않습니다.");
        }
        return raw;
    }

    static String requireName(String raw) {
        String name = raw == null ? "" : raw.strip();
        if (name.isEmpty()) {
            throw invalid("이름을 입력하세요.");
        }
        if (name.codePointCount(0, name.length()) > NAME_MAX) {
            throw invalid("이름은 " + NAME_MAX + "자를 넘을 수 없습니다.");
        }
        if (name.codePoints().anyMatch(Character::isISOControl)) {
            throw invalid("이름에 줄바꿈이나 제어 문자를 넣을 수 없습니다.");
        }
        return name;
    }

    static String cleanDescription(String raw) {
        String description = raw == null ? "" : raw.strip();
        if (description.isEmpty()) {
            return null;
        }
        if (description.codePointCount(0, description.length()) > DESCRIPTION_MAX) {
            throw invalid("설명은 " + DESCRIPTION_MAX + "자를 넘을 수 없습니다.");
        }
        if (description.codePoints().anyMatch(Character::isISOControl)) {
            throw invalid("설명에 줄바꿈이나 제어 문자를 넣을 수 없습니다.");
        }
        return description;
    }

    /* ───────────────────────── 내부 ───────────────────────── */

    private CriticalAsset requireAsset(long id) {
        CriticalAsset asset = criticalAssetMapper.findById(id);
        if (asset == null) {
            throw notFound();
        }
        return asset;
    }

    private void audit(String actorUsername, String actorRole, String operation, CriticalAsset asset, String clientIp) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("operation", operation);
        detail.put("hostIp", asset.getHostIp());
        detail.put("name", asset.getName());
        auditService.record(actorUsername, actorRole, AuditActionType.CRITICAL_ASSET_CHANGE,
                null, null, null, detail, clientIp);
    }

    private OffsetDateTime now() {
        return OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    /** 정렬용 수 값(검증을 거친 IPv4. 아니면 맨 뒤) */
    private static long ipv4Value(String ip) {
        if (ip == null || HostIpFilter.kindOf(ip) != HostIpFilter.Kind.EXACT) {
            return Long.MAX_VALUE;
        }
        long value = 0;
        for (String part : ip.split("\\.")) {
            value = value * 256 + Integer.parseInt(part);
        }
        return value;
    }

    private static CriticalAssetException invalid(String message) {
        return new CriticalAssetException(400, "INVALID_REQUEST", message);
    }

    private static CriticalAssetException exists() {
        return new CriticalAssetException(409, "CRITICAL_ASSET_EXISTS", "이미 등록된 주소입니다.");
    }

    private static CriticalAssetException notFound() {
        return new CriticalAssetException(404, "NOT_FOUND", "중요 자산을 찾을 수 없습니다.");
    }
}
