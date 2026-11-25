package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.zeekad.dashboard.model.zeekad.IncidentRowCount;
import com.zeekad.dashboard.model.zeekad.SlackThreadLink;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * T40 알림 묶음(Slack 스레드) 구성원. 묶음의 뜻은 zeek_AD 기록(zeekad_thread_parent) 그대로다:
 * 구성원 = 머리 incident_id 자신 ∪ slack_deliveries에서 TRIM(zeekad_thread_parent) = 머리인 행의 incident_id.
 * 상세의 memberCount와 큐의 thread 조건이 같은 코드를 쓴다. 결과(incident_id 목록)는 응답에 넣지 않는다.
 */
@Service
public class SlackThreadService {

    private static final Logger log = LoggerFactory.getLogger(SlackThreadService.class);

    /** 구성원 배열 상한(머리 포함). 넘으면 잘라 쓰고 경고 한 줄(개수만) */
    public static final int MEMBER_CAP = 5000;

    private final ZeekadReadMapper zeekadReadMapper;

    public SlackThreadService(ZeekadReadMapper zeekadReadMapper) {
        this.zeekadReadMapper = zeekadReadMapper;
    }

    /** 머리 ∪ 답글 incident_id(머리가 맨 앞, 중복 없이, 상한 MEMBER_CAP). 머리가 비면 빈 배열 */
    public String[] memberIds(String headIncidentId) {
        if (headIncidentId == null || headIncidentId.isBlank()) {
            return new String[0];
        }
        Set<String> members = new LinkedHashSet<>();
        members.add(headIncidentId);
        // 머리 자신이 답글 목록에 섞여 있을 수 있어 하나 더 읽어 상한 넘김을 판단한다
        List<String> replies = zeekadReadMapper.findThreadReplyIncidentIds(headIncidentId, MEMBER_CAP + 1);
        boolean truncated = false;
        for (String id : replies) {
            if (id == null || id.isBlank()) {
                continue;
            }
            if (members.size() >= MEMBER_CAP && !members.contains(id)) {
                truncated = true;
                break;
            }
            members.add(id);
        }
        if (truncated) {
            log.warn("알림 묶음 구성원이 상한을 넘어 잘랐습니다(상한 {}건)", MEMBER_CAP);
        }
        return members.toArray(new String[0]);
    }

    /* ───────────── T45 큐 행 묶음 표지(쪽의 행 수와 무관하게 질의 한 번씩) ───────────── */

    /** 표지 계산에서 한 번에 읽는 답글 짝 상한. 넘으면 그 응답의 표지를 모두 생략한다(경고 한 줄, 개수만) */
    public static final int BADGE_REPLY_ROW_CAP = 20_000;

    /**
     * 인시던트마다 후보 머리: Slack 기록 행마다 부모가 있으면 TRIM한 부모, 없으면 자기 incident_id
     * (상세 buildSlackThreads의 묶음 열쇠와 같다). Slack 기록이 없는 인시던트는 결과에 없다. 질의 한 번.
     */
    public Map<String, Set<String>> candidateHeads(Collection<String> incidentIds) {
        Set<String> ids = new LinkedHashSet<>();
        if (incidentIds != null) {
            for (String id : incidentIds) {
                if (id != null && !id.isBlank()) {
                    ids.add(id);
                }
            }
        }
        Map<String, Set<String>> out = new LinkedHashMap<>();
        if (ids.isEmpty()) {
            return out;
        }
        for (SlackThreadLink link : zeekadReadMapper.findSlackThreadLinksByIncidentIds(ids.toArray(new String[0]))) {
            String own = link.getIncidentId();
            if (own == null || !ids.contains(own)) {
                continue;
            }
            String parent = link.getThreadParent();
            String head = parent != null && !parent.isBlank() ? parent.trim() : own;
            out.computeIfAbsent(own, k -> new LinkedHashSet<>()).add(head);
        }
        return out;
    }

    /**
     * 머리마다 구성원 수: countVisibleMembers(allowed, memberIds(머리))와 같은 값을 질의 두 번(답글 짝, 최신 큐 소속)으로 구한다.
     * 구성원이 MEMBER_CAP을 넘는 머리는 결과에 없다(상세는 잘라 세므로 같은 값을 보장할 수 없어 표지를 생략한다).
     * 답글 짝이 BADGE_REPLY_ROW_CAP을 넘으면 빈 결과다. 머리·허용 캡처가 비면 질의 없이 빈 결과.
     */
    public Map<String, Long> visibleMemberCounts(List<String> allowedCaptures, Collection<String> heads) {
        return visibleThreadMembers(allowedCaptures, heads).visibleCounts();
    }

    /**
     * T45b: 머리마다 구성원 집합(머리 포함, incident_id)과 허용 캡처 최신 큐에 있는 구성원 수.
     * members와 visibleCounts는 같은 머리를 열쇠로 갖는다(구성원이 MEMBER_CAP을 넘는 머리는 둘 다에 없다).
     * omitted = 답글 짝이 BADGE_REPLY_ROW_CAP을 넘어 계산 전체를 생략함(이때 두 맵은 비어 있다).
     * 구성원 집합은 응답에 넣지 않는다.
     */
    public record ThreadMembers(Map<String, Set<String>> members, Map<String, Long> visibleCounts, boolean omitted) {
    }

    /** visibleMemberCounts와 같은 계산(질의 두 번)에 머리별 구성원 집합과 생략 여부를 더해 돌려준다 */
    public ThreadMembers visibleThreadMembers(List<String> allowedCaptures, Collection<String> heads) {
        Map<String, Long> out = new HashMap<>();
        Map<String, Set<String>> none = new LinkedHashMap<>();
        if (allowedCaptures == null || allowedCaptures.isEmpty() || heads == null || heads.isEmpty()) {
            return new ThreadMembers(none, out, false);
        }
        Map<String, Set<String>> members = new LinkedHashMap<>();
        for (String head : heads) {
            if (head != null && !head.isBlank()) {
                members.computeIfAbsent(head, k -> new LinkedHashSet<>()).add(head);
            }
        }
        if (members.isEmpty()) {
            return new ThreadMembers(none, out, false);
        }
        List<SlackThreadLink> replies = zeekadReadMapper.findThreadRepliesByHeads(
                members.keySet().toArray(new String[0]), BADGE_REPLY_ROW_CAP + 1);
        if (replies.size() > BADGE_REPLY_ROW_CAP) {
            log.warn("알림 묶음 표지 계산의 답글 짝이 상한을 넘어 표지를 생략했습니다(상한 {}건)", BADGE_REPLY_ROW_CAP);
            return new ThreadMembers(none, out, true);
        }
        for (SlackThreadLink reply : replies) {
            Set<String> set = reply.getThreadParent() == null ? null : members.get(reply.getThreadParent());
            String id = reply.getIncidentId();
            if (set != null && id != null && !id.isBlank()) {
                set.add(id);
            }
        }
        Set<String> all = new LinkedHashSet<>();
        int overCap = 0;
        for (Iterator<Map.Entry<String, Set<String>>> it = members.entrySet().iterator(); it.hasNext(); ) {
            Set<String> set = it.next().getValue();
            if (set.size() > MEMBER_CAP) {
                overCap++;
                it.remove();
            } else {
                all.addAll(set);
            }
        }
        if (overCap > 0) {
            log.warn("알림 묶음 구성원이 상한을 넘는 묶음 {}개의 표지를 생략했습니다(상한 {}건)", overCap, MEMBER_CAP);
        }
        if (all.isEmpty()) {
            return new ThreadMembers(none, out, false);
        }
        Map<String, Long> rows = new HashMap<>();
        for (IncidentRowCount c : zeekadReadMapper.countLatestQueueRowsByIncidentIds(allowedCaptures,
                all.toArray(new String[0]))) {
            if (c.getIncidentId() != null) {
                rows.merge(c.getIncidentId(), c.getRowCount(), Long::sum);
            }
        }
        for (Map.Entry<String, Set<String>> e : members.entrySet()) {
            long total = 0;
            for (String id : e.getValue()) {
                total += rows.getOrDefault(id, 0L);
            }
            out.put(e.getKey(), total);
        }
        return new ThreadMembers(members, out, false);
    }

    /** 구성원 가운데 허용 캡처 안이고 최신 큐에 있는 수. 허용 캡처가 비면 0 */
    public long countVisibleMembers(List<String> allowedCaptures, String[] memberIds) {
        if (allowedCaptures == null || allowedCaptures.isEmpty() || memberIds == null || memberIds.length == 0) {
            return 0L;
        }
        return zeekadReadMapper.countLatestQueueByIncidentIds(allowedCaptures, memberIds);
    }
}
