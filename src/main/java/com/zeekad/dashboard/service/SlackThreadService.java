package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
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

    /** 구성원 가운데 허용 캡처 안이고 최신 큐에 있는 수. 허용 캡처가 비면 0 */
    public long countVisibleMembers(List<String> allowedCaptures, String[] memberIds) {
        if (allowedCaptures == null || allowedCaptures.isEmpty() || memberIds == null || memberIds.length == 0) {
            return 0L;
        }
        return zeekadReadMapper.countLatestQueueByIncidentIds(allowedCaptures, memberIds);
    }
}
