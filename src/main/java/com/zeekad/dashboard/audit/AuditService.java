package com.zeekad.dashboard.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
import com.zeekad.dashboard.service.UntrustedText;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * 불변 감사 로그 기록 서비스.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogMapper auditLogMapper;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public AuditService(AuditLogMapper auditLogMapper, ObjectMapper objectMapper, Clock clock) {
        this.auditLogMapper = auditLogMapper;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public void record(String actorUsername,
                       String actorRole,
                       AuditActionType actionType,
                       String targetCaptureId,
                       Long targetJobId,
                       String targetIncidentId,
                       Map<String, ?> detail,
                       String clientIp) {
        AuditLog entry = new AuditLog();
        entry.setOccurredAt(OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        entry.setActorUsername(truncate(actorUsername, 100));
        entry.setActorRole(truncate(actorRole, 32));
        entry.setActionType(actionType.name());
        entry.setTargetCaptureId(truncate(targetCaptureId, 128));
        entry.setTargetJobId(targetJobId);
        entry.setTargetIncidentId(truncate(targetIncidentId, 255));
        entry.setDetailJson(toJson(detail));
        entry.setClientIp(truncate(clientIp, 64));
        auditLogMapper.insertAuditLog(entry);
    }

    public void recordAuthEvent(String actorUsername,
                                String actorRole,
                                AuditActionType actionType,
                                Map<String, ?> detail,
                                String clientIp) {
        record(actorUsername, actorRole, actionType, null, null, null, detail, clientIp);
    }

    private String toJson(Map<String, ?> detail) {
        if (detail == null || detail.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(detail);
        } catch (JsonProcessingException e) {
            log.warn("감사 로그 detail 직렬화 실패", e);
            return "{}";
        }
    }

    /**
     * T63: UTF-16 단위 상한 이하로 자르되 서러게이트 쌍을 가르지 않는다(걸치면 그 쌍을 통째로 버린다). H2는 VARCHAR를 UTF-16 단위로,
     * PostgreSQL은 문자로 세므로 두 DB 모두 들어간다. 저장하는 값의 뜻(숨은 문자)은 바꾸지 않는다(원문은 증거다).
     */
    private String truncate(String value, int maxLen) {
        return UntrustedText.truncateUtf16(value, maxLen);
    }
}
