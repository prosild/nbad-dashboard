package com.zeekad.dashboard.service;

import com.zeekad.dashboard.config.DashboardProperties;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Locale;

/**
 * 착수 목표(T25). 대상은 실습망(live) 수집원 · 상태 신규(open) · 우선순위가 있는 인시던트다(가져온 데이터는 재생 데이터라 제외).
 * <ul>
 *   <li>ackDueAt = detectedAt + 지금 우선순위의 목표. 대상이 아니거나 detectedAt이 없으면 null</li>
 *   <li>ackOverdue = 대상이고 ackDueAt &lt; 기준 시각(같으면 지연 아님). SQL 식(ZeekadReadMapper ackOverdueCond)과 같다:
 *       detected_at &lt; 기준 시각 − 목표</li>
 * </ul>
 * 우선순위는 지금 값이다(검토 결정 뒤 High → Medium이면 목표도 바뀐다).
 */
@Service
public class AckTargetService {

    private final TimeContextService timeContextService;
    private final Duration high;
    private final Duration medium;
    private final Duration low;

    public AckTargetService(DashboardProperties properties, TimeContextService timeContextService) {
        this.timeContextService = timeContextService;
        DashboardProperties.Ack ack = properties.getSla().getAck();
        validate(ack.getHigh(), ack.getMedium(), ack.getLow());
        this.high = ack.getHigh();
        this.medium = ack.getMedium();
        this.low = ack.getLow();
    }

    static void validate(Duration high, Duration medium, Duration low) {
        check("high", high);
        check("medium", medium);
        check("low", low);
        if (high.compareTo(medium) > 0 || medium.compareTo(low) > 0) {
            throw new IllegalStateException("dashboard.sla.ack 값은 high ≤ medium ≤ low여야 합니다: "
                    + high + ", " + medium + ", " + low);
        }
    }

    private static void check(String name, Duration d) {
        if (d == null || d.isZero() || d.isNegative()) {
            throw new IllegalStateException("dashboard.sla.ack." + name + " 값은 0보다 커야 합니다: " + d);
        }
    }

    public Duration high() {
        return high;
    }

    public Duration medium() {
        return medium;
    }

    public Duration low() {
        return low;
    }

    /** 우선순위의 목표(없는 우선순위면 null) */
    public Duration targetFor(String priority) {
        if (priority == null) {
            return null;
        }
        return switch (priority.trim().toLowerCase(Locale.ROOT)) {
            case "high" -> high;
            case "medium" -> medium;
            case "low" -> low;
            default -> null;
        };
    }

    /** 신규 상태(빈 값 포함) */
    public static boolean isOpen(String status) {
        String s = status == null ? "" : status.trim().toLowerCase(Locale.ROOT);
        return s.isEmpty() || "open".equals(s);
    }

    public OffsetDateTime dueAt(String captureId, String status, String priority, OffsetDateTime detectedAt) {
        if (detectedAt == null || !isOpen(status) || !timeContextService.isLive(captureId)) {
            return null;
        }
        Duration target = targetFor(priority);
        return target == null ? null : detectedAt.plus(target);
    }

    public static boolean isOverdue(OffsetDateTime dueAt, OffsetDateTime anchor) {
        return dueAt != null && anchor != null && dueAt.isBefore(anchor);
    }
}
