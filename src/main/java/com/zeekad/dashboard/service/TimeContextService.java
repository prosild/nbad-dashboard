package com.zeekad.dashboard.service;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.security.CapturePatternMatcher;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;

/**
 * 기준 시각(T23)과 수집원 분류(T23) 설정. 잘못된 설정이면 앱 시작 때 실패한다.
 * <ul>
 *   <li>기준 시각 now: 서버 현재 시각</li>
 *   <li>기준 시각 latest-data: 그 사용자 허용 캡처 안 성공 작업 finished_at 최대값(없으면 현재 시각). 숨긴 캡처는 세지 않는다.</li>
 *   <li>수집원: dashboard.capture-sources.live-patterns에 맞으면 live(실습망 센서), 아니면 imported(가져온 데이터)</li>
 *   <li>센서(T24): live-patterns의 패턴 하나가 센서 하나다. 캡처가 패턴 둘 이상에 맞으면 설정 목록에서 먼저 나온 패턴의 센서다.</li>
 *   <li>센서 상태 기준(T24): stale-after·down-after. 0 이하이거나 stale-after ≥ down-after면 시작 때 실패한다.</li>
 * </ul>
 */
@Service
public class TimeContextService {

    public static final String MODE_NOW = "now";
    public static final String MODE_LATEST_DATA = "latest-data";
    public static final String SOURCE_LIVE = "live";
    public static final String SOURCE_IMPORTED = "imported";

    private final ZeekadReadMapper zeekadReadMapper;
    private final Clock clock;
    private final String mode;
    private final List<String> livePatterns;
    private final Duration staleAfter;
    private final Duration downAfter;

    public TimeContextService(DashboardProperties properties, ZeekadReadMapper zeekadReadMapper, Clock clock) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.clock = clock;
        this.mode = parseMode(properties.getTimeAnchor());
        this.livePatterns = parseLivePatterns(properties.getCaptureSources().getLivePatterns());
        this.staleAfter = properties.getCaptureSources().getStaleAfter();
        this.downAfter = properties.getCaptureSources().getDownAfter();
        validateHealthThresholds(staleAfter, downAfter);
    }

    static void validateHealthThresholds(Duration staleAfter, Duration downAfter) {
        if (staleAfter == null || staleAfter.isZero() || staleAfter.isNegative()) {
            throw new IllegalStateException("dashboard.capture-sources.stale-after 값은 0보다 커야 합니다: " + staleAfter);
        }
        if (downAfter == null || downAfter.isZero() || downAfter.isNegative()) {
            throw new IllegalStateException("dashboard.capture-sources.down-after 값은 0보다 커야 합니다: " + downAfter);
        }
        if (staleAfter.compareTo(downAfter) >= 0) {
            throw new IllegalStateException("dashboard.capture-sources.stale-after는 down-after보다 작아야 합니다: "
                    + staleAfter + " ≥ " + downAfter);
        }
    }

    static String parseMode(String raw) {
        String norm = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (norm.isEmpty() || MODE_NOW.equals(norm)) {
            return MODE_NOW;
        }
        if (MODE_LATEST_DATA.equals(norm)) {
            return MODE_LATEST_DATA;
        }
        throw new IllegalStateException(
                "DASHBOARD_TIME_ANCHOR 값이 올바르지 않습니다(now 또는 latest-data만 허용): " + raw);
    }

    static List<String> parseLivePatterns(String raw) {
        try {
            return CapturePatternMatcher.parseAndValidateList(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "dashboard.capture-sources.live-patterns 값이 올바르지 않습니다: " + e.getMessage(), e);
        }
    }

    public String mode() {
        return mode;
    }

    public boolean isSnapshot() {
        return MODE_LATEST_DATA.equals(mode);
    }

    public String sourceType(String captureId) {
        return CapturePatternMatcher.matchesAny(livePatterns, captureId) ? SOURCE_LIVE : SOURCE_IMPORTED;
    }

    public boolean isLive(String captureId) {
        return SOURCE_LIVE.equals(sourceType(captureId));
    }

    /** 센서 패턴 목록(설정 순서) */
    public List<String> sensorPatterns() {
        return livePatterns;
    }

    /** 캡처가 속한 센서 패턴(설정 목록에서 먼저 맞는 것). 가져온 데이터면 null */
    public String sensorKey(String captureId) {
        for (String pattern : livePatterns) {
            if (CapturePatternMatcher.matches(pattern, captureId)) {
                return pattern;
            }
        }
        return null;
    }

    /** 센서 표시 이름: lab-*면 "실습망 센서", 그 밖은 "센서 <패턴>" */
    public static String sensorLabel(String pattern) {
        return "lab-*".equals(pattern) ? "실습망 센서" : "센서 " + pattern;
    }

    public Duration staleAfter() {
        return staleAfter;
    }

    public Duration downAfter() {
        return downAfter;
    }

    public OffsetDateTime now() {
        return OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
    }

    /** 사용자 허용 캡처 목록으로 기준 시각을 정한다. */
    public OffsetDateTime anchorFor(List<String> allowedCaptures) {
        if (!isSnapshot() || allowedCaptures == null || allowedCaptures.isEmpty()) {
            return now();
        }
        OffsetDateTime latest = zeekadReadMapper.findMaxSucceededFinishedAt(allowedCaptures);
        return latest != null ? latest.withOffsetSameInstant(ZoneOffset.UTC) : now();
    }
}
