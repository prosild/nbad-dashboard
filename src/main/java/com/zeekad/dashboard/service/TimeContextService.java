package com.zeekad.dashboard.service;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.security.CapturePatternMatcher;
import org.springframework.stereotype.Service;

import java.time.Clock;
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

    public TimeContextService(DashboardProperties properties, ZeekadReadMapper zeekadReadMapper, Clock clock) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.clock = clock;
        this.mode = parseMode(properties.getTimeAnchor());
        this.livePatterns = parseLivePatterns(properties.getCaptureSources().getLivePatterns());
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
