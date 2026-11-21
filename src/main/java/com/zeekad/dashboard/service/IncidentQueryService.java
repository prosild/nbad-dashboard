package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * zeekad v1·v2·v2.1 읽기 전용 뷰 조회 및 필터링·권한·마스킹 조합 서비스.
 */
@Service
public class IncidentQueryService {

    private final ZeekadReadMapper zeekadReadMapper;
    private final UserMapper userMapper;
    private final CaptureAccessService captureAccessService;
    private final MaskingService maskingService;

    public IncidentQueryService(ZeekadReadMapper zeekadReadMapper,
                                UserMapper userMapper,
                                CaptureAccessService captureAccessService,
                                MaskingService maskingService) {
        this.zeekadReadMapper = zeekadReadMapper;
        this.userMapper = userMapper;
        this.captureAccessService = captureAccessService;
        this.maskingService = maskingService;
    }

    public QueueViewResult loadQueueView(DashboardUserPrincipal principal,
                                         String captureId,
                                         Long jobId,
                                         String pickedBy,
                                         String role,
                                         String asset,
                                         String status,
                                         String hasReportParam,
                                         String wouldSendParam,
                                         String clientIp) {
        List<String> allowedCaptures = captureAccessService.listAllowedCaptures(principal);
        String cleanCaptureId = trimToNull(captureId);

        ScoringJob selectedJob = null;
        String selectedCaptureId = null;
        boolean useLatestQueue = false;

        if (jobId != null) {
            selectedJob = captureAccessService.requireJobAccess(principal, jobId, cleanCaptureId, clientIp);
            selectedCaptureId = selectedJob.getCaptureId();
            ScoringJob latestSucceededJob = zeekadReadMapper.findLatestSucceededJobByCaptureId(selectedCaptureId);
            useLatestQueue = latestSucceededJob != null
                    && Objects.equals(selectedJob.getJobId(), latestSucceededJob.getJobId());
        } else if (cleanCaptureId != null) {
            captureAccessService.requireCaptureAccess(principal, cleanCaptureId, clientIp);
            selectedCaptureId = cleanCaptureId;
            ScoringJob latestSucceededJob = zeekadReadMapper.findLatestSucceededJobByCaptureId(selectedCaptureId);
            useLatestQueue = latestSucceededJob != null;
            selectedJob = latestSucceededJob != null
                    ? latestSucceededJob
                    : zeekadReadMapper.findLatestJobByCaptureId(selectedCaptureId);
        } else if (!allowedCaptures.isEmpty()) {
            selectedCaptureId = allowedCaptures.get(0);
            ScoringJob latestSucceededJob = zeekadReadMapper.findLatestSucceededJobByCaptureId(selectedCaptureId);
            useLatestQueue = latestSucceededJob != null;
            selectedJob = latestSucceededJob != null
                    ? latestSucceededJob
                    : zeekadReadMapper.findLatestJobByCaptureId(selectedCaptureId);
        }

        if (selectedJob == null) {
            return new QueueViewResult(
                    allowedCaptures,
                    selectedCaptureId,
                    null,
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        }

        List<ScoringJob> captureJobs = zeekadReadMapper.findScoringJobs(selectedCaptureId);
        List<IncidentQueueItem> unfilteredForOptions = fetchQueueItems(
                useLatestQueue, selectedCaptureId, selectedJob.getJobId(), null, null, null, null, null);
        List<String> availableModels = unfilteredForOptions.stream()
                .map(IncidentQueueItem::getZeekadPickedBy)
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .toList();
        List<String> availableRoles = unfilteredForOptions.stream()
                .map(IncidentQueueItem::getZeekadRole)
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .toList();

        Boolean hasReport = parseOptionalBoolean(hasReportParam);
        Boolean wouldSend = parseOptionalBoolean(wouldSendParam);
        UserRole userRole = principal != null ? principal.getRole() : UserRole.VIEWER;

        List<IncidentQueueItem> rawItems = fetchQueueItems(
                useLatestQueue,
                selectedCaptureId,
                selectedJob.getJobId(),
                trimToNull(pickedBy),
                trimToNull(role),
                trimToNull(status),
                hasReport,
                wouldSend
        );

        String assetQuery = trimToNull(asset);
        List<IncidentQueueItem> items = rawItems.stream()
                .map(item -> maskingService.maskIncidentQueueItem(item, userRole))
                .filter(item -> matchesAssetFilter(item, assetQuery))
                .toList();

        return new QueueViewResult(
                allowedCaptures,
                selectedCaptureId,
                selectedJob,
                captureJobs,
                items,
                availableModels,
                availableRoles
        );
    }

    public ReviewsViewResult loadReviewsView(DashboardUserPrincipal principal,
                                             String captureId,
                                             boolean pendingOnly,
                                             String clientIp) {
        List<String> allowedCaptures = captureAccessService.listAllowedCaptures(principal);
        String cleanCaptureId = trimToNull(captureId);
        if (cleanCaptureId != null) {
            captureAccessService.requireCaptureAccess(principal, cleanCaptureId, clientIp);
        }

        UserRole userRole = principal != null ? principal.getRole() : UserRole.VIEWER;
        Map<String, String> userDisplayMap = loadUserDisplayMap();
        List<AnalystReviewItem> reviews = zeekadReadMapper.findAnalystReviewQueue(cleanCaptureId, pendingOnly).stream()
                .filter(r -> principal != null && principal.isCaptureAllowed(r.getCaptureId()))
                .map(r -> {
                    AnalystReviewItem masked = maskingService.maskAnalystReviewItem(r, userRole);
                    if (masked.getAnalyst() != null && !masked.getAnalyst().isBlank()) {
                        masked.setAnalystDisplay(formatActorDisplay(masked.getAnalyst(), userDisplayMap));
                    }
                    return masked;
                })
                .toList();

        return new ReviewsViewResult(allowedCaptures, cleanCaptureId, pendingOnly, reviews);
    }

    public Map<String, String> loadUserDisplayMap() {
        List<DashboardUser> users = userMapper.findAll();
        Map<String, String> map = new HashMap<>();
        for (DashboardUser u : users) {
            if (u.getUsername() != null && u.getDisplayName() != null && !u.getDisplayName().isBlank()) {
                map.put(u.getUsername().toLowerCase(Locale.ROOT), u.getDisplayName());
            }
        }
        return map;
    }

    public String formatActorDisplay(String actor, Map<String, String> userDisplayMap) {
        if (actor == null || actor.isBlank()) {
            return "-";
        }
        String displayName = userDisplayMap.get(actor.trim().toLowerCase(Locale.ROOT));
        if (displayName != null && !displayName.isBlank()) {
            return displayName + " (" + actor + ")";
        }
        return actor;
    }

    public List<AssetNameRecord> findAssetNames(String captureId, String hostIp, UserRole userRole) {
        return zeekadReadMapper.findRawAssetNames(captureId, hostIp).stream()
                .map(AssetNameRecord::fromRawMap)
                .map(asset -> maskingService.maskAssetNameRecord(asset, userRole))
                .toList();
    }

    private List<IncidentQueueItem> fetchQueueItems(boolean useLatestQueue,
                                                  String captureId,
                                                  Long jobId,
                                                  String pickedBy,
                                                  String role,
                                                  String status,
                                                  Boolean hasReport,
                                                  Boolean wouldSend) {
        if (useLatestQueue) {
            return zeekadReadMapper.findLatestIncidentQueue(captureId, pickedBy, role, status, hasReport, wouldSend);
        }
        return zeekadReadMapper.findIncidentQueue(jobId, pickedBy, role, status, hasReport, wouldSend);
    }

    static boolean matchesAssetFilter(IncidentQueueItem item, String assetQuery) {
        if (assetQuery == null) {
            return true;
        }
        String needle = assetQuery.toLowerCase(Locale.ROOT);
        if (item.getHostIp() != null && item.getHostIp().toLowerCase(Locale.ROOT).contains(needle)) {
            return true;
        }
        if (item.getHostName() != null) {
            for (String host : item.getHostName()) {
                if (host != null && host.toLowerCase(Locale.ROOT).contains(needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Boolean parseOptionalBoolean(String value) {
        String clean = trimToNull(value);
        if (clean == null) {
            return null;
        }
        if ("true".equalsIgnoreCase(clean)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(clean)) {
            return Boolean.FALSE;
        }
        return null;
    }

    public record QueueViewResult(
            List<String> allowedCaptures,
            String selectedCaptureId,
            ScoringJob selectedJob,
            List<ScoringJob> captureJobs,
            List<IncidentQueueItem> items,
            List<String> availableModels,
            List<String> availableRoles
    ) {
    }

    public record ReviewsViewResult(
            List<String> allowedCaptures,
            String selectedCaptureId,
            boolean pendingOnly,
            List<AnalystReviewItem> reviews
    ) {
    }
}
