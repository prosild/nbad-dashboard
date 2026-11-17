package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.AssetNameRecord;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * zeekad v1·v2 읽기 전용 뷰 조회 및 필터링·권한·마스킹 조합 서비스.
 */
@Service
public class IncidentQueryService {

    private final ZeekadReadMapper zeekadReadMapper;
    private final CaptureAccessService captureAccessService;
    private final MaskingService maskingService;

    public IncidentQueryService(ZeekadReadMapper zeekadReadMapper,
                                CaptureAccessService captureAccessService,
                                MaskingService maskingService) {
        this.zeekadReadMapper = zeekadReadMapper;
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

        if (jobId != null) {
            selectedJob = captureAccessService.requireJobAccess(principal, jobId, cleanCaptureId, clientIp);
            selectedCaptureId = selectedJob.getCaptureId();
        } else if (cleanCaptureId != null) {
            captureAccessService.requireCaptureAccess(principal, cleanCaptureId, clientIp);
            selectedCaptureId = cleanCaptureId;
            selectedJob = resolveDefaultJobForCapture(selectedCaptureId);
        } else if (!allowedCaptures.isEmpty()) {
            selectedCaptureId = allowedCaptures.get(0);
            selectedJob = resolveDefaultJobForCapture(selectedCaptureId);
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
        List<IncidentQueueItem> unfilteredForOptions = zeekadReadMapper.findIncidentQueue(
                selectedJob.getJobId(), null, null, null, null, null);
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

        List<IncidentQueueItem> rawItems = zeekadReadMapper.findIncidentQueue(
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

    public OperationsViewResult loadOperationsView(DashboardUserPrincipal principal,
                                                   String captureId,
                                                   String clientIp) {
        List<String> allowedCaptures = captureAccessService.listAllowedCaptures(principal);
        String cleanCaptureId = trimToNull(captureId);
        if (cleanCaptureId != null) {
            captureAccessService.requireCaptureAccess(principal, cleanCaptureId, clientIp);
        }

        List<ScoringJob> jobs = zeekadReadMapper.findScoringJobs(cleanCaptureId).stream()
                .filter(j -> principal != null && principal.isCaptureAllowed(j.getCaptureId()))
                .toList();

        List<ModelBundle> bundles = zeekadReadMapper.findAllModelBundles();

        UserRole userRole = principal != null ? principal.getRole() : UserRole.VIEWER;
        List<SlackSummary> summaries = zeekadReadMapper.findSlackSummaries(cleanCaptureId).stream()
                .filter(s -> principal != null && principal.isCaptureAllowed(s.getCaptureId()))
                .map(s -> maskingService.maskSlackSummary(s, userRole))
                .toList();

        return new OperationsViewResult(allowedCaptures, cleanCaptureId, jobs, bundles, summaries);
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
        List<AnalystReviewItem> reviews = zeekadReadMapper.findAnalystReviewQueue(cleanCaptureId, pendingOnly).stream()
                .filter(r -> principal != null && principal.isCaptureAllowed(r.getCaptureId()))
                .map(r -> maskingService.maskAnalystReviewItem(r, userRole))
                .toList();

        return new ReviewsViewResult(allowedCaptures, cleanCaptureId, pendingOnly, reviews);
    }

    public List<AssetNameRecord> findAssetNames(String captureId, String hostIp, UserRole userRole) {
        return zeekadReadMapper.findRawAssetNames(captureId, hostIp).stream()
                .map(AssetNameRecord::fromRawMap)
                .map(asset -> maskingService.maskAssetNameRecord(asset, userRole))
                .toList();
    }

    private ScoringJob resolveDefaultJobForCapture(String captureId) {
        ScoringJob job = zeekadReadMapper.findLatestSucceededJobByCaptureId(captureId);
        if (job != null) {
            return job;
        }
        return zeekadReadMapper.findLatestJobByCaptureId(captureId);
    }

    private boolean matchesAssetFilter(IncidentQueueItem item, String assetQuery) {
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

    public record OperationsViewResult(
            List<String> allowedCaptures,
            String selectedCaptureId,
            List<ScoringJob> jobs,
            List<ModelBundle> bundles,
            List<SlackSummary> slackSummaries
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
