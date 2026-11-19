package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.ScoringJob;

import java.util.List;

/**
 * 이상탐지 조사 큐 API 응답 DTO.
 */
public record IncidentQueueResponse(
        boolean maskedView,
        List<String> allowedCaptures,
        String selectedCaptureId,
        ScoringJob selectedJob,
        List<ScoringJob> captureJobs,
        List<IncidentQueueItem> incidents,
        List<String> availableModels,
        List<String> availableRoles
) {
}
