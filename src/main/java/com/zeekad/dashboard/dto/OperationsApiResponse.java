package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SlackSummary;

import java.util.List;

/**
 * 운영 상태 API 응답 DTO.
 */
public record OperationsApiResponse(
        boolean maskedView,
        List<String> allowedCaptures,
        String selectedCaptureId,
        List<ScoringJob> jobs,
        List<ModelBundle> bundles,
        List<FeedbackSummaryRecord> feedbackSummaries,
        List<SlackSummary> slackSummaries
) {
}
