package com.zeekad.dashboard.dto;

import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SlackSummary;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 운영 상태 API 응답 DTO.
 * T24: period가 있으면 jobs·slackSummaries는 기간 안만(jobs는 최대 500건, 넘으면 jobsTruncated·jobsTotal),
 * period가 없으면 지금처럼 전체다. feedbackSummaries는 기간 없이 누적이다. latestJobs는 기간과 무관하다.
 * bundles는 조건 수집원의 작업이 쓴 모델 버전만이다. sources는 허용 캡처 전체와 수집원 종류(조건 줄 선택지)다.
 */
public record OperationsApiResponse(
        boolean maskedView,
        List<String> allowedCaptures,
        String selectedCaptureId,
        List<ScoringJob> jobs,
        List<ModelBundle> bundles,
        List<FeedbackSummaryRecord> feedbackSummaries,
        List<SlackSummary> slackSummaries,
        String period,
        String source,
        OffsetDateTime anchor,
        boolean jobsTruncated,
        long jobsTotal,
        List<LatestJobs> latestJobs,
        List<UnifiedQueueResponse.Source> sources
) {
    /** 캡처마다 최신 끝난 작업(succeeded·failed)과 최신 성공 작업(기간 무관) */
    public record LatestJobs(String captureId,
                             DashboardOverviewResponse.JobRef latestEnded,
                             DashboardOverviewResponse.JobRef latestSucceeded) {
    }
}
