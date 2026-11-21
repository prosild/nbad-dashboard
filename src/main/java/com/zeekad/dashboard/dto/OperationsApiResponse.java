package com.zeekad.dashboard.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
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
 * T25: handlingTimes는 period가 있을 때만(없으면 응답에 넣지 않는다), workload는 기간과 무관한 지금 값이다.
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
        List<UnifiedQueueResponse.Source> sources,
        @JsonInclude(JsonInclude.Include.NON_NULL) HandlingTimes handlingTimes,
        Workload workload
) {
    /** 한 지표: 건수, 중앙값·p90(초, n = 0이면 null), 제외(음수·필요한 시각 없음), 표본 부족(0 &lt; n &lt; 10) */
    public record TimeStat(long n, Long medianSeconds, Long p90Seconds, long excluded, boolean smallSample) {
    }

    /** 판정별 처리 시간. resolution: true_positive · false_positive · benign · none(판정 없음) */
    public record ResolutionStat(String resolution, TimeStat stat) {
    }

    public record ResolveTimes(TimeStat all, java.util.List<ResolutionStat> byResolution) {
    }

    /** detection = 탐지 지연(MTTD, 실습망만), acknowledge = 착수 시간(MTTA), resolve = 처리 시간(MTTR) */
    public record HandlingTimes(TimeStat detection, TimeStat acknowledge, ResolveTimes resolve) {
    }

    /** 담당자 한 사람의 미종결 담당 수 */
    public record AssigneeLoad(String username, String displayName, boolean enabled, long open, long investigating) {
    }

    /** 담당 현황(지금): unclosed = assigned + unassigned, assigned = byAssignee 합, ackOverdue = 큐 overdue=true(기간 all) total */
    public record Workload(long unclosed, long assigned, long unassigned, long ackOverdue, java.util.List<AssigneeLoad> byAssignee) {
    }

    /** 캡처마다 최신 끝난 작업(succeeded·failed)과 최신 성공 작업(기간 무관) */
    public record LatestJobs(String captureId,
                             DashboardOverviewResponse.JobRef latestEnded,
                             DashboardOverviewResponse.JobRef latestSucceeded) {
    }
}
