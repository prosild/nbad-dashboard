package com.zeekad.dashboard.mapper.zeekad.read;

import com.zeekad.dashboard.model.zeekad.AnalystReviewItem;
import com.zeekad.dashboard.model.zeekad.IncidentModelScore;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.model.zeekad.IncidentReport;
import com.zeekad.dashboard.model.zeekad.IncidentStatus;
import com.zeekad.dashboard.model.zeekad.IncidentStatusHistory;
import com.zeekad.dashboard.model.zeekad.ModelBundle;
import com.zeekad.dashboard.model.zeekad.ScoringJob;
import com.zeekad.dashboard.model.zeekad.SendDecision;
import com.zeekad.dashboard.model.zeekad.SlackDelivery;
import com.zeekad.dashboard.model.zeekad.SlackSummary;
import com.zeekad.dashboard.model.zeekad.CaptureJobStat;
import com.zeekad.dashboard.model.zeekad.CaptureQueueStat;
import com.zeekad.dashboard.model.zeekad.IncidentPoint;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueRecord;
import com.zeekad.dashboard.model.zeekad.UnifiedQueueSummaryRow;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * zeekad 읽기 전용 DataSource(dashboard 스키마 v1·v2·v2.1·migration 017 뷰 14종) 조회 MyBatis 매퍼.
 * 모든 파라미터 바인딩에 #{}만 사용한다.
 */
@Mapper
public interface ZeekadReadMapper {

    List<String> findDistinctCaptureIds();

    List<ScoringJob> findScoringJobs(@Param("captureId") String captureId);

    ScoringJob findScoringJobById(@Param("jobId") Long jobId);

    ScoringJob findLatestSucceededJobByCaptureId(@Param("captureId") String captureId);

    ScoringJob findLatestJobByCaptureId(@Param("captureId") String captureId);

    List<ModelBundle> findAllModelBundles();

    ModelBundle findModelBundleById(@Param("bundleId") String bundleId);

    List<IncidentQueueItem> findLatestIncidentQueue(@Param("captureId") String captureId,
                                                    @Param("pickedBy") String pickedBy,
                                                    @Param("role") String role,
                                                    @Param("status") String status,
                                                    @Param("hasReport") Boolean hasReport,
                                                    @Param("wouldSend") Boolean wouldSend);

    List<IncidentQueueItem> findIncidentQueue(@Param("jobId") Long jobId,
                                              @Param("pickedBy") String pickedBy,
                                              @Param("role") String role,
                                              @Param("status") String status,
                                              @Param("hasReport") Boolean hasReport,
                                              @Param("wouldSend") Boolean wouldSend);

    IncidentQueueItem findIncidentQueueItemByJobAndRank(@Param("jobId") Long jobId,
                                                          @Param("queueRank") Integer queueRank);

    IncidentQueueItem findIncidentQueueItemByJobAndIncident(@Param("jobId") Long jobId,
                                                              @Param("incidentId") String incidentId);

    List<IncidentModelScore> findModelScores(@Param("jobId") Long jobId,
                                             @Param("incidentId") String incidentId);

    List<Map<String, Object>> findRawAssetNames(@Param("captureId") String captureId,
                                                @Param("hostIp") String hostIp);

    IncidentReport findIncidentReport(@Param("jobId") Long jobId,
                                      @Param("incidentId") String incidentId);

    SendDecision findSendDecision(@Param("jobId") Long jobId,
                                  @Param("incidentId") String incidentId);

    List<SlackDelivery> findSlackDeliveries(@Param("incidentId") String incidentId);

    /** T40 알림 묶음: TRIM(zeekad_thread_parent) = 머리인 행의 incident_id(중복 없이, 상한 limit건) */
    List<String> findThreadReplyIncidentIds(@Param("headIncidentId") String headIncidentId,
                                            @Param("limit") int limit);

    /** T40 묶음 구성원 가운데 허용 캡처 안이고 최신 큐에 있는 행 수 */
    long countLatestQueueByIncidentIds(@Param("captureIds") List<String> captureIds,
                                       @Param("incidentIds") String[] incidentIds);

    /* T45 큐 묶음 표지(쪽 행 수와 무관하게 한 번씩). 빈 배열·빈 목록으로는 부르지 않는다. */

    /** 인시던트들의 Slack 기록에서 (incident_id, zeekad_thread_parent 원문) 짝(중복 없이) */
    List<com.zeekad.dashboard.model.zeekad.SlackThreadLink> findSlackThreadLinksByIncidentIds(
            @Param("incidentIds") String[] incidentIds);

    /** 머리들의 답글 짝: TRIM(zeekad_thread_parent)이 heads 안인 행의 (incident_id, 그 머리)(중복 없이, 상한 limit건) */
    List<com.zeekad.dashboard.model.zeekad.SlackThreadLink> findThreadRepliesByHeads(@Param("heads") String[] heads,
                                                                                    @Param("limit") int limit);

    /** incident_id별 허용 캡처 안 최신 큐 행 수(countLatestQueueByIncidentIds와 같은 행 집합을 incident_id로 나눈 것) */
    List<com.zeekad.dashboard.model.zeekad.IncidentRowCount> countLatestQueueRowsByIncidentIds(
            @Param("captureIds") List<String> captureIds,
            @Param("incidentIds") String[] incidentIds);

    /**
     * T45b 현황판 주요 알림 묶음: 머리 인시던트들의 최신 큐 행(incident_id·capture_id·host_ip·zeekad_picked_by만).
     * 허용 캡처 전체 범위에서 한 번 읽는다. 빈 배열·빈 목록으로는 부르지 않는다.
     */
    List<com.zeekad.dashboard.model.zeekad.ThreadHeadRow> findLatestQueueHeadRows(
            @Param("captureIds") List<String> captureIds,
            @Param("incidentIds") String[] incidentIds);

    /* T45 큐 hostIp·attack 조건. captureIds가 비면 부르지 않는다. 기간·다른 거르기 조건은 넣지 않는다. */

    /** 캡처들의 최신 큐에 있는 host_ip 원문(중복 없이). 응답에 넣지 않고 조건 값 고르기에만 쓴다 */
    List<String> findDistinctLatestHostIps(@Param("captureIds") List<String> captureIds);

    /** 캡처들의 최신 큐 행이 가리키는 리포트(zeekad_report_job_id)의 ATT&amp;CK 후보(값이 없는 행은 뺀다) */
    List<com.zeekad.dashboard.model.zeekad.IncidentAttackCandidates> findLatestAttackCandidates(
            @Param("captureIds") List<String> captureIds);

    List<SlackSummary> findSlackSummaries(@Param("captureId") String captureId);

    IncidentStatus findIncidentStatus(@Param("incidentId") String incidentId);

    List<IncidentStatusHistory> findIncidentStatusHistory(@Param("incidentId") String incidentId);

    List<AnalystReviewItem> findAnalystReviewQueue(@Param("captureId") String captureId,
                                                   @Param("pendingOnly") Boolean pendingOnly);

    AnalystReviewItem findAnalystReviewByJobAndIncident(@Param("jobId") Long jobId,
                                                        @Param("incidentId") String incidentId);

    List<Map<String, Object>> findRawFeedbackSummaries(@Param("captureId") String captureId);

    /* T23 통합 인시던트 큐. c.captureIds가 비어 있으면 부르지 않는다. */

    List<UnifiedQueueRecord> findUnifiedQueue(@Param("c") UnifiedQueueCriteria criteria);

    long countUnifiedQueue(@Param("c") UnifiedQueueCriteria criteria);

    /**
     * T35 이전·다음: 목록과 같은 조건·정렬로 DB가 순번을 매겨 지금 행(jobId·queueRank)과 앞뒤 행(최대 3행)을 돌려준다.
     * 각 행에 순번(queuePos)과 조건에 맞는 전체 수(queueTotal)가 붙는다. 지금 행이 조건 밖이면 빈 목록.
     * c.incidentId·limit·offset은 비워 넘긴다.
     */
    List<com.zeekad.dashboard.model.zeekad.UnifiedQueueNeighborRecord> findUnifiedQueueNeighbors(
            @Param("c") UnifiedQueueCriteria criteria,
            @Param("jobId") long jobId,
            @Param("queueRank") int queueRank);

    UnifiedQueueSummaryRow summarizeUnifiedQueue(@Param("c") UnifiedQueueCriteria criteria);

    OffsetDateTime findMaxUnifiedDetectedAt(@Param("c") UnifiedQueueCriteria criteria);

    /** T29 기간 조건 없이 한 번 훑어 기간 안·전체 수와 기간 안 최대·기간 시작 이하 최대 탐지 시각. c의 기간 조건은 비워 넘긴다 */
    com.zeekad.dashboard.model.zeekad.UnifiedQueuePeriodSplit splitUnifiedQueueByPeriod(
            @Param("c") UnifiedQueueCriteria criteria,
            @Param("after") OffsetDateTime after,
            @Param("until") OffsetDateTime until);

    /** T29 캡처별 최신 큐 인시던트의 가장 늦은 탐지 시각 */
    List<com.zeekad.dashboard.model.zeekad.CaptureLastDetected> findCaptureLastDetected(
            @Param("captureIds") List<String> captureIds);

    OffsetDateTime findMaxSucceededFinishedAt(@Param("captureIds") List<String> captureIds);

    List<CaptureQueueStat> findCaptureQueueStats(@Param("captureIds") List<String> captureIds);

    List<String> findDistinctLatestPickedBy(@Param("captureIds") List<String> captureIds);

    List<String> findDistinctLatestRoles(@Param("captureIds") List<String> captureIds);

    /* ───── T24 현황판·운영 현황 ───── */

    /** 통합 큐와 같은 조건(c 그대로)의 가벼운 투영. T45b: 인시던트 ID·호스트·통신 방향도 같이 읽는다 */
    List<IncidentPoint> findUnifiedQueuePoints(@Param("c") UnifiedQueueCriteria criteria);

    /** 캡처별 최근 끝난 작업·최근 성공 작업 ID와 (after, until] 안 실패 작업 수(finished_at, 없으면 started_at). null이면 그 쪽 시각 조건 없음 */
    List<CaptureJobStat> findCaptureJobStats(@Param("captureIds") List<String> captureIds,
                                             @Param("after") OffsetDateTime after,
                                             @Param("until") OffsetDateTime until);

    List<ScoringJob> findScoringJobsByIds(@Param("jobIds") List<Long> jobIds);

    /** 캡처 목록의 작업(새로운 순). 시각은 finished_at(없으면 started_at) 기준 (after, until], limit null이면 전부 */
    List<ScoringJob> findScoringJobsForCaptures(@Param("captureIds") List<String> captureIds,
                                                @Param("after") OffsetDateTime after,
                                                @Param("until") OffsetDateTime until,
                                                @Param("limit") Integer limit);

    long countScoringJobsForCaptures(@Param("captureIds") List<String> captureIds,
                                     @Param("after") OffsetDateTime after,
                                     @Param("until") OffsetDateTime until);

    /** 캡처 목록의 작업이 쓴 모델 버전만(scoring_jobs.bundle_id 경유) */
    List<ModelBundle> findModelBundlesUsedByCaptures(@Param("captureIds") List<String> captureIds);

    /** 캡처 목록의 Slack 일일 요약(created_at (after, until]), 새로운 순 */
    List<SlackSummary> findSlackSummariesForCaptures(@Param("captureIds") List<String> captureIds,
                                                     @Param("after") OffsetDateTime after,
                                                     @Param("until") OffsetDateTime until);

    /** T25 처리 시간 지표·담당 현황 투영(after가 있으면 SQL 하한으로 먼저 줄임) */
    java.util.List<com.zeekad.dashboard.model.zeekad.HandlingPoint> findHandlingPoints(
            @Param("c") com.zeekad.dashboard.model.zeekad.UnifiedQueueCriteria c,
            @Param("after") java.time.OffsetDateTime after);

    /* ───────────── T27 인시던트 번호 ───────────── */

    /**
     * 번호 후보: latest_incident_queue 전체(모든 캡처)의 incident_id·capture_id·탐지 시각.
     * 탐지 시각은 통합 큐(unifiedQueueBase의 fs.detected_at)와 같은 정의다.
     */
    List<com.zeekad.dashboard.model.IncidentRef> findLatestIncidentRefCandidates();

    /** 번호 후보(행만): 주어진 incident_id가 든 성공 작업 기준의 캡처·탐지 시각. 성공 작업에 없으면 결과에 없다 */
    List<com.zeekad.dashboard.model.IncidentRef> findIncidentRefCandidatesByIds(@Param("incidentIds") String[] incidentIds);

    /** 최신 큐에서의 위치(없으면 null) */
    com.zeekad.dashboard.model.zeekad.IncidentLocation findLatestLocationByIncidentId(@Param("incidentId") String incidentId);

    /** 그 인시던트가 든 가장 최근 성공 작업의 위치(없으면 null) */
    com.zeekad.dashboard.model.zeekad.IncidentLocation findLastSucceededLocationByIncidentId(@Param("incidentId") String incidentId);
}
