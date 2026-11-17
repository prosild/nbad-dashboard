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
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

/**
 * zeekad 읽기 전용 DataSource(dashboard 스키마 v1·v2 뷰 12종) 조회 MyBatis 매퍼.
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

    List<SlackDelivery> findSlackDeliveries(@Param("jobId") Long jobId,
                                            @Param("incidentId") String incidentId);

    List<SlackSummary> findSlackSummaries(@Param("captureId") String captureId);

    IncidentStatus findIncidentStatus(@Param("jobId") Long jobId,
                                      @Param("incidentId") String incidentId);

    List<IncidentStatusHistory> findIncidentStatusHistory(@Param("jobId") Long jobId,
                                                          @Param("incidentId") String incidentId);

    List<AnalystReviewItem> findAnalystReviewQueue(@Param("captureId") String captureId,
                                                   @Param("pendingOnly") Boolean pendingOnly);
}
