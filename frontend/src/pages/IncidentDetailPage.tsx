import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Cpu, Server, UserCheck } from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { EvidenceSection } from '../components/incident/EvidenceSection';
import { IncidentStatusAndReviewSection } from '../components/incident/IncidentStatusAndReviewSection';
import { ReportSection } from '../components/incident/ReportSection';
import { SendDecisionSection } from '../components/incident/SendDecisionSection';
import { SlackThreadsSection } from '../components/incident/SlackThreadsSection';
import {
  CodeLabel,
  DetectionModelName,
  IncidentStatusBadge,
  ResolutionBadge,
  SocBadge,
} from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { IncidentDetailApiResponse } from '../types/api';
import { formatDateTime, formatDateTimeRange, formatDuration, formatNumber } from '../utils/format';
import { detectionModelInfo, labelText, lookupLabel } from '../utils/labels';

/** 자산 관측 항목 값: 시각은 표준 형식, 이름 종류는 사전, 숫자는 천 단위 구분 */
function AssetAttributeValue({ attrKey, value }: { attrKey: string; value: unknown }) {
  if (value === null || value === undefined || value === '') {
    return <span className="text-slate-500">-</span>;
  }
  if (attrKey === 'zeekad_name_kind') {
    return <CodeLabel dict="assetNameKind" value={String(value)} />;
  }
  if (attrKey === 'first_seen' || attrKey === 'last_seen') {
    return <span className="tabular-nums">{formatDateTime(String(value))}</span>;
  }
  if (typeof value === 'number') {
    return <span className="tabular-nums">{formatNumber(value)}</span>;
  }
  return <span className="font-mono">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>;
}

export function IncidentDetailPage() {
  const { jobId, queueRank } = useParams<{ jobId: string; queueRank: string }>();
  const [data, setData] = useState<IncidentDetailApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    if (!jobId || !queueRank) {
      setErrorMsg('잘못된 인시던트 경로입니다.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await incidentsApi.detail(jobId, queueRank);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '인시던트 정보를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [jobId, queueRank]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  const detail = data?.detail;
  const incident = detail?.incident;
  const jobWhen = detail?.job ? (detail.job.finishedAt ?? detail.job.startedAt) : null;

  return (
    <AppShell
      title={incident ? `인시던트 상세 · ${incident.hostIp} · ${incident.queueRank}위` : '인시던트 상세'}
      subtitle={
        incident
          ? `${formatDateTimeRange(incident.eventStart, incident.eventEnd)} · 캡처 ${incident.captureId}`
          : undefined
      }
      actions={
        <Link
          to={incident ? `/incidents?captureId=${encodeURIComponent(incident.captureId)}` : '/incidents'}
          className="soc-btn-secondary py-1.5 text-xs"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          인시던트 목록으로
        </Link>
      }
    >
      <div className="space-y-6">
        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadDetail()} />}

        {loading && !detail ? (
          <LoadingPanel label="인시던트 정보를 불러오는 중..." />
        ) : detail && incident ? (
          <>
            <section className="soc-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <IncidentStatusBadge status={detail.currentStatus} />
                    <ResolutionBadge resolution={detail.currentResolution} />
                    {incident.zeekadReportJobId === null && <SocBadge tone="muted">리포트 없음</SocBadge>}
                  </div>
                  <div className="text-xs text-slate-400">
                    인시던트 ID{' '}
                    <span className="break-all font-mono text-slate-200" data-raw="">
                      {incident.incidentId}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">
                    탐지 작업{' '}
                    <span className="tabular-nums text-slate-300" title={`탐지 작업 #${incident.jobId}`}>
                      {jobWhen ? formatDateTime(jobWhen) : `#${incident.jobId}`}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {incident.zeekadPickedBy && (
                    <span className="text-slate-400">
                      탐지 모델{' '}
                      <DetectionModelName
                        id={incident.zeekadPickedBy}
                        variant="detail"
                        className="font-semibold text-slate-100"
                      />
                    </span>
                  )}
                  {incident.zeekadAlsoFlaggedBy.length > 0 && (
                    <SocBadge
                      tone="neutral"
                      title={incident.zeekadAlsoFlaggedBy.map((m) => detectionModelInfo(m).tooltip).join('\n\n')}
                    >
                      교차 탐지 +{incident.zeekadAlsoFlaggedBy.length}
                    </SocBadge>
                  )}
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="soc-panel p-3.5">
                  <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
                    <Server className="h-3.5 w-3.5 text-slate-400" />
                    대상 호스트 · 이름
                  </div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-100">{incident.hostIp}</div>
                  <div className="mt-0.5 font-mono text-xs text-slate-400">
                    {incident.hostName.length > 0 ? incident.hostName.join(', ') : '호스트 이름 없음'}
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">통신 방향 · 모델 버전</div>
                  <div className="mt-1 text-sm font-bold text-slate-100">
                    <CodeLabel dict="hostRole" value={incident.zeekadRole} />
                  </div>
                  <div className="mt-0.5 font-mono text-xs text-slate-400" data-raw="">
                    {incident.bundleId}
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">관측 구간 · 지속 시간</div>
                  <div className="mt-1 text-xs tabular-nums text-slate-200">{formatDateTime(incident.eventStart)}</div>
                  <div className="mt-0.5 text-xs tabular-nums text-slate-400">
                    ~ {formatDateTime(incident.eventEnd)} · {formatDuration(incident.eventStart, incident.eventEnd)}
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">총 세션 수</div>
                  <div className="mt-1 text-xl font-bold tabular-nums text-slate-100">
                    {formatNumber(incident.connectionCount)}
                  </div>
                </div>
              </div>
            </section>

            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              <section className="soc-card space-y-3 p-5">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <Cpu className="h-4 w-4 text-slate-400" />
                    모델별 탐지 윈도우
                  </div>
                  <span className="text-[11px] text-slate-400">기준값을 넘은 윈도우 수 / 전체 윈도우 수</span>
                </div>

                {detail.modelScores.length === 0 ? (
                  <p className="text-xs text-slate-400">모델별 탐지 윈도우 정보가 없습니다.</p>
                ) : (
                  <div className="space-y-3">
                    {detail.modelScores.map((score) => {
                      const cand = score.candidateWindows ?? 0;
                      const total = score.windows ?? 0;
                      const ratioLabel = score.windowRatioLabel || `${cand} / ${total}`;
                      return (
                        <div key={score.zeekadModel} className="soc-panel space-y-1.5 p-3">
                          <div className="flex items-center justify-between text-xs">
                            <DetectionModelName
                              id={score.zeekadModel}
                              variant="detail"
                              className="font-semibold text-slate-100"
                            />
                            <span className="font-bold tabular-nums text-slate-100">{ratioLabel}</span>
                          </div>
                          <SvgProgressBar
                            value={cand}
                            max={total > 0 ? total : 1}
                            tone="cyan"
                            label={`${labelText('detectionModel', score.zeekadModel)} 탐지 윈도우 ${ratioLabel}`}
                          />
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="soc-card space-y-3 p-5">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                  <UserCheck className="h-4 w-4 text-slate-400" />
                  Kerberos·NTLM 관측 계정 이름
                </div>

                {detail.assetNames.length === 0 ? (
                  <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">
                    관측된 Kerberos·NTLM 계정 이름이 없습니다.
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {detail.assetNames.map((asset, idx) => {
                      const extras = Object.entries(asset.extraAttributes ?? {});
                      return (
                        <div key={idx} className="soc-panel space-y-2 p-3.5 text-xs">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-mono font-semibold text-slate-100">{asset.hostIp ?? '-'}</span>
                            <span className="font-mono text-[11px] text-slate-400">{asset.captureId ?? '-'}</span>
                          </div>
                          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                            <div>
                              <span className="text-slate-400">Kerberos 사용자 </span>
                              <span className="font-mono text-slate-100">{asset.kerberosUser || '-'}</span>
                            </div>
                            <div>
                              <span className="text-slate-400">NTLM 사용자 </span>
                              <span className="font-mono text-slate-100">{asset.ntlmUser || '-'}</span>
                            </div>
                          </div>
                          {extras.length > 0 && (
                            <dl className="grid grid-cols-1 gap-x-4 gap-y-1 border-t border-slate-800 pt-2 text-[11px] sm:grid-cols-2">
                              {extras.map(([k, v]) => {
                                const keyLabel = lookupLabel('assetAttribute', k);
                                return (
                                  <div key={k} className="flex justify-between gap-3">
                                    <dt className="text-slate-400">
                                      <CodeLabel dict="assetAttribute" value={keyLabel.raw} />
                                    </dt>
                                    <dd className="text-right text-slate-200">
                                      <AssetAttributeValue attrKey={k} value={v} />
                                    </dd>
                                  </div>
                                );
                              })}
                            </dl>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            </div>

            <EvidenceSection evidence={detail.evidence} />
            <ReportSection report={detail.report} />
            <SendDecisionSection sendDecision={detail.sendDecision} />
            <SlackThreadsSection threadGroups={detail.slackThreadGroups} />
            <IncidentStatusAndReviewSection
              jobId={incident.jobId}
              queueRank={incident.queueRank}
              currentStatus={detail.currentStatus}
              currentResolution={detail.currentResolution}
              statusUpdatedAt={detail.statusUpdatedAt}
              statusUpdatedByDisplay={detail.statusUpdatedByDisplay}
              canTransition={detail.canTransition}
              nextAllowedStatus={detail.nextAllowedStatus}
              statusHistory={detail.statusHistory}
              analystReview={detail.analystReview}
              onRefresh={loadDetail}
            />
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
