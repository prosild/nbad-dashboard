import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Cpu, Server, ShieldAlert, UserCheck } from 'lucide-react';
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
  IncidentStatusBadge,
  ResolutionBadge,
  SocBadge,
} from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { IncidentDetailApiResponse } from '../types/api';
import { formatDateTime, formatDuration, formatNumber } from '../utils/format';

export function IncidentDetailPage() {
  const { jobId, queueRank } = useParams<{ jobId: string; queueRank: string }>();
  const [data, setData] = useState<IncidentDetailApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    if (!jobId || !queueRank) {
      setErrorMsg('잘못된 사건 경로입니다.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await incidentsApi.detail(jobId, queueRank);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '사건 상세 정보를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [jobId, queueRank]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  const detail = data?.detail;
  const incident = detail?.incident;

  return (
    <AppShell
      title={incident ? `사건 상세 · ${incident.hostIp} (#${incident.queueRank})` : '사건 상세'}
      subtitle={incident ? `incident_id: ${incident.incidentId}` : undefined}
      actions={
        <Link
          to={incident ? `/incidents?captureId=${encodeURIComponent(incident.captureId)}` : '/incidents'}
          className="soc-btn-secondary py-1.5 text-xs"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          조사 큐로
        </Link>
      }
    >
      <div className="space-y-6">
        {data?.maskedView && (
          <div className="flex items-center gap-2.5 rounded-xl border border-amber-500/35 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200">
            <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              조회자(VIEWER) 마스킹 모드가 활성화되어 IP 및 계정명이 부분 가림 처리됩니다.
            </span>
          </div>
        )}

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadDetail()} />}

        {loading && !detail ? (
          <LoadingPanel label="사건 근거·보고서·판단 데이터를 조합하는 중..." />
        ) : detail && incident ? (
          <>
            <section className="soc-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <IncidentStatusBadge status={detail.currentStatus} />
                    <ResolutionBadge resolution={detail.currentResolution} />
                    <SocBadge tone="cyan">캡처: {incident.captureId}</SocBadge>
                    <SocBadge tone="slate">큐 작업 #{incident.jobId}</SocBadge>
                    <SocBadge tone="slate">
                      보고 작업:{' '}
                      {incident.zeekadReportJobId !== null
                        ? `#${incident.zeekadReportJobId}`
                        : '보고서 없음'}
                    </SocBadge>
                  </div>
                  <div className="font-mono text-xs text-slate-400">
                    incident_id: <span className="text-slate-200">{incident.incidentId}</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {incident.zeekadPickedBy && (
                    <SocBadge tone="cyan">꼽은 모델: {incident.zeekadPickedBy}</SocBadge>
                  )}
                  {incident.zeekadAlsoFlaggedBy.length > 0 && (
                    <SocBadge tone="purple">
                      중복 탐지: {incident.zeekadAlsoFlaggedBy.join(', ')}
                    </SocBadge>
                  )}
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="soc-panel p-3.5">
                  <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
                    <Server className="h-3.5 w-3.5 text-cyan-400" />
                    대상 호스트 · 이름
                  </div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-100">
                    {incident.hostIp}
                  </div>
                  <div className="mt-0.5 font-mono text-xs text-slate-400">
                    {incident.hostName.length > 0 ? incident.hostName.join(', ') : '호스트명 없음'}
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">역할 · 번들</div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-100">
                    {incident.zeekadRole}
                  </div>
                  <div className="mt-0.5 font-mono text-xs text-slate-400">
                    {incident.bundleId}
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">관측 구간 · 지속 시간</div>
                  <div className="mt-1 font-mono text-xs tabular-nums text-slate-200">
                    {formatDateTime(incident.eventStart)}
                  </div>
                  <div className="mt-0.5 font-mono text-xs tabular-nums text-slate-400">
                    ~ {formatDateTime(incident.eventEnd)} (
                    {formatDuration(incident.eventStart, incident.eventEnd)})
                  </div>
                </div>

                <div className="soc-panel p-3.5">
                  <div className="text-[11px] font-medium text-slate-400">총 연결 수 (큐 기준)</div>
                  <div className="mt-1 font-mono text-xl font-bold tabular-nums text-cyan-300">
                    {formatNumber(incident.connectionCount)}
                  </div>
                </div>
              </div>
            </section>

            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              <section className="soc-card space-y-3 p-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <Cpu className="h-4 w-4 text-cyan-400" />
                    모델 창 비율 (큐 작업 #{incident.jobId})
                  </div>
                  <span className="text-[11px] text-slate-400">
                    임계값 이상 창 수 / 전체 창 수
                  </span>
                </div>

                {detail.modelScores.length === 0 ? (
                  <p className="text-xs text-slate-400">모델 창 비율 정보가 없습니다.</p>
                ) : (
                  <div className="space-y-3">
                    {detail.modelScores.map((score) => {
                      const cand = score.candidateWindows ?? 0;
                      const total = score.windows ?? 0;
                      const ratioLabel = score.windowRatioLabel || `${cand} / ${total}`;
                      return (
                        <div key={score.zeekadModel} className="soc-panel space-y-1.5 p-3">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono font-semibold text-slate-100">
                              {score.zeekadModel}
                            </span>
                            <span className="font-mono font-bold tabular-nums text-cyan-300">
                              {ratioLabel}
                            </span>
                          </div>
                          <SvgProgressBar
                            value={cand}
                            max={total > 0 ? total : 1}
                            tone="cyan"
                            label={`${score.zeekadModel} 창 비율 ${ratioLabel}`}
                          />
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="soc-card space-y-3 p-5">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                  <UserCheck className="h-4 w-4 text-cyan-400" />
                  자산 관측 이름 (Kerberos / NTLM)
                </div>

                {detail.assetNames.length === 0 ? (
                  <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">
                    관측된 Kerberos/NTLM 사용자 이름이 없습니다.
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {detail.assetNames.map((asset, idx) => {
                      const extras = Object.entries(asset.extraAttributes ?? {});
                      return (
                        <div key={idx} className="soc-panel space-y-2 p-3.5 text-xs">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-mono font-semibold text-slate-100">
                              {asset.hostIp ?? '-'}
                            </span>
                            <span className="font-mono text-[11px] text-slate-400">
                              {asset.captureId ?? '-'}
                            </span>
                          </div>
                          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                            <div>
                              <span className="text-slate-400">Kerberos 사용자: </span>
                              <span className="font-mono text-cyan-200">
                                {asset.kerberosUser || '-'}
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-400">NTLM 사용자: </span>
                              <span className="font-mono text-cyan-200">
                                {asset.ntlmUser || '-'}
                              </span>
                            </div>
                          </div>
                          {extras.length > 0 && (
                            <div className="flex flex-wrap gap-2 border-t border-slate-800 pt-2 text-[11px] text-slate-400">
                              {extras.map(([k, v]) => (
                                <span key={k} className="font-mono">
                                  {k}: {String(v ?? '-')}
                                </span>
                              ))}
                            </div>
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
