import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, AlertCircle, BarChart3, Layers, MessageSquare } from 'lucide-react';
import { ApiError } from '../api/client';
import { operationsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { SocBadge } from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { FeedbackSummaryRecord, OperationsApiResponse } from '../types/api';
import { formatDateTime, formatNumber, formatPercent } from '../utils/format';

function isAllModelRow(row: FeedbackSummaryRecord): boolean {
  if (row.allModel !== undefined) {
    return row.allModel;
  }
  return (row.zeekadPickedBy ?? '').trim().toLowerCase() === 'all';
}

function buildPrecisionText(row: FeedbackSummaryRecord): string {
  if (row.precisionSummaryText) {
    return row.precisionSummaryText;
  }
  const incidents = row.incidents ?? 0;
  const resolved = row.resolved ?? 0;
  if (incidents <= 0) {
    return row.zeekadPrecision === null || row.zeekadPrecision === undefined
      ? '- (결론 없음)'
      : `정밀도 ${row.zeekadPrecision.toFixed(2)}`;
  }
  const pct = ((resolved / incidents) * 100).toFixed(1);
  if (row.zeekadPrecision !== null && row.zeekadPrecision !== undefined) {
    return `정밀도 ${row.zeekadPrecision.toFixed(2)}, 결론 ${resolved}/${incidents} (${pct}%)`;
  }
  return `- (결론 ${resolved}/${incidents}, ${pct}%)`;
}

function buildAlertPrecisionText(row: FeedbackSummaryRecord): string {
  if (row.alertPrecisionSummaryText) {
    return row.alertPrecisionSummaryText;
  }
  const alerted = row.alerted ?? 0;
  if (alerted <= 0) {
    return '- (알림 없음)';
  }
  const effResolved =
    row.effectiveAlertedResolved ??
    row.alertedResolved ??
    (row.zeekadAlertResolvedRate !== null && row.zeekadAlertResolvedRate !== undefined
      ? Math.round(row.zeekadAlertResolvedRate * alerted)
      : null);
  const rateSuffix =
    row.zeekadAlertResolvedRate !== null && row.zeekadAlertResolvedRate !== undefined
      ? ` (${(row.zeekadAlertResolvedRate * 100).toFixed(1)}%)`
      : '';
  if (effResolved === null) {
    return row.zeekadAlertPrecision === null || row.zeekadAlertPrecision === undefined
      ? '- (결론 없음)'
      : `정밀도 ${row.zeekadAlertPrecision.toFixed(2)}${rateSuffix}`;
  }
  if (row.zeekadAlertPrecision !== null && row.zeekadAlertPrecision !== undefined) {
    return `정밀도 ${row.zeekadAlertPrecision.toFixed(2)}, 결론 ${effResolved}/${alerted}${rateSuffix}`;
  }
  return `- (결론 ${effResolved}/${alerted}${rateSuffix})`;
}

export function OperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<OperationsApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const captureId = searchParams.get('captureId') ?? '';

  const loadOperations = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await operationsApi.get(captureId || undefined);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '운영 상태 데이터를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [captureId]);

  useEffect(() => {
    void loadOperations();
  }, [loadOperations]);

  function handleCaptureChange(value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set('captureId', value);
    else next.delete('captureId');
    setSearchParams(next);
  }

  return (
    <AppShell
      title="운영 상태 및 분석가 결론 집계"
      subtitle="dashboard.feedback_summary · scoring_jobs · model_bundles · slack_summaries"
    >
      <div className="space-y-6">
        <section className="soc-card flex flex-wrap items-center justify-between gap-4 p-4">
          <div>
            <label htmlFor="ops-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
              캡처 필터
            </label>
            <select
              id="ops-capture"
              value={captureId}
              onChange={(e) => handleCaptureChange(e.target.value)}
              className="soc-select font-mono text-xs"
            >
              <option value="">전체 허용 캡처</option>
              {(data?.allowedCaptures ?? []).map((cap) => (
                <option key={cap} value={cap}>
                  {cap}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-wrap gap-3 font-mono text-xs text-slate-400">
            <span>결론 집계 {data?.feedbackSummaries.length ?? 0}행</span>
            <span>· 채점 작업 {data?.jobs.length ?? 0}건</span>
            <span>· 번들 {data?.bundles.length ?? 0}개</span>
            <span>· Slack 요약 {data?.slackSummaries.length ?? 0}건</span>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadOperations()} />}

        {loading && !data ? (
          <LoadingPanel label="운영 상태 및 결론 집계를 불러오는 중..." />
        ) : (
          <>
            <section className="soc-card space-y-4 p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                  <BarChart3 className="h-4 w-4 text-cyan-400" />
                  분석가 결론 집계 (dashboard.feedback_summary)
                </div>
                <div className="flex items-center gap-1.5 rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-1 text-xs text-amber-200">
                  <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
                  <span>놓친 공격(재현율)은 이 집계로 알 수 없습니다.</span>
                </div>
              </div>

              {(data?.feedbackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
                  표시할 분석가 결론 집계 데이터가 없습니다.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left">
                    <thead>
                      <tr>
                        <th className="soc-th">캡처 · 번들</th>
                        <th className="soc-th">처음 뽑은 모델</th>
                        <th className="soc-th">사건 / 알림 / 결론</th>
                        <th className="soc-th">결론 3종 분포</th>
                        <th className="soc-th">전체 정밀도</th>
                        <th className="soc-th">알림 정밀도 · 결론 비율</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(data?.feedbackSummaries ?? []).map((row, idx) => {
                        const isAll = isAllModelRow(row);
                        return (
                          <tr
                            key={`${row.captureId}-${row.bundleId}-${row.zeekadPickedBy}-${idx}`}
                            className={
                              isAll
                                ? 'bg-cyan-500/10 hover:bg-cyan-500/15'
                                : 'hover:bg-slate-800/35'
                            }
                          >
                            <td className="soc-td font-mono text-xs">
                              <div className="font-semibold text-slate-100">
                                {row.captureId ?? '-'}
                              </div>
                              <div className="mt-0.5 text-[11px] text-slate-400">
                                {row.bundleId ?? '-'}
                              </div>
                            </td>
                            <td className="soc-td font-mono text-xs">
                              {isAll ? (
                                <SocBadge tone="cyan">전체 (all)</SocBadge>
                              ) : (
                                <span className="text-slate-200">{row.zeekadPickedBy ?? '-'}</span>
                              )}
                            </td>
                            <td className="soc-td font-mono text-xs tabular-nums text-slate-200">
                              <div>사건 {formatNumber(row.incidents)}</div>
                              <div className="text-slate-400">
                                알림 {formatNumber(row.alerted)} · 결론 {formatNumber(row.resolved)}
                              </div>
                            </td>
                            <td className="soc-td text-xs">
                              <div className="flex flex-wrap gap-1 font-mono tabular-nums">
                                <SocBadge tone="rose">TP {formatNumber(row.truePositive ?? 0)}</SocBadge>
                                <SocBadge tone="amber">FP {formatNumber(row.falsePositive ?? 0)}</SocBadge>
                                <SocBadge tone="slate">정상 {formatNumber(row.benign ?? 0)}</SocBadge>
                              </div>
                            </td>
                            <td className="soc-td min-w-[210px] text-xs">
                              <div className="font-mono text-slate-100">
                                {buildPrecisionText(row)}
                              </div>
                              <div className="mt-1.5">
                                <SvgProgressBar
                                  value={row.zeekadPrecision ?? 0}
                                  max={1}
                                  tone={row.zeekadPrecision !== null && row.zeekadPrecision !== undefined ? 'cyan' : 'slate'}
                                  label="전체 정밀도"
                                />
                              </div>
                            </td>
                            <td className="soc-td min-w-[220px] text-xs">
                              <div className="font-mono text-slate-100">
                                {buildAlertPrecisionText(row)}
                              </div>
                              <div className="mt-1.5 grid grid-cols-2 gap-2">
                                <div>
                                  <div className="mb-0.5 text-[10px] text-slate-400">
                                    알림 정밀도 ({row.zeekadAlertPrecision !== null && row.zeekadAlertPrecision !== undefined ? row.zeekadAlertPrecision.toFixed(2) : '-'})
                                  </div>
                                  <SvgProgressBar
                                    value={row.zeekadAlertPrecision ?? 0}
                                    max={1}
                                    tone={row.zeekadAlertPrecision !== null && row.zeekadAlertPrecision !== undefined ? 'emerald' : 'slate'}
                                    label="알림 정밀도"
                                  />
                                </div>
                                <div>
                                  <div className="mb-0.5 text-[10px] text-slate-400">
                                    결론 비율 ({formatPercent(row.zeekadAlertResolvedRate)})
                                  </div>
                                  <SvgProgressBar
                                    value={row.zeekadAlertResolvedRate ?? 0}
                                    max={1}
                                    tone={row.zeekadAlertResolvedRate !== null && row.zeekadAlertResolvedRate !== undefined ? 'purple' : 'slate'}
                                    label="알림 결론 비율"
                                  />
                                </div>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="soc-card space-y-4 p-5">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                <Activity className="h-4 w-4 text-cyan-400" />
                채점 작업 현황 (scoring_jobs)
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr>
                      <th className="soc-th">Job ID</th>
                      <th className="soc-th">캡처</th>
                      <th className="soc-th">번들</th>
                      <th className="soc-th">상태</th>
                      <th className="soc-th">사건 수</th>
                      <th className="soc-th">시작 · 완료 시각</th>
                      <th className="soc-th">오류</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.jobs ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-xs text-slate-400">
                          채점 작업 기록이 없습니다.
                        </td>
                      </tr>
                    ) : (
                      (data?.jobs ?? []).map((job) => (
                        <tr key={job.jobId} className="hover:bg-slate-800/35">
                          <td className="soc-td font-mono text-xs font-semibold text-cyan-300">
                            #{job.jobId}
                          </td>
                          <td className="soc-td font-mono text-xs">{job.captureId}</td>
                          <td className="soc-td font-mono text-xs text-slate-300">{job.bundleId}</td>
                          <td className="soc-td text-xs">
                            <SocBadge
                              tone={
                                job.status === 'succeeded'
                                  ? 'emerald'
                                  : job.status === 'failed'
                                    ? 'rose'
                                    : 'amber'
                              }
                            >
                              {job.status}
                            </SocBadge>
                          </td>
                          <td className="soc-td font-mono text-xs tabular-nums">
                            {formatNumber(job.incidentCount)}
                          </td>
                          <td className="soc-td font-mono text-xs tabular-nums text-slate-300">
                            <div>시작: {formatDateTime(job.startedAt)}</div>
                            <div className="text-slate-400">완료: {formatDateTime(job.finishedAt)}</div>
                          </td>
                          <td className="soc-td max-w-xs break-all font-mono text-xs text-rose-300">
                            {job.error || '-'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="soc-card space-y-4 p-5">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                <Layers className="h-4 w-4 text-cyan-400" />
                모델 번들 (model_bundles)
              </div>
              {(data?.bundles ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">
                  등록된 모델 번들이 없습니다.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  {(data?.bundles ?? []).map((bundle) => {
                    const thresholds = bundle.thresholdEntries ?? {};
                    const thresholdList = Object.entries(thresholds);
                    return (
                      <div key={bundle.bundleId} className="soc-panel space-y-2.5 p-4 text-xs">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-mono text-sm font-bold text-cyan-200">
                            {bundle.bundleId}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400">
                            {formatDateTime(bundle.registeredAt)}
                          </span>
                        </div>
                        <div className="font-mono text-slate-300">
                          {bundle.registryName ?? '-'} ({bundle.registryVersion ?? '-'})
                        </div>
                        {bundle.manifestSha256 && (
                          <div className="truncate font-mono text-[11px] text-slate-500">
                            sha256: {bundle.manifestSha256}
                          </div>
                        )}
                        {thresholdList.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 border-t border-slate-800 pt-2">
                            {thresholdList.map(([model, th]) => (
                              <SocBadge key={model} tone="slate">
                                {model}: {th}
                              </SocBadge>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <section className="soc-card space-y-4 p-5">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                <MessageSquare className="h-4 w-4 text-cyan-400" />
                Slack 일일 요약 (slack_summaries)
              </div>
              {(data?.slackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">
                  Slack 일일 요약 기록이 없습니다.
                </div>
              ) : (
                <div className="space-y-3">
                  {(data?.slackSummaries ?? []).map((summary, idx) => (
                    <div
                      key={`${summary.jobId ?? idx}-${summary.captureId ?? idx}`}
                      className="soc-panel space-y-2 p-4 text-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <SocBadge tone="cyan">{summary.captureId ?? '-'}</SocBadge>
                          <SocBadge tone="slate">작업 #{summary.jobId ?? '-'}</SocBadge>
                          {summary.zeekadMessageVersion && (
                            <SocBadge tone="slate">{summary.zeekadMessageVersion}</SocBadge>
                          )}
                          {summary.dryRunOrRecorded && (
                            <SocBadge tone="amber">기록만(dry-run)</SocBadge>
                          )}
                        </div>
                        <span className="font-mono text-[11px] tabular-nums text-slate-400">
                          {formatDateTime(summary.deliveredAt ?? summary.createdAt)}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-400">
                        채널: {summary.payloadChannel ?? '-'} · 상태: {summary.zeekadDeliveryStatus ?? '-'}
                      </div>
                      {summary.payloadTextPreview && (
                        <p className="whitespace-pre-wrap rounded border border-slate-800 bg-[#090f1d] p-3 text-xs text-slate-200">
                          {summary.payloadTextPreview}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </AppShell>
  );
}
