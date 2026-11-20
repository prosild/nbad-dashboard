import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, BarChart3, Info, Layers, MessageSquare } from 'lucide-react';
import { ApiError } from '../api/client';
import { operationsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { CodeLabel, JobStatusBadge, SocBadge, type BadgeTone } from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { FeedbackSummaryRecord, OperationsApiResponse } from '../types/api';
import { formatDateTime, formatNumber, formatPercent } from '../utils/format';

function isAllModelRow(row: FeedbackSummaryRecord): boolean {
  if (row.allModel !== undefined) {
    return row.allModel;
  }
  return (row.zeekadPickedBy ?? '').trim().toLowerCase() === 'all';
}

// 정밀도 문장은 백엔드 문구와 같은 형식이다. 문장 개편은 T20 범위라 이번에는 그대로 둔다.
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

/** 판정 건수 배지: 0이면 색을 쓰지 않는다 */
function ResolutionCountBadge({ code, count, tone }: { code: string; count: number; tone: BadgeTone }) {
  return (
    <SocBadge tone={count > 0 ? tone : 'muted'}>
      <CodeLabel dict="resolution" value={code} />
      <span className="tabular-nums">{formatNumber(count)}</span>
    </SocBadge>
  );
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
      setErrorMsg(err instanceof ApiError ? err.message : '운영 현황을 불러오지 못했습니다.');
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
    <AppShell title="운영 현황" subtitle="모델별 탐지 성과, 분석 실행 기록, Slack 일일 요약을 확인합니다">
      <div className="space-y-6">
        <section className="soc-card flex flex-wrap items-center justify-between gap-4 p-4">
          <div>
            <label htmlFor="ops-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
              수집 구간
            </label>
            <select
              id="ops-capture"
              value={captureId}
              onChange={(e) => handleCaptureChange(e.target.value)}
              className="soc-select text-xs"
            >
              <option value="">열람 허용 수집 구간 전체</option>
              {(data?.allowedCaptures ?? []).map((cap) => (
                <option key={cap} value={cap}>
                  {cap}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-wrap gap-3 text-xs tabular-nums text-slate-400">
            <span>판정 집계 {data?.feedbackSummaries.length ?? 0}행</span>
            <span>· 분석 실행 {data?.jobs.length ?? 0}건</span>
            <span>· 모델 구성 {data?.bundles.length ?? 0}개</span>
            <span>· Slack 일일 요약 {data?.slackSummaries.length ?? 0}건</span>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadOperations()} />}

        {loading && !data ? (
          <LoadingPanel label="운영 현황을 불러오는 중..." />
        ) : (
          <>
            <section className="soc-card space-y-4 p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                  <BarChart3 className="h-4 w-4 text-slate-400" />
                  분석가 판정 집계
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Info className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>이 표는 탐지된 사건만 셉니다. 놓친 공격 수는 알 수 없습니다.</span>
                </div>
              </div>

              {(data?.feedbackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
                  아직 분석가 판정이 기록된 사건이 없습니다.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left">
                    <thead>
                      <tr>
                        <th className="soc-th">수집 구간 · 모델 구성</th>
                        <th className="soc-th">주 탐지 모델</th>
                        <th className="soc-th text-right">사건 / 알림 / 판정</th>
                        <th className="soc-th">판정 분포</th>
                        <th className="soc-th">전체 정밀도</th>
                        <th className="soc-th">알림 정밀도 · 판정 비율</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(data?.feedbackSummaries ?? []).map((row, idx) => {
                        const isAll = isAllModelRow(row);
                        return (
                          <tr
                            key={`${row.captureId}-${row.bundleId}-${row.zeekadPickedBy}-${idx}`}
                            className={isAll ? 'bg-slate-800/40 hover:bg-slate-800/60' : 'hover:bg-slate-800/35'}
                          >
                            <td className="soc-td text-xs">
                              <div className="font-mono font-semibold text-slate-100">{row.captureId ?? '-'}</div>
                              <div className="mt-0.5 font-mono text-[11px] text-slate-400" data-raw="">
                                {row.bundleId ?? '-'}
                              </div>
                            </td>
                            <td className="soc-td text-xs">
                              {isAll ? (
                                <span className="font-semibold text-slate-100">모든 모델 합계</span>
                              ) : (
                                <span className="font-mono text-slate-200" data-raw="">
                                  {row.zeekadPickedBy ?? '-'}
                                </span>
                              )}
                            </td>
                            <td className="soc-td soc-num text-xs text-slate-200">
                              <div>사건 {formatNumber(row.incidents)}</div>
                              <div className="text-slate-400">
                                알림 {formatNumber(row.alerted)} · 판정 {formatNumber(row.resolved)}
                              </div>
                            </td>
                            <td className="soc-td text-xs">
                              <div className="flex flex-wrap gap-1">
                                <ResolutionCountBadge code="true_positive" count={row.truePositive ?? 0} tone="danger" />
                                <ResolutionCountBadge code="false_positive" count={row.falsePositive ?? 0} tone="violet" />
                                <ResolutionCountBadge code="benign" count={row.benign ?? 0} tone="positive" />
                              </div>
                            </td>
                            <td className="soc-td min-w-[210px] text-xs">
                              <div className="tabular-nums text-slate-100">{buildPrecisionText(row)}</div>
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
                              <div className="tabular-nums text-slate-100">{buildAlertPrecisionText(row)}</div>
                              <div className="mt-1.5 grid grid-cols-2 gap-2">
                                <div>
                                  <div className="mb-0.5 text-[11px] tabular-nums text-slate-400">
                                    알림 정밀도{' '}
                                    {row.zeekadAlertPrecision !== null && row.zeekadAlertPrecision !== undefined
                                      ? row.zeekadAlertPrecision.toFixed(2)
                                      : '-'}
                                  </div>
                                  <SvgProgressBar
                                    value={row.zeekadAlertPrecision ?? 0}
                                    max={1}
                                    tone={
                                      row.zeekadAlertPrecision !== null && row.zeekadAlertPrecision !== undefined
                                        ? 'emerald'
                                        : 'slate'
                                    }
                                    label="알림 정밀도"
                                  />
                                </div>
                                <div>
                                  <div className="mb-0.5 text-[11px] tabular-nums text-slate-400">
                                    판정 비율 {formatPercent(row.zeekadAlertResolvedRate)}
                                  </div>
                                  <SvgProgressBar
                                    value={row.zeekadAlertResolvedRate ?? 0}
                                    max={1}
                                    tone={
                                      row.zeekadAlertResolvedRate !== null && row.zeekadAlertResolvedRate !== undefined
                                        ? 'purple'
                                        : 'slate'
                                    }
                                    label="알림 판정 비율"
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
                <Activity className="h-4 w-4 text-slate-400" />
                분석 실행 기록
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr>
                      <th className="soc-th">완료 시각</th>
                      <th className="soc-th">수집 구간</th>
                      <th className="soc-th">모델 구성</th>
                      <th className="soc-th">상태</th>
                      <th className="soc-th text-right">사건 수</th>
                      <th className="soc-th">시작 시각</th>
                      <th className="soc-th">오류</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.jobs ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-xs text-slate-400">
                          분석 실행 기록이 없습니다.
                        </td>
                      </tr>
                    ) : (
                      (data?.jobs ?? []).map((job) => (
                        <tr key={job.jobId} className="hover:bg-slate-800/35">
                          <td
                            className="soc-td whitespace-nowrap text-xs font-semibold tabular-nums text-slate-100"
                            title={`분석 실행 #${job.jobId}`}
                          >
                            {formatDateTime(job.finishedAt)}
                          </td>
                          <td className="soc-td font-mono text-xs">{job.captureId}</td>
                          <td className="soc-td font-mono text-xs text-slate-300" data-raw="">
                            {job.bundleId}
                          </td>
                          <td className="soc-td text-xs">
                            <JobStatusBadge status={job.status} />
                          </td>
                          <td className="soc-td soc-num text-xs">{formatNumber(job.incidentCount)}</td>
                          <td className="soc-td whitespace-nowrap text-xs tabular-nums text-slate-400">
                            {formatDateTime(job.startedAt)}
                          </td>
                          <td className="soc-td max-w-xs break-all text-xs text-amber-200">{job.error || '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="soc-card space-y-4 p-5">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-semibold text-slate-100">
                <Layers className="h-4 w-4 text-slate-400" />
                모델 구성
              </div>
              {(data?.bundles ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">등록된 모델 구성이 없습니다.</div>
              ) : (
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  {(data?.bundles ?? []).map((bundle) => {
                    const thresholds = bundle.thresholdEntries ?? {};
                    const thresholdList = Object.entries(thresholds);
                    return (
                      <div key={bundle.bundleId} className="soc-panel space-y-2.5 p-4 text-xs">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-mono text-sm font-bold text-slate-100" data-raw="">
                            {bundle.bundleId}
                          </span>
                          <span className="text-[11px] tabular-nums text-slate-400">
                            등록 {formatDateTime(bundle.registeredAt)}
                          </span>
                        </div>
                        <div className="text-slate-400">
                          등록 이름{' '}
                          <span className="font-mono text-slate-300" data-raw="">
                            {bundle.registryName ?? '-'}
                          </span>{' '}
                          · 판{' '}
                          <span className="font-mono text-slate-300" data-raw="">
                            {bundle.registryVersion ?? '-'}
                          </span>
                        </div>
                        {bundle.manifestSha256 && (
                          <div className="truncate text-[11px] text-slate-500">
                            구성 파일 해시{' '}
                            <span className="font-mono" data-raw="">
                              {bundle.manifestSha256}
                            </span>
                          </div>
                        )}
                        {thresholdList.length > 0 && (
                          <div className="space-y-1 border-t border-slate-800 pt-2">
                            <div className="text-[11px] text-slate-400">모델별 기준값</div>
                            <div className="flex flex-wrap gap-1.5">
                              {thresholdList.map(([model, th]) => (
                                <SocBadge key={model} tone="neutral">
                                  <span className="font-mono" data-raw="">
                                    {model}
                                  </span>
                                  <span className="tabular-nums">{th}</span>
                                </SocBadge>
                              ))}
                            </div>
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
                <MessageSquare className="h-4 w-4 text-slate-400" />
                Slack 일일 요약
              </div>
              {(data?.slackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">Slack 일일 요약 기록이 없습니다.</div>
              ) : (
                <div className="space-y-3">
                  {(data?.slackSummaries ?? []).map((summary, idx) => (
                    <div key={`${summary.jobId ?? idx}-${summary.captureId ?? idx}`} className="soc-panel space-y-2 p-4 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className="font-mono font-semibold text-slate-100"
                            title={[
                              summary.jobId !== null ? `분석 실행 #${summary.jobId}` : null,
                              summary.zeekadMessageVersion ? `메시지 형식 ${summary.zeekadMessageVersion}` : null,
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                          >
                            {summary.captureId ?? '-'}
                          </span>
                          {summary.dryRunOrRecorded && <SocBadge tone="muted">시험 모드(실제 전송 안 함)</SocBadge>}
                        </div>
                        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
                          {formatDateTime(summary.deliveredAt ?? summary.createdAt)}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        채널 <span className="font-mono text-slate-300">{summary.payloadChannel ?? '-'}</span> · 전송 결과{' '}
                        <CodeLabel dict="slackDeliveryStatus" value={summary.zeekadDeliveryStatus} className="text-slate-300" />
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
