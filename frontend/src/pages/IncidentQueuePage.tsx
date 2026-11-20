import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  BellRing,
  CheckCircle2,
  Clock,
  ExternalLink,
  Filter,
  Layers,
  RotateCcw,
} from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import {
  CodeLabel,
  IncidentStatusBadge,
  ResolutionBadge,
  ReviewActionBadge,
  SocBadge,
  VerificationBadge,
  WouldSendBadge,
} from '../components/StatusBadge';
import type { IncidentQueueResponse, ScoringJob } from '../types/api';
import { formatDateTime, formatDuration, formatNumber } from '../utils/format';
import { labelText } from '../utils/labels';

/** 분석 실행은 날짜·시각으로 보여 주고 실행 번호는 툴팁에만 둔다. */
function jobTimeLabel(job: ScoringJob | null | undefined): string {
  if (!job) {
    return '-';
  }
  const when = job.finishedAt ?? job.startedAt;
  return when ? formatDateTime(when) : '시각 미기록';
}

export function IncidentQueuePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<IncidentQueueResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const captureId = searchParams.get('captureId') ?? '';
  const jobId = searchParams.get('jobId') ?? '';
  const pickedBy = searchParams.get('pickedBy') ?? '';
  const role = searchParams.get('role') ?? '';
  const asset = searchParams.get('asset') ?? '';
  const status = searchParams.get('status') ?? '';
  const hasReport = searchParams.get('hasReport') ?? '';
  const wouldSend = searchParams.get('wouldSend') ?? '';

  const [assetDraft, setAssetDraft] = useState(asset);

  useEffect(() => {
    setAssetDraft(asset);
  }, [asset]);

  const loadQueue = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await incidentsApi.list({
        captureId: captureId || undefined,
        jobId: jobId || undefined,
        pickedBy: pickedBy || undefined,
        role: role || undefined,
        asset: asset || undefined,
        status: status || undefined,
        hasReport: hasReport || undefined,
        wouldSend: wouldSend || undefined,
      });
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '사건 목록을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [captureId, jobId, pickedBy, role, asset, status, hasReport, wouldSend]);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  function updateParam(key: string, value: string, clearJobId = false) {
    const next = new URLSearchParams(searchParams);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    if (clearJobId) {
      next.delete('jobId');
    }
    setSearchParams(next);
  }

  function handleResetFilters() {
    const next = new URLSearchParams();
    if (data?.selectedCaptureId) {
      next.set('captureId', data.selectedCaptureId);
    }
    setAssetDraft('');
    setSearchParams(next);
  }

  function handleAssetSubmit(e: React.FormEvent) {
    e.preventDefault();
    updateParam('asset', assetDraft.trim());
  }

  const kpis = useMemo(() => {
    const list = data?.incidents ?? [];
    let openCount = 0;
    let investigatingCount = 0;
    let closedCount = 0;
    let reviewPendingCount = 0;
    let wouldSendCount = 0;

    for (const item of list) {
      const st = (item.zeekadStatus ?? 'open').toLowerCase();
      if (st === 'open') openCount += 1;
      else if (st === 'investigating') investigatingCount += 1;
      else if (st === 'closed') closedCount += 1;

      if (item.zeekadReviewPending) reviewPendingCount += 1;
      if (item.zeekadWouldSend) wouldSendCount += 1;
    }

    return {
      total: list.length,
      openCount,
      investigatingCount,
      closedCount,
      reviewPendingCount,
      wouldSendCount,
    };
  }, [data]);

  return (
    <AppShell title="탐지 사건" subtitle="탐지 모델이 올린 사건을 우선순위 순으로 확인하고 조사합니다">
      <div className="space-y-5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>전체 사건 수</span>
              <Layers className="h-4 w-4 text-slate-400" />
            </div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-slate-100">{formatNumber(kpis.total)}</div>
            <div className="mt-1 text-[11px] text-slate-400">
              수집 구간 <span className="font-mono">{data?.selectedCaptureId ?? '-'}</span> · 분석 실행{' '}
              <span
                className="tabular-nums"
                title={data?.selectedJob ? `분석 실행 #${data.selectedJob.jobId}` : undefined}
              >
                {jobTimeLabel(data?.selectedJob)}
              </span>
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>처리 상태</span>
              <CheckCircle2 className="h-4 w-4 text-slate-400" />
            </div>
            <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm text-slate-400">
              <span>
                {labelText('incidentStatus', 'open')}{' '}
                <span className="text-xl font-bold tabular-nums text-slate-100">{formatNumber(kpis.openCount)}</span>
              </span>
              <span>
                {labelText('incidentStatus', 'investigating')}{' '}
                <span className="text-xl font-bold tabular-nums text-sky-200">
                  {formatNumber(kpis.investigatingCount)}
                </span>
              </span>
              <span>
                {labelText('incidentStatus', 'closed')}{' '}
                <span className="text-xl font-bold tabular-nums text-slate-300">{formatNumber(kpis.closedCount)}</span>
              </span>
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>분석가 판단 대기</span>
              <Clock className="h-4 w-4 text-amber-400" />
            </div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-amber-300">
              {formatNumber(kpis.reviewPendingCount)}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              <Link to="/reviews?pendingOnly=true" className="text-cyan-300 hover:underline">
                판단 요청 화면으로 이동
              </Link>
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>알림 보냄</span>
              <BellRing className="h-4 w-4 text-cyan-400" />
            </div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-slate-100">
              {formatNumber(kpis.wouldSendCount)}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">알림 전송 판단에서 Slack 알림을 보내기로 한 사건</div>
          </div>
        </div>

        <section className="soc-card p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="soc-subhead flex items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              필터
            </div>
            <button type="button" onClick={handleResetFilters} className="soc-btn-secondary py-1 text-xs">
              <RotateCcw className="h-3.5 w-3.5" />
              필터 초기화
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
            <div>
              <label htmlFor="filter-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
                수집 구간
              </label>
              <select
                id="filter-capture"
                value={data?.selectedCaptureId ?? captureId}
                onChange={(e) => updateParam('captureId', e.target.value, true)}
                className="soc-select w-full font-mono text-xs"
              >
                {(data?.allowedCaptures ?? []).map((cap) => (
                  <option key={cap} value={cap}>
                    {cap}
                  </option>
                ))}
                {(data?.allowedCaptures?.length ?? 0) === 0 && <option value="">열람 허용 수집 구간 없음</option>}
              </select>
            </div>

            <div>
              <label htmlFor="filter-job" className="mb-1 block text-[11px] font-medium text-slate-400">
                분석 실행
              </label>
              <select
                id="filter-job"
                value={data?.selectedJob?.jobId ? String(data.selectedJob.jobId) : jobId}
                onChange={(e) => updateParam('jobId', e.target.value)}
                className="soc-select w-full text-xs tabular-nums"
              >
                {(data?.captureJobs ?? []).map((job, idx) => (
                  <option key={job.jobId} value={String(job.jobId)} title={`분석 실행 #${job.jobId}`}>
                    {jobTimeLabel(job)} · {job.bundleId} · {labelText('jobStatus', job.status)}
                    {idx === 0 ? ' · 최신' : ''}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-model" className="mb-1 block text-[11px] font-medium text-slate-400">
                주 탐지 모델
              </label>
              <select
                id="filter-model"
                value={pickedBy}
                onChange={(e) => updateParam('pickedBy', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">모든 모델</option>
                {(data?.availableModels ?? []).map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-role" className="mb-1 block text-[11px] font-medium text-slate-400">
                통신 방향
              </label>
              <select
                id="filter-role"
                value={role}
                onChange={(e) => updateParam('role', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">모든 방향</option>
                {(data?.availableRoles ?? []).map((r) => (
                  <option key={r} value={r}>
                    {labelText('hostRole', r)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-status" className="mb-1 block text-[11px] font-medium text-slate-400">
                사건 상태
              </label>
              <select
                id="filter-status"
                value={status}
                onChange={(e) => updateParam('status', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">모든 상태</option>
                <option value="open">{labelText('incidentStatus', 'open')}</option>
                <option value="investigating">{labelText('incidentStatus', 'investigating')}</option>
                <option value="closed">{labelText('incidentStatus', 'closed')}</option>
              </select>
            </div>

            <div>
              <label htmlFor="filter-has-report" className="mb-1 block text-[11px] font-medium text-slate-400">
                AI 분석 보고서
              </label>
              <select
                id="filter-has-report"
                value={hasReport}
                onChange={(e) => updateParam('hasReport', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">전체</option>
                <option value="true">보고서 있음</option>
                <option value="false">보고서 없음</option>
              </select>
            </div>

            <div>
              <label htmlFor="filter-would-send" className="mb-1 block text-[11px] font-medium text-slate-400">
                알림 전송 판단
              </label>
              <select
                id="filter-would-send"
                value={wouldSend}
                onChange={(e) => updateParam('wouldSend', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">전체</option>
                <option value="true">알림 보냄</option>
                <option value="false">알림 보류</option>
              </select>
            </div>

            <form onSubmit={handleAssetSubmit}>
              <label htmlFor="filter-asset" className="mb-1 block text-[11px] font-medium text-slate-400">
                자산 IP·호스트 이름 검색
              </label>
              <div className="flex gap-1.5">
                <input
                  id="filter-asset"
                  type="text"
                  value={assetDraft}
                  onChange={(e) => setAssetDraft(e.target.value)}
                  placeholder="IP 또는 호스트 이름"
                  className="soc-input py-1.5 text-xs"
                />
                <button type="submit" className="soc-btn-secondary shrink-0 px-3 py-1.5 text-xs">
                  적용
                </button>
              </div>
            </form>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadQueue()} />}

        {loading && !data ? (
          <LoadingPanel label="사건 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th text-right">순위</th>
                    <th className="soc-th">호스트</th>
                    <th className="soc-th">통신 방향</th>
                    <th className="soc-th">관측 구간 · 지속 시간</th>
                    <th className="soc-th">탐지 모델</th>
                    <th className="soc-th">AI 분석 보고서</th>
                    <th className="soc-th">알림</th>
                    <th className="soc-th">상태 · 판정</th>
                    <th className="soc-th">분석가 판단</th>
                    <th className="soc-th text-right">상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.incidents ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-4 py-12 text-center text-sm text-slate-400">
                        조건에 맞는 사건이 없습니다. 필터를 줄이거나 [필터 초기화]를 누르세요.
                      </td>
                    </tr>
                  ) : (
                    (data?.incidents ?? []).map((item) => {
                      const detailUrl = `/incidents/${item.jobId}/rank/${item.queueRank}`;
                      return (
                        <tr
                          key={`${item.jobId}-${item.queueRank}-${item.incidentId}`}
                          className="transition hover:bg-slate-800/35"
                        >
                          <td className="soc-td soc-num font-bold text-slate-100">{item.queueRank}</td>
                          <td className="soc-td">
                            <div className="font-mono text-xs font-semibold text-slate-100">{item.hostIp}</div>
                            {item.hostName.length > 0 && (
                              <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                                {item.hostName.join(', ')}
                              </div>
                            )}
                            <div className="mt-1 text-[11px] tabular-nums text-slate-400">
                              연결 {formatNumber(item.connectionCount)}건
                            </div>
                          </td>
                          <td className="soc-td whitespace-nowrap text-xs text-slate-300">
                            <CodeLabel dict="hostRole" value={item.zeekadRole} />
                          </td>
                          <td className="soc-td whitespace-nowrap text-xs tabular-nums">
                            <div className="text-slate-200">{formatDateTime(item.eventStart)}</div>
                            <div className="mt-0.5 text-[11px] text-slate-400">~ {formatDateTime(item.eventEnd)}</div>
                            <div className="mt-1 text-[11px] text-slate-400">
                              지속 {formatDuration(item.eventStart, item.eventEnd)}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <div className="font-mono font-semibold text-slate-100" data-raw="">
                              {item.zeekadPickedBy ?? '-'}
                            </div>
                            {item.zeekadAlsoFlaggedBy.length > 0 && (
                              <div className="mt-1">
                                <SocBadge tone="neutral" title={item.zeekadAlsoFlaggedBy.join(', ')}>
                                  함께 탐지한 모델 +{item.zeekadAlsoFlaggedBy.length}
                                </SocBadge>
                              </div>
                            )}
                          </td>
                          <td className="soc-td text-xs">
                            {item.zeekadReportJobId === null ? (
                              <span className="whitespace-nowrap text-slate-500">보고서 없음</span>
                            ) : (
                              <div
                                className="flex flex-wrap items-center gap-1"
                                title={`보고서 실행 #${item.zeekadReportJobId}`}
                              >
                                <SocBadge tone="neutral">
                                  <CodeLabel dict="reportKind" value={item.zeekadReportKind} />
                                </SocBadge>
                                <VerificationBadge passed={item.zeekadVerificationPassed} />
                              </div>
                            )}
                          </td>
                          <td className="soc-td text-xs">
                            <WouldSendBadge wouldSend={item.zeekadWouldSend} />
                          </td>
                          <td className="soc-td text-xs">
                            <div className="flex flex-col items-start gap-1">
                              <IncidentStatusBadge status={item.zeekadStatus} />
                              <ResolutionBadge resolution={item.zeekadResolution} />
                              {item.statusUpdatedAt && (
                                <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
                                  갱신 {formatDateTime(item.statusUpdatedAt)}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <ReviewActionBadge action={item.zeekadReviewAction} pending={item.zeekadReviewPending} />
                          </td>
                          <td className="soc-td text-right">
                            <Link to={detailUrl} className="soc-btn-secondary inline-flex py-1.5 text-xs">
                              상세
                              <ExternalLink className="h-3.5 w-3.5" />
                            </Link>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
