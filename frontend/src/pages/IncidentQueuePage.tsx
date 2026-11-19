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
  ShieldAlert,
} from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import {
  IncidentStatusBadge,
  ResolutionBadge,
  ReviewActionBadge,
  SocBadge,
} from '../components/StatusBadge';
import type { IncidentQueueResponse } from '../types/api';
import { formatDateTime, formatDuration, formatNumber } from '../utils/format';

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
      setErrorMsg(err instanceof ApiError ? err.message : '조사 큐 데이터를 불러오지 못했습니다.');
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
    <AppShell
      title="이상탐지 조사 큐"
      subtitle="dashboard.latest_incident_queue 기반 캡처별 최신 우선순위 큐 및 과거 작업 전환"
    >
      <div className="space-y-5">
        {data?.maskedView && (
          <div className="flex items-center gap-2.5 rounded-xl border border-amber-500/35 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200">
            <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              조회자(VIEWER) 권한으로 접속 중입니다. 호스트 IP·사용자 계정명·상대 IP·가명 실제 IP는 서버에서 마스킹되어 표시됩니다.
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>전체 사건 수</span>
              <Layers className="h-4 w-4 text-cyan-400" />
            </div>
            <div className="mt-2 font-mono text-2xl font-bold tabular-nums text-slate-100">
              {formatNumber(kpis.total)}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              선택 캡처 {data?.selectedCaptureId ?? '-'} · 작업 #{data?.selectedJob?.jobId ?? '-'}
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>상태별 분포 (open / investigating / closed)</span>
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2 font-mono text-xl font-bold tabular-nums">
              <span className="text-rose-300">{kpis.openCount}</span>
              <span className="text-slate-600">/</span>
              <span className="text-amber-300">{kpis.investigatingCount}</span>
              <span className="text-slate-600">/</span>
              <span className="text-emerald-300">{kpis.closedCount}</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              미해결 · 확인 중 · 종료 건수
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>분석가 승인 대기</span>
              <Clock className="h-4 w-4 text-amber-400" />
            </div>
            <div className="mt-2 font-mono text-2xl font-bold tabular-nums text-amber-300">
              {formatNumber(kpis.reviewPendingCount)}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              <Link to="/reviews?pendingOnly=true" className="text-cyan-300 hover:underline">
                승인 대기 화면으로 이동
              </Link>
            </div>
          </div>

          <div className="soc-card p-4">
            <div className="flex items-center justify-between text-xs font-medium text-slate-400">
              <span>Slack 전송 대상</span>
              <BellRing className="h-4 w-4 text-purple-400" />
            </div>
            <div className="mt-2 font-mono text-2xl font-bold tabular-nums text-purple-300">
              {formatNumber(kpis.wouldSendCount)}
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              단계 5 전송 판단 기준(would_send=true)
            </div>
          </div>
        </div>

        <section className="soc-card p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
              <Filter className="h-3.5 w-3.5 text-cyan-400" />
              캡처 · 작업 · 조사 필터
            </div>
            <button
              type="button"
              onClick={handleResetFilters}
              className="soc-btn-secondary py-1 text-xs"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              필터 초기화
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
            <div>
              <label htmlFor="filter-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
                캡처 (Capture)
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
                {(data?.allowedCaptures?.length ?? 0) === 0 && (
                  <option value="">허용된 캡처 없음</option>
                )}
              </select>
            </div>

            <div>
              <label htmlFor="filter-job" className="mb-1 block text-[11px] font-medium text-slate-400">
                채점 작업 (Job)
              </label>
              <select
                id="filter-job"
                value={data?.selectedJob?.jobId ? String(data.selectedJob.jobId) : jobId}
                onChange={(e) => updateParam('jobId', e.target.value)}
                className="soc-select w-full font-mono text-xs"
              >
                {(data?.captureJobs ?? []).map((job, idx) => (
                  <option key={job.jobId} value={String(job.jobId)}>
                    #{job.jobId} · {job.bundleId} · {job.status}
                    {idx === 0 ? ' (최신)' : ''}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-model" className="mb-1 block text-[11px] font-medium text-slate-400">
                꼽은 모델 (pickedBy)
              </label>
              <select
                id="filter-model"
                value={pickedBy}
                onChange={(e) => updateParam('pickedBy', e.target.value)}
                className="soc-select w-full font-mono text-xs"
              >
                <option value="">전체 모델</option>
                {(data?.availableModels ?? []).map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-role" className="mb-1 block text-[11px] font-medium text-slate-400">
                역할 (Role)
              </label>
              <select
                id="filter-role"
                value={role}
                onChange={(e) => updateParam('role', e.target.value)}
                className="soc-select w-full font-mono text-xs"
              >
                <option value="">전체 역할</option>
                {(data?.availableRoles ?? []).map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="filter-status" className="mb-1 block text-[11px] font-medium text-slate-400">
                사건 상태 (Status)
              </label>
              <select
                id="filter-status"
                value={status}
                onChange={(e) => updateParam('status', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">전체 상태</option>
                <option value="open">미해결 (open)</option>
                <option value="investigating">확인 중 (investigating)</option>
                <option value="closed">종료 (closed)</option>
              </select>
            </div>

            <div>
              <label htmlFor="filter-has-report" className="mb-1 block text-[11px] font-medium text-slate-400">
                단계 5 보고서 유무
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
                Slack 전송 판단
              </label>
              <select
                id="filter-would-send"
                value={wouldSend}
                onChange={(e) => updateParam('wouldSend', e.target.value)}
                className="soc-select w-full text-xs"
              >
                <option value="">전체</option>
                <option value="true">전송 대상</option>
                <option value="false">보류 / 미전송</option>
              </select>
            </div>

            <form onSubmit={handleAssetSubmit}>
              <label htmlFor="filter-asset" className="mb-1 block text-[11px] font-medium text-slate-400">
                자산 IP / 호스트명 검색
              </label>
              <div className="flex gap-1.5">
                <input
                  id="filter-asset"
                  type="text"
                  value={assetDraft}
                  onChange={(e) => setAssetDraft(e.target.value)}
                  placeholder="IP 또는 호스트명"
                  className="soc-input py-1.5 font-mono text-xs"
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
          <LoadingPanel label="조사 큐를 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">순위</th>
                    <th className="soc-th">호스트 IP / 이름</th>
                    <th className="soc-th">역할</th>
                    <th className="soc-th">관측 시각 · 지속 시간</th>
                    <th className="soc-th">탐지 모델</th>
                    <th className="soc-th">단계 5 보고서</th>
                    <th className="soc-th">전송 판단</th>
                    <th className="soc-th">상태 · 결론</th>
                    <th className="soc-th">검토 상태</th>
                    <th className="soc-th text-right">상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.incidents ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-4 py-12 text-center text-sm text-slate-400">
                        조건에 해당하는 이상탐지 사건이 없습니다.
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
                          <td className="soc-td font-mono font-bold tabular-nums text-cyan-300">
                            #{item.queueRank}
                          </td>
                          <td className="soc-td">
                            <div className="font-mono text-xs font-semibold text-slate-100">
                              {item.hostIp}
                            </div>
                            {item.hostName.length > 0 && (
                              <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                                {item.hostName.join(', ')}
                              </div>
                            )}
                            <div className="mt-1 font-mono text-[10px] text-slate-500">
                              연결 {formatNumber(item.connectionCount)}건
                            </div>
                          </td>
                          <td className="soc-td font-mono text-xs text-slate-300">
                            {item.zeekadRole}
                          </td>
                          <td className="soc-td text-xs">
                            <div className="font-mono tabular-nums text-slate-200">
                              {formatDateTime(item.eventStart)}
                            </div>
                            <div className="mt-0.5 font-mono text-[11px] tabular-nums text-slate-400">
                              ~ {formatDateTime(item.eventEnd)}
                            </div>
                            <div className="mt-1">
                              <SocBadge tone="slate">
                                지속 {formatDuration(item.eventStart, item.eventEnd)}
                              </SocBadge>
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <div className="font-mono font-semibold text-cyan-200">
                              {item.zeekadPickedBy ?? '-'}
                            </div>
                            {item.zeekadAlsoFlaggedBy.length > 0 && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                <SocBadge tone="purple">
                                  중복 탐지 +{item.zeekadAlsoFlaggedBy.length}
                                </SocBadge>
                                <span className="font-mono text-[10px] text-slate-400">
                                  {item.zeekadAlsoFlaggedBy.join(', ')}
                                </span>
                              </div>
                            )}
                          </td>
                          <td className="soc-td text-xs">
                            {item.zeekadReportJobId === null ? (
                              <SocBadge tone="slate">보고서 없음</SocBadge>
                            ) : (
                              <div className="space-y-1">
                                <div className="flex flex-wrap items-center gap-1">
                                  <SocBadge tone={item.zeekadReportKind === 'llm' ? 'cyan' : 'slate'}>
                                    {item.zeekadReportKind ?? 'report'}
                                  </SocBadge>
                                  {item.zeekadVerificationPassed === true && (
                                    <SocBadge tone="emerald">검증 통과</SocBadge>
                                  )}
                                  {item.zeekadVerificationPassed === false && (
                                    <SocBadge tone="rose">검증 실패</SocBadge>
                                  )}
                                </div>
                                <div className="font-mono text-[11px] text-slate-400">
                                  보고 작업 #{item.zeekadReportJobId}
                                </div>
                              </div>
                            )}
                          </td>
                          <td className="soc-td text-xs">
                            {item.zeekadWouldSend ? (
                              <SocBadge tone="rose">전송 대상</SocBadge>
                            ) : (
                              <SocBadge tone="slate">보류</SocBadge>
                            )}
                          </td>
                          <td className="soc-td text-xs">
                            <div className="flex flex-col items-start gap-1">
                              <IncidentStatusBadge status={item.zeekadStatus} />
                              <ResolutionBadge resolution={item.zeekadResolution} />
                              {item.statusUpdatedAt && (
                                <span className="font-mono text-[10px] tabular-nums text-slate-400">
                                  갱신 {formatDateTime(item.statusUpdatedAt)}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <ReviewActionBadge
                              action={item.zeekadReviewAction}
                              pending={item.zeekadReviewPending}
                            />
                          </td>
                          <td className="soc-td text-right">
                            <Link
                              to={detailUrl}
                              className="soc-btn-secondary inline-flex py-1.5 text-xs"
                            >
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
