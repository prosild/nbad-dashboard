import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Bell,
  BellOff,
  ChevronLeft,
  ChevronRight,
  FileText,
  FileX,
  Filter,
  Info,
  RotateCcw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import {
  CodeLabel,
  DetectionModelName,
  IncidentStatusBadge,
  PRIORITY_TOOLTIP,
  PriorityBadge,
  ResolutionBadge,
  ReviewActionBadge,
} from '../components/StatusBadge';
import type { IncidentQueueItem, IncidentQueueResponse, ScoringJob } from '../types/api';
import { formatDateTime, formatDateTimeRange, formatDuration, formatNumber } from '../utils/format';
import { captureInfo, detectionModelInfo, labelText, lookupLabel } from '../utils/labels';
import {
  CLIENT_FILTER_KEYS,
  computePriority,
  DEFAULT_SORT_DIR,
  orderQueue,
  PAGE_SIZES,
  pageWindow,
  parsePageSize,
  parseQueueView,
  PRIORITY_VALUES,
  SERVER_FILTER_KEYS,
  type Priority,
  type SortDir,
  type SortKey,
} from '../utils/triage';

/** 탐지 작업은 날짜·시각으로 보여 주고 실행 번호는 툴팁에만 둔다. */
function jobTimeLabel(job: ScoringJob | null | undefined): string {
  if (!job) {
    return '-';
  }
  const when = job.finishedAt ?? job.startedAt;
  return when ? formatDateTime(when) : '시각 미기록';
}

/** 필터·정렬·쪽 크기 변경 때 지우는 쪽 번호 키 */
const PAGE_KEY = 'page';

type RowItem = { item: IncidentQueueItem; priority: Priority | null };

/**
 * 상세 주소. 목록의 쿼리(서버 필터·화면 필터·정렬·쪽)를 `from=`으로 넘겨 상세의 이전·다음과 목록 복귀가 같은 순서를 쓴다(T19 M1).
 * 캡처를 고르지 않은 기본 목록이면 서버가 고른 캡처를 넣어 새로 고침해도 같은 목록이 되게 한다.
 */
function detailUrl(item: IncidentQueueItem, listQuery: string): string {
  return `/incidents/${item.jobId}/rank/${item.queueRank}?${new URLSearchParams({ from: listQuery }).toString()}`;
}


export function IncidentQueuePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<IncidentQueueResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const captureId = searchParams.get('captureId') ?? '';
  const jobId = searchParams.get('jobId') ?? '';
  const pickedBy = searchParams.get('pickedBy') ?? '';
  const role = searchParams.get('role') ?? '';
  const asset = searchParams.get('asset') ?? '';
  const status = searchParams.get('status') ?? '';
  const hasReport = searchParams.get('hasReport') ?? '';
  const wouldSend = searchParams.get('wouldSend') ?? '';

  const view = parseQueueView(searchParams);
  const priorityFilter: Priority | null = view.priority;
  const reviewPendingFilter = view.reviewPending;
  const alertedFilter = view.alerted;
  const sortKey: SortKey = view.sortKey;
  const sortDir: SortDir = view.sortDir;
  const pageSize = parsePageSize(searchParams.get('size'));
  const rawPage = searchParams.get(PAGE_KEY);

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
      setErrorMsg(err instanceof ApiError ? err.message : '인시던트 목록을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [captureId, jobId, pickedBy, role, asset, status, hasReport, wouldSend]);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  /** URL 쿼리를 바꾼다. 기본은 쪽 번호를 지운다(1쪽으로). */
  function updateParams(changes: Record<string, string | null>, opts: { keepPage?: boolean; clearJobId?: boolean } = {}) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(changes)) {
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
    }
    if (opts.clearJobId) {
      next.delete('jobId');
    }
    if (!opts.keepPage && !(PAGE_KEY in changes)) {
      next.delete(PAGE_KEY);
    }
    setSearchParams(next);
  }

  function updateParam(key: string, value: string, clearJobId = false) {
    updateParams({ [key]: value || null }, { clearJobId });
  }

  /** 캡처·탐지 작업을 뺀 나머지를 모두 지운다. */
  function handleResetFilters() {
    const next = new URLSearchParams();
    const cap = captureId || data?.selectedCaptureId || '';
    if (cap) {
      next.set('captureId', cap);
    }
    if (jobId) {
      next.set('jobId', jobId);
    }
    setAssetDraft('');
    setSearchParams(next);
  }

  function handleAssetSubmit(e: React.FormEvent) {
    e.preventDefault();
    updateParam('asset', assetDraft.trim());
  }

  function handleSort(key: SortKey) {
    const dir: SortDir = key === sortKey ? (sortDir === 'asc' ? 'desc' : 'asc') : DEFAULT_SORT_DIR[key];
    updateParams({ sort: key, dir });
  }

  const rows: RowItem[] = useMemo(
    () => (data?.incidents ?? []).map((item) => ({ item, priority: computePriority(item) })),
    [data],
  );

  /** 요약 띠 건수: 서버 응답 집합(서버 필터 적용 뒤, 화면 필터 적용 전) 기준 */
  const summary = useMemo(() => {
    const counts = { total: rows.length, high: 0, medium: 0, low: 0, reviewPending: 0, alerted: 0 };
    for (const { item, priority } of rows) {
      if (priority) counts[priority] += 1;
      if (item.zeekadReviewPending) counts.reviewPending += 1;
      // T21: 경보 발송 = 사건 알림 Slack 기록(alerted). 발송 판단(zeekadWouldSend)이 아니다.
      if (item.alerted) counts.alerted += 1;
    }
    return counts;
  }, [rows]);

  // 화면 필터·정렬은 상세의 이전·다음과 같은 함수(orderQueue)를 쓴다.
  const filteredSorted = useMemo(() => {
    const priorityById = new Map(rows.map((r) => [r.item, r.priority]));
    const ordered = orderQueue(
      rows.map((r) => r.item),
      {
        priority: priorityFilter,
        reviewPending: reviewPendingFilter,
        alerted: alertedFilter,
        sortKey,
        sortDir,
      },
    );
    return ordered.map((item) => ({ item, priority: priorityById.get(item) ?? null }));
  }, [rows, priorityFilter, reviewPendingFilter, alertedFilter, sortKey, sortDir]);

  /** 상세로 넘기는 목록 쿼리 */
  const listQuery = useMemo(() => {
    const q = new URLSearchParams(searchParams);
    if (!q.get('captureId') && data?.selectedCaptureId) {
      q.set('captureId', data.selectedCaptureId);
    }
    return q.toString();
  }, [searchParams, data]);

  const win = pageWindow(filteredSorted.length, rawPage, pageSize);
  const pageRows = filteredSorted.slice(win.startIndex, win.endIndex);

  // 범위 밖 page는 마지막 쪽으로, 허용 밖 size는 50으로 URL을 고친다(응답을 받은 뒤에만).
  useEffect(() => {
    if (loading || !data) return;
    const next = new URLSearchParams(searchParams);
    let changed = false;
    if (rawPage !== null && rawPage !== String(win.page)) {
      if (win.page === 1) next.delete(PAGE_KEY);
      else next.set(PAGE_KEY, String(win.page));
      changed = true;
    }
    const rawSize = searchParams.get('size');
    if (rawSize !== null && rawSize !== String(pageSize)) {
      next.delete('size');
      changed = true;
    }
    if (changed) {
      setSearchParams(next, { replace: true });
    }
  }, [loading, data, rawPage, win.page, pageSize, searchParams, setSearchParams]);

  const chips = useMemo(() => {
    const list: { key: string; label: string; raw?: string }[] = [];
    if (pickedBy) {
      const model = lookupLabel('detectionModel', pickedBy);
      list.push(
        model.known
          ? { key: 'pickedBy', label: `탐지 모델: ${model.text}` }
          : { key: 'pickedBy', label: '탐지 모델', raw: pickedBy },
      );
    }
    if (role) list.push({ key: 'role', label: `통신 방향: ${labelText('hostRole', role)}` });
    if (status) list.push({ key: 'status', label: `인시던트 상태: ${labelText('incidentStatus', status)}` });
    if (hasReport)
      list.push({ key: 'hasReport', label: `AI 리포트: ${hasReport === 'true' ? '리포트 있음' : '리포트 없음'}` });
    if (wouldSend)
      list.push({ key: 'wouldSend', label: `발송 판단: ${wouldSend === 'true' ? '발송' : '보류'}` });
    if (asset) list.push({ key: 'asset', label: '자산 검색', raw: asset });
    if (priorityFilter) list.push({ key: 'priority', label: `우선순위: ${labelText('priority', priorityFilter)}` });
    if (reviewPendingFilter) list.push({ key: 'reviewPending', label: '에스컬레이션 대기만' });
    if (alertedFilter) list.push({ key: 'alerted', label: '경보 발송만' });
    return list;
  }, [pickedBy, role, status, hasReport, wouldSend, asset, priorityFilter, reviewPendingFilter, alertedFilter]);

  function toggleClientFilter(key: (typeof CLIENT_FILTER_KEYS)[number], value: string) {
    const current = searchParams.get(key);
    updateParams({ [key]: current === value ? null : value });
  }

  const serverFilterCount = SERVER_FILTER_KEYS.filter((k) => (searchParams.get(k) ?? '') !== '').length;

  return (
    <AppShell title="인시던트" subtitle="탐지 모델이 올린 인시던트를 우선순위 순으로 확인하고 분석합니다">
      <div className="space-y-3">
        <SummaryStrip
          summary={summary}
          priorityFilter={priorityFilter}
          reviewPendingFilter={reviewPendingFilter}
          alertedFilter={alertedFilter}
          onToggle={toggleClientFilter}
        />

        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <div className="flex min-w-0 flex-1 basis-full items-center gap-2 sm:basis-auto sm:flex-none">
              <label htmlFor="filter-capture" className="shrink-0 text-xs font-medium text-slate-400">
                캡처
              </label>
              <select
                id="filter-capture"
                value={data?.selectedCaptureId ?? captureId}
                onChange={(e) => updateParam('captureId', e.target.value, true)}
                className="soc-select w-full py-1.5 text-xs sm:w-60"
                title={captureInfo(data?.selectedCaptureId ?? captureId).tooltip || undefined}
              >
                {(data?.allowedCaptures ?? []).map((cap) => {
                  const info = captureInfo(cap);
                  return (
                    <option key={cap} value={cap} title={info.tooltip}>
                      {info.text}
                    </option>
                  );
                })}
                {(data?.allowedCaptures?.length ?? 0) === 0 && <option value="">열람 허용 캡처 없음</option>}
              </select>
            </div>

            <div className="flex min-w-0 flex-1 basis-full items-center gap-2 sm:basis-auto sm:flex-none">
              <label htmlFor="filter-job" className="shrink-0 text-xs font-medium text-slate-400">
                탐지 작업
              </label>
              <select
                id="filter-job"
                value={data?.selectedJob?.jobId ? String(data.selectedJob.jobId) : jobId}
                onChange={(e) => updateParam('jobId', e.target.value)}
                className="soc-select w-full py-1.5 text-xs tabular-nums sm:w-80"
              >
                {(data?.captureJobs ?? []).map((job, idx) => (
                  <option key={job.jobId} value={String(job.jobId)} title={`탐지 작업 #${job.jobId}`}>
                    {jobTimeLabel(job)} · {job.bundleId} · {labelText('jobStatus', job.status)}
                    {idx === 0 ? ' · 최신' : ''}
                  </option>
                ))}
              </select>
            </div>

            <span className="hidden h-5 w-px bg-slate-800 sm:block" aria-hidden="true" />

            <button
              type="button"
              onClick={() => setFiltersOpen((v) => !v)}
              aria-expanded={filtersOpen}
              aria-controls="queue-filter-panel"
              className="soc-btn-secondary py-1 text-xs"
            >
              <Filter className="h-3.5 w-3.5" aria-hidden="true" />
              필터
              {serverFilterCount > 0 && (
                <span className="rounded bg-cyan-500/20 px-1.5 text-[11px] tabular-nums text-cyan-200">
                  {serverFilterCount}
                </span>
              )}
            </button>

            {chips.length > 0 && (
              <ul className="flex flex-wrap items-center gap-1.5" aria-label="적용 중인 필터">
                {chips.map((chip) => (
                  <li key={chip.key}>
                    <button
                      type="button"
                      onClick={() => updateParam(chip.key, '')}
                      aria-label={`${chip.label}${chip.raw ? ` ${chip.raw}` : ''} 필터 지우기`}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800/70 px-2 py-0.5 text-xs text-slate-200 transition hover:border-slate-500"
                    >
                      <span>
                        {chip.label}
                        {chip.raw && (
                          <>
                            : <span className="font-mono" data-raw="">{chip.raw}</span>
                          </>
                        )}
                      </span>
                      <X className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <button
              type="button"
              onClick={handleResetFilters}
              className="ml-auto inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 transition hover:text-slate-100"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              필터 초기화
            </button>
          </div>

          {filtersOpen && (
            <div
              id="queue-filter-panel"
              className="mt-2.5 grid grid-cols-1 gap-3 border-t border-slate-800 pt-2.5 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6"
            >
              <div>
                <label htmlFor="filter-model" className="mb-1 block text-[11px] font-medium text-slate-400">
                  탐지 모델
                </label>
                <select
                  id="filter-model"
                  value={pickedBy}
                  onChange={(e) => updateParam('pickedBy', e.target.value)}
                  className="soc-select w-full py-1.5 text-xs"
                >
                  <option value="">모든 모델</option>
                  {(data?.availableModels ?? []).map((m) => (
                    <option key={m} value={m} title={detectionModelInfo(m).tooltip}>
                      {labelText('detectionModel', m)}
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
                  className="soc-select w-full py-1.5 text-xs"
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
                  인시던트 상태
                </label>
                <select
                  id="filter-status"
                  value={status}
                  onChange={(e) => updateParam('status', e.target.value)}
                  className="soc-select w-full py-1.5 text-xs"
                >
                  <option value="">모든 상태</option>
                  <option value="open">{labelText('incidentStatus', 'open')}</option>
                  <option value="investigating">{labelText('incidentStatus', 'investigating')}</option>
                  <option value="closed">{labelText('incidentStatus', 'closed')}</option>
                </select>
              </div>

              <div>
                <label htmlFor="filter-has-report" className="mb-1 block text-[11px] font-medium text-slate-400">
                  AI 리포트
                </label>
                <select
                  id="filter-has-report"
                  value={hasReport}
                  onChange={(e) => updateParam('hasReport', e.target.value)}
                  className="soc-select w-full py-1.5 text-xs"
                >
                  <option value="">전체</option>
                  <option value="true">리포트 있음</option>
                  <option value="false">리포트 없음</option>
                </select>
              </div>

              <div>
                <label htmlFor="filter-would-send" className="mb-1 block text-[11px] font-medium text-slate-400">
                  발송 판단
                </label>
                <select
                  id="filter-would-send"
                  value={wouldSend}
                  onChange={(e) => updateParam('wouldSend', e.target.value)}
                  className="soc-select w-full py-1.5 text-xs"
                >
                  <option value="">전체</option>
                  <option value="true">발송</option>
                  <option value="false">보류</option>
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
          )}
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadQueue()} />}

        {loading && !data ? (
          <LoadingPanel label="인시던트 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            {pageRows.length === 0 ? (
              <p className="px-4 py-12 text-center text-sm text-slate-400">
                조건에 맞는 인시던트가 없습니다. 필터를 줄이거나 [필터 초기화]를 누르세요.
              </p>
            ) : (
              <>
                <QueueTable
                  rows={pageRows}
                  sortKey={sortKey}
                  sortDir={sortDir}
                  onSort={handleSort}
                  listQuery={listQuery}
                />
                <QueueMobileList rows={pageRows} listQuery={listQuery} />
              </>
            )}
            <Pagination
              total={filteredSorted.length}
              win={win}
              pageSize={pageSize}
              onPage={(p) => updateParams({ [PAGE_KEY]: p === 1 ? null : String(p) }, { keepPage: true })}
              onSize={(s) => updateParams({ size: s === 50 ? null : String(s) })}
            />
          </div>
        )}
      </div>
    </AppShell>
  );
}

/* ───────────────────────── 요약 띠 ───────────────────────── */

function SummaryStrip({
  summary,
  priorityFilter,
  reviewPendingFilter,
  alertedFilter,
  onToggle,
}: {
  summary: { total: number; high: number; medium: number; low: number; reviewPending: number; alerted: number };
  priorityFilter: Priority | null;
  reviewPendingFilter: boolean;
  alertedFilter: boolean;
  onToggle: (key: 'priority' | 'reviewPending' | 'alerted', value: string) => void;
}) {
  const priorityDot: Record<Priority, string> = {
    high: 'bg-rose-400',
    medium: 'bg-slate-200',
    low: 'bg-slate-600',
  };
  const priorityNum: Record<Priority, string> = {
    high: 'text-rose-200',
    medium: 'text-slate-50',
    low: 'text-slate-400',
  };
  return (
    <section
      aria-label="인시던트 요약"
      className="soc-card flex flex-wrap items-center gap-x-1 gap-y-1 px-2 py-1.5 text-xs"
    >
      <div className="flex items-baseline gap-2 px-2 py-1">
        <span className="text-slate-400">전체 인시던트</span>
        <span className="text-lg font-bold tabular-nums text-slate-100">{formatNumber(summary.total)}</span>
      </div>

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      {PRIORITY_VALUES.map((p) => (
        <StripButton
          key={p}
          pressed={priorityFilter === p}
          onClick={() => onToggle('priority', p)}
          ariaLabel={`우선순위 ${labelText('priority', p)} ${summary[p]}건만 보기`}
          title={PRIORITY_TOOLTIP}
        >
          <span className={`h-2 w-2 rounded-full ${priorityDot[p]}`} aria-hidden="true" />
          <span className="text-slate-400">{labelText('priority', p)}</span>
          <span className={`text-base font-bold tabular-nums ${priorityNum[p]}`}>{formatNumber(summary[p])}</span>
        </StripButton>
      ))}

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      <div className="flex items-center">
        <StripButton
          pressed={reviewPendingFilter}
          onClick={() => onToggle('reviewPending', 'true')}
          ariaLabel={`에스컬레이션 대기 ${summary.reviewPending}건만 보기`}
        >
          <span className="text-slate-400">에스컬레이션 대기</span>
          <span
            className={`text-base font-bold tabular-nums ${summary.reviewPending > 0 ? 'text-amber-300' : 'text-slate-300'}`}
          >
            {formatNumber(summary.reviewPending)}
          </span>
        </StripButton>
        <Link to="/reviews?pendingOnly=true" className="px-1 text-[11px] text-cyan-300 hover:underline">
          에스컬레이션으로 이동
        </Link>
      </div>

      <StripButton
        pressed={alertedFilter}
        onClick={() => onToggle('alerted', 'true')}
        ariaLabel={`경보 발송 ${summary.alerted}건만 보기`}
      >
        <Bell className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
        <span className="text-slate-400">경보 발송</span>
        <span className="text-base font-bold tabular-nums text-slate-100">{formatNumber(summary.alerted)}</span>
      </StripButton>

      <details className="relative ml-auto">
        <summary className="flex cursor-pointer list-none items-center gap-1 rounded-md px-2 py-1 text-[11px] text-slate-400 transition hover:text-slate-100 [&::-webkit-details-marker]:hidden">
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
          자동 분류 기준
        </summary>
        <div className="soc-card absolute right-0 top-full z-20 mt-1 w-80 max-w-[calc(100vw-2rem)] p-3 text-xs leading-relaxed text-slate-300">
          <p className="mb-2 text-slate-400">
            우선순위는 파이프라인 결과로 화면이 자동 계산한 값입니다. 분석가 판정이 아닙니다.
          </p>
          <ul className="space-y-1">
            <li>
              <span className="font-semibold text-rose-200">High</span>: 발송 판단이 &lsquo;발송&rsquo;이거나 에스컬레이션 대기 중인
              인시던트
            </li>
            <li>
              <span className="font-semibold text-slate-50">Medium</span>: 교차 탐지(2개 이상 모델)됐거나 AI 분석
              리포트가 있는 인시던트
            </li>
            <li>
              <span className="font-semibold text-slate-400">Low</span>: 그 밖의 인시던트
            </li>
            <li className="text-slate-400">종결된 인시던트는 우선순위를 매기지 않습니다(-).</li>
          </ul>
          <p className="mt-2 text-slate-400">기본 정렬은 우선순위, 같으면 탐지 순위 순입니다.</p>
        </div>
      </details>
    </section>
  );
}

function StripButton({
  pressed,
  onClick,
  ariaLabel,
  title,
  children,
}: {
  pressed: boolean;
  onClick: () => void;
  ariaLabel: string;
  title?: string;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={pressed}
      aria-label={ariaLabel}
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 transition ${
        pressed
          ? 'border-cyan-500/60 bg-cyan-500/10'
          : 'border-transparent hover:border-slate-700 hover:bg-slate-800/50'
      }`}
    >
      {children}
    </button>
  );
}

/* ───────────────────────── 표(태블릿·PC) ───────────────────────── */

const SORT_LABEL: Record<SortKey, string> = {
  priority: '우선순위',
  rank: '순위',
  start: '관측 시작',
  connections: '세션 수',
  status: '상태',
};

function SortHeader({
  column,
  label,
  sortKey,
  sortDir,
  onSort,
  className = '',
  align = 'left',
  title,
}: {
  column: SortKey;
  label: string;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  className?: string;
  align?: 'left' | 'right';
  title?: string;
}) {
  const active = column === sortKey;
  const Icon = !active ? ArrowUpDown : sortDir === 'asc' ? ArrowUp : ArrowDown;
  const dirText = sortDir === 'asc' ? '오름차순' : '내림차순';
  return (
    <th
      scope="col"
      aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`soc-th-compact ${align === 'right' ? 'text-right' : ''} ${className}`}
      title={title}
    >
      <button
        type="button"
        onClick={() => onSort(column)}
        className={`inline-flex items-center gap-1 rounded hover:text-slate-100 ${active ? 'text-slate-100' : ''}`}
        aria-label={`${SORT_LABEL[column]} 기준 정렬${active ? `, 지금 ${dirText}` : ''}`}
      >
        {label}
        <Icon className={`h-3 w-3 ${active ? 'text-cyan-300' : 'text-slate-600'}`} aria-hidden="true" />
      </button>
    </th>
  );
}

function hiddenInfoTitle(item: IncidentQueueItem): string {
  const review = item.zeekadReviewPending
    ? '대기'
    : item.zeekadReviewAction
      ? labelText('reviewAction', item.zeekadReviewAction.toLowerCase())
      : '-';
  return `통신 방향 ${labelText('hostRole', item.zeekadRole)} · 세션 ${formatNumber(item.connectionCount)}건 · 에스컬레이션 ${review}`;
}

function QueueTable({
  rows,
  sortKey,
  sortDir,
  onSort,
  listQuery,
}: {
  rows: RowItem[];
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  listQuery: string;
}) {
  const navigate = useNavigate();

  function open(e: React.MouseEvent<HTMLTableRowElement>, url: string) {
    // 글자를 끌어 고른 경우(IP 복사 등)는 이동하지 않는다.
    const selection = window.getSelection?.();
    if (selection && selection.toString().length > 0) {
      return;
    }
    if (e.ctrlKey || e.metaKey) {
      window.open(url, '_blank', 'noopener');
      return;
    }
    navigate(url);
  }

  const headerProps = { sortKey, sortDir, onSort };
  return (
    <div className="hidden overflow-x-auto md:block">
      <table className="w-full border-collapse text-left">
        <caption className="sr-only">인시던트 목록. 호스트 링크나 행을 누르거나 행에서 Enter 키를 누르면 인시던트 상세로 갑니다.</caption>
        <thead>
          <tr>
            <SortHeader column="priority" label="우선순위" title={PRIORITY_TOOLTIP} {...headerProps} />
            <SortHeader column="rank" label="순위" align="right" {...headerProps} />
            <th scope="col" className="soc-th-compact">
              호스트
            </th>
            <th scope="col" className="soc-th-compact hidden 2xl:table-cell">
              통신 방향
            </th>
            <SortHeader column="start" label="관측 시작 · 지속" {...headerProps} />
            <th scope="col" className="soc-th-compact">
              탐지 모델
            </th>
            <th scope="col" className="soc-th-compact" title="AI 분석 리포트 · 검증 · 발송 판단">
              리포트·판단
            </th>
            <SortHeader column="status" label="상태 · 판정" {...headerProps} />
            <th scope="col" className="soc-th-compact hidden lg:table-cell">
              에스컬레이션
            </th>
            <SortHeader
              column="connections"
              label="세션 수"
              align="right"
              className="hidden xl:table-cell"
              {...headerProps}
            />
          </tr>
        </thead>
        <tbody>
          {rows.map(({ item, priority }) => {
            const url = detailUrl(item, listQuery);
            const firstName = item.hostName[0];
            const moreNames = item.hostName.length - 1;
            return (
              <tr
                key={`${item.jobId}-${item.queueRank}-${item.incidentId}`}
                tabIndex={0}
                title={hiddenInfoTitle(item)}
                onClick={(e) => open(e, url)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && e.target === e.currentTarget) {
                    e.preventDefault();
                    navigate(url);
                  }
                }}
                className="cursor-pointer transition hover:bg-slate-800/40 focus:outline-none focus-visible:bg-slate-800/50 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-cyan-400/70"
              >
                <td className="soc-td-compact">
                  <PriorityBadge priority={priority} />
                </td>
                <td className="soc-td-compact soc-num font-semibold text-slate-100">{item.queueRank}</td>
                <td className="soc-td-compact">
                  <div className="flex max-w-[17rem] items-baseline gap-2">
                    {/* 화면 판독기가 행을 링크로 알 수 있게 실제 링크를 둔다(T18 L3). 행 클릭과 겹치지 않게 전파를 막는다. */}
                    <Link
                      to={url}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`인시던트 상세: ${item.hostIp} · ${item.queueRank}위`}
                      className="shrink-0 font-mono font-semibold text-slate-100 hover:text-cyan-200 hover:underline focus:outline-none focus-visible:underline"
                    >
                      {item.hostIp}
                    </Link>
                    {firstName !== undefined && (
                      <span
                        className="min-w-0 truncate font-mono text-[11px] text-slate-400"
                        title={item.hostName.join(', ')}
                      >
                        {firstName}
                        {moreNames > 0 && <span className="ml-1 font-sans text-slate-500">외 {moreNames}</span>}
                      </span>
                    )}
                  </div>
                </td>
                <td className="soc-td-compact hidden text-slate-300 2xl:table-cell">
                  <CodeLabel dict="hostRole" value={item.zeekadRole} />
                </td>
                <td
                  className="soc-td-compact tabular-nums"
                  title={`관측 구간 ${formatDateTimeRange(item.eventStart, item.eventEnd)}`}
                >
                  <span className="text-slate-200">{formatDateTime(item.eventStart)}</span>
                  <span className="mx-1.5 text-slate-600" aria-hidden="true">
                    ·
                  </span>
                  <span className="text-slate-400">{formatDuration(item.eventStart, item.eventEnd)}</span>
                </td>
                <td className="soc-td-compact">
                  <DetectionModelName id={item.zeekadPickedBy} className="font-semibold text-slate-100" />
                  <AlsoFlagged models={item.zeekadAlsoFlaggedBy} />
                </td>
                <td className="soc-td-compact">
                  <SignalChips item={item} />
                </td>
                <td
                  className="soc-td-compact"
                  title={item.statusUpdatedAt ? `상태 갱신 ${formatDateTime(item.statusUpdatedAt)}` : undefined}
                >
                  <div className="flex items-center gap-1">
                    <IncidentStatusBadge status={item.zeekadStatus} />
                    <ResolutionBadge resolution={item.zeekadResolution} />
                  </div>
                </td>
                <td className="soc-td-compact hidden lg:table-cell">
                  <ReviewActionBadge action={item.zeekadReviewAction} pending={item.zeekadReviewPending} />
                </td>
                <td className="soc-td-compact soc-num hidden text-slate-300 xl:table-cell">
                  {formatNumber(item.connectionCount)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** 교차 탐지 모델 수. 화면 글은 +N으로 줄이고 이름은 툴팁, 개수는 읽기 프로그램용 글로 남긴다. */
function AlsoFlagged({ models }: { models: string[] | null | undefined }) {
  const list = models ?? [];
  if (list.length === 0) {
    return null;
  }
  return (
    <span
      title={`교차 탐지: ${list.map((m) => labelText('detectionModel', m)).join(', ')}`}
      className="ml-1.5 rounded border border-slate-700 bg-slate-800/80 px-1 text-[11px] tabular-nums text-slate-300"
    >
      <span aria-hidden="true">+{list.length}</span>
      <span className="sr-only">교차 탐지 모델 {list.length}개</span>
    </span>
  );
}

const CHIP_BASE = 'inline-flex h-5 w-5 items-center justify-center rounded border';

/** 리포트·검증·발송 판단을 묶은 아이콘 칩(T21: 세 번째 칩은 발송 판단 zeekadWouldSend이며 "경보 발송"이 아니다). 각 칩은 접근성 이름과 툴팁을 가진다. */
function SignalChips({ item }: { item: IncidentQueueItem }) {
  const hasReport = item.zeekadReportJobId !== null;
  const kind = labelText('reportKind', item.zeekadReportKind);
  return (
    <div className="flex items-center gap-1">
      {hasReport ? (
        <span
          role="img"
          aria-label={`AI 분석 리포트 있음: ${kind}`}
          title={`${kind} 리포트 · 리포트 작업 #${item.zeekadReportJobId}`}
          className={`${CHIP_BASE} border-slate-600 bg-slate-800 text-slate-100`}
        >
          <FileText className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : (
        <span role="img" aria-label="리포트 없음" title="리포트 없음" className={`${CHIP_BASE} border-slate-800 text-slate-600`}>
          <FileX className="h-3 w-3" aria-hidden="true" />
        </span>
      )}
      {hasReport && item.zeekadVerificationPassed === true ? (
        <span
          role="img"
          aria-label="검증 통과"
          title="검증 통과"
          className={`${CHIP_BASE} border-emerald-500/35 bg-emerald-500/10 text-emerald-300`}
        >
          <ShieldCheck className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : hasReport && item.zeekadVerificationPassed === false ? (
        <span
          role="img"
          aria-label="검증 실패"
          title="검증 실패"
          className={`${CHIP_BASE} border-amber-500/40 bg-amber-500/15 text-amber-300`}
        >
          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : (
        <span className={`${CHIP_BASE} border-transparent`} aria-hidden="true" />
      )}
      {item.zeekadWouldSend ? (
        <span
          role="img"
          aria-label="발송 판단: 발송"
          title="발송 판단: 발송"
          className={`${CHIP_BASE} border-cyan-500/35 bg-cyan-500/10 text-cyan-300`}
        >
          <Bell className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : (
        <span
          role="img"
          aria-label="발송 판단: 보류"
          title="발송 판단: 보류"
          className={`${CHIP_BASE} border-slate-800 text-slate-600`}
        >
          <BellOff className="h-3 w-3" aria-hidden="true" />
        </span>
      )}
    </div>
  );
}

/* ───────────────────────── 휴대폰 목록 ───────────────────────── */

function QueueMobileList({ rows, listQuery }: { rows: RowItem[]; listQuery: string }) {
  return (
    <ul className="divide-y divide-slate-800/80 md:hidden" aria-label="인시던트 목록">
      {rows.map(({ item, priority }) => (
        <li key={`${item.jobId}-${item.queueRank}-${item.incidentId}`}>
          <Link
            to={detailUrl(item, listQuery)}
            className="block px-3 py-2.5 transition hover:bg-slate-800/40 focus:outline-none focus-visible:bg-slate-800/50"
          >
            <div className="flex items-center gap-2">
              <PriorityBadge priority={priority} />
              <span className="shrink-0 font-mono text-sm font-semibold text-slate-100">{item.hostIp}</span>
              {item.hostName[0] !== undefined && (
                <span className="min-w-0 truncate font-mono text-[11px] text-slate-400">{item.hostName[0]}</span>
              )}
              <span className="ml-auto shrink-0 text-[11px] tabular-nums text-slate-500">{item.queueRank}위</span>
            </div>
            <div className="mt-1 flex items-center gap-2 text-xs">
              <span className="tabular-nums text-slate-300">{formatDateTime(item.eventStart)}</span>
              <span className="text-slate-500">{formatDuration(item.eventStart, item.eventEnd)}</span>
              <span className="ml-auto">
                <IncidentStatusBadge status={item.zeekadStatus} />
              </span>
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

/* ───────────────────────── 페이지 나눔 ───────────────────────── */

function pageList(page: number, pageCount: number): (number | 'gap')[] {
  const set = new Set<number>([1, pageCount, page - 1, page, page + 1]);
  const pages = [...set].filter((p) => p >= 1 && p <= pageCount).sort((a, b) => a - b);
  const out: (number | 'gap')[] = [];
  pages.forEach((p, i) => {
    if (i > 0 && p - pages[i - 1] > 1) out.push('gap');
    out.push(p);
  });
  return out;
}

function Pagination({
  total,
  win,
  pageSize,
  onPage,
  onSize,
}: {
  total: number;
  win: ReturnType<typeof pageWindow>;
  pageSize: number;
  onPage: (page: number) => void;
  onSize: (size: number) => void;
}) {
  return (
    <nav
      aria-label="쪽 이동"
      className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 px-3 py-2 text-xs text-slate-400"
    >
      <span className="tabular-nums" aria-live="polite">
        전체 {formatNumber(total)}건 중 {formatNumber(win.from)}–{formatNumber(win.to)}
      </span>
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-1.5">
          <span>쪽당</span>
          <select
            value={String(pageSize)}
            onChange={(e) => onSize(Number(e.target.value))}
            className="soc-select py-1 pl-2 pr-7 text-xs tabular-nums"
            aria-label="쪽당 건수"
          >
            {PAGE_SIZES.map((s) => (
              <option key={s} value={String(s)}>
                {s}건
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-center gap-0.5">
          <button
            type="button"
            onClick={() => onPage(win.page - 1)}
            disabled={win.page <= 1}
            aria-label="이전 쪽"
            className="rounded p-1 hover:bg-slate-800 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" aria-hidden="true" />
          </button>
          {pageList(win.page, win.pageCount).map((p, i) =>
            p === 'gap' ? (
              <span key={`gap-${i}`} className="px-1 text-slate-600" aria-hidden="true">
                …
              </span>
            ) : (
              <button
                key={p}
                type="button"
                onClick={() => onPage(p)}
                aria-current={p === win.page ? 'page' : undefined}
                aria-label={`${p}쪽`}
                className={`min-w-[1.75rem] rounded px-1.5 py-0.5 tabular-nums ${
                  p === win.page
                    ? 'bg-cyan-500/15 font-semibold text-cyan-200'
                    : 'hover:bg-slate-800 hover:text-slate-100'
                }`}
              >
                {p}
              </button>
            ),
          )}
          <button
            type="button"
            onClick={() => onPage(win.page + 1)}
            disabled={win.page >= win.pageCount}
            aria-label="다음 쪽"
            className="rounded p-1 hover:bg-slate-800 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </div>
    </nav>
  );
}
