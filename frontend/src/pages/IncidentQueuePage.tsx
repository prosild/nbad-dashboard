import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Bell,
  BellOff,
  BellRing,
  ChevronLeft,
  ChevronRight,
  Database,
  FileText,
  FileX,
  Filter,
  Info,
  Lock,
  Radio,
  RotateCcw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import {
  CaptureName,
  CodeLabel,
  DetectionModelName,
  IncidentStatusBadge,
  NewRowBadge,
  OngoingBadge,
  PRIORITY_TOOLTIP,
  PriorityBadge,
  ResolutionBadge,
  ReviewActionBadge,
  SOURCE_TYPE_LABEL,
  SourceTypeBadge,
} from '../components/StatusBadge';
import type { QueueSource, SourceType, UnifiedQueueItem, UnifiedQueueResponse } from '../types/api';
import {
  formatDateTime,
  formatDateTimeRange,
  formatDuration,
  formatNumber,
  formatRelativeTo,
} from '../utils/format';
import { captureInfo, detectionModelInfo, labelText, lookupLabel } from '../utils/labels';
import {
  DEFAULT_PAGE_SIZE,
  DEFAULT_PERIOD,
  DEFAULT_SORT_DIR,
  LEGACY_JOB_NOTICE,
  migrateLegacyQueueParams,
  PAGE_SIZES,
  PANEL_FILTER_KEYS,
  parseQueueQuery,
  PERIODS,
  periodLabel,
  PRIORITY_VALUES,
  queueApiParams,
  STRIP_FILTER_KEYS,
  type Priority,
  type SortDir,
  type SortKey,
} from '../utils/triage';

/** 자동 갱신 주기(T23): 60초마다 새 인시던트 수를 묻는다. 화면이 숨겨지면 멈춘다. */
export const NEW_INCIDENT_POLL_MS = 60_000;

/** 필터·정렬·쪽 크기 변경 때 지우는 쪽 번호 키 */
const PAGE_KEY = 'page';

/**
 * 상세 주소. 목록의 쿼리(기간·수집원·거르기·정렬·쪽)를 `from=`으로 넘겨 상세의 이전·다음(neighbors API)과 목록 복귀가 같은 조건을 쓴다.
 */
function detailUrl(item: UnifiedQueueItem, listQuery: string): string {
  return `/incidents/${item.jobId}/rank/${item.queueRank}?${new URLSearchParams({ from: listQuery }).toString()}`;
}

/**
 * 새 인시던트 수 확인(T23). 60초마다 `new-count`를 부르고, 화면이 숨겨지면 멈췄다가 다시 보이면 곧바로 한 번 부른다.
 * since는 마지막으로 불러온 큐 응답의 latestDetectedAt(없으면 anchor)이며 브라우저 시각은 쓰지 않는다.
 * 목록 행은 바꾸지 않고 수만 돌려준다.
 */
function useNewIncidentCount(enabled: boolean, since: string | null, paramsKey: string): number {
  const [count, setCount] = useState(0);
  useEffect(() => {
    setCount(0);
    if (!enabled || !since) return undefined;
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const params = JSON.parse(paramsKey) as Record<string, string | undefined>;
    const check = async () => {
      try {
        const res = await incidentsApi.newCount(params, since);
        if (!cancelled) setCount(res.count);
      } catch {
        // 확인 실패는 띠를 바꾸지 않는다(다음 주기에 다시 묻는다).
      }
    };
    const stop = () => {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    };
    const start = () => {
      stop();
      timer = setInterval(() => void check(), NEW_INCIDENT_POLL_MS);
    };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        stop();
      } else {
        void check();
        start();
      }
    };
    if (document.visibilityState !== 'hidden') start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      cancelled = true;
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, since, paramsKey]);
  return count;
}

export function IncidentQueuePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<UnifiedQueueResponse | null>(null);
  /** data를 받은 요청의 쿼리 키(지금 URL과 같을 때만 URL을 고친다) */
  const [dataKey, setDataKey] = useState<string | null>(null);
  const requestSeq = useRef(0);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [legacyNotice, setLegacyNotice] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  /** 새 인시던트 띠를 눌렀을 때의 since. 다음 응답의 이보다 늦은 행에 "새" 표지를 붙인다. */
  const pendingHighlightRef = useRef<string | null>(null);
  const [highlightAfter, setHighlightAfter] = useState<string | null>(null);

  // 옛 주소(T23): jobId는 지우고 안내를 한 번 보이며, sort=rank는 기본 정렬로 바꾼다.
  const legacy = migrateLegacyQueueParams(searchParams);
  useEffect(() => {
    if (!legacy.changed) return;
    if (legacy.droppedJob) setLegacyNotice(true);
    setSearchParams(legacy.next, { replace: true });
  }, [legacy.changed, legacy.droppedJob, legacy.next, setSearchParams]);

  const query = parseQueueQuery(legacy.changed ? legacy.next : searchParams);
  const apiKey = JSON.stringify(queueApiParams(query));
  const pollKey = JSON.stringify(queueApiParams(query, { paging: false, sort: false, period: false }));

  const [assetDraft, setAssetDraft] = useState(query.asset);
  useEffect(() => {
    setAssetDraft(query.asset);
  }, [query.asset]);

  const loadQueue = useCallback(async () => {
    const seq = ++requestSeq.current;
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await incidentsApi.queue(JSON.parse(apiKey) as Record<string, string | undefined>);
      if (seq !== requestSeq.current) return;
      setData(res);
      setDataKey(apiKey);
      setHighlightAfter(pendingHighlightRef.current);
      pendingHighlightRef.current = null;
    } catch (err) {
      if (seq !== requestSeq.current) return;
      setErrorMsg(err instanceof ApiError ? err.message : '인시던트 목록을 불러오지 못했습니다.');
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [apiKey]);

  useEffect(() => {
    if (legacy.changed) return;
    void loadQueue();
    // reloadTick: 같은 쿼리로 다시 부를 때(새 인시던트 불러오기)
  }, [loadQueue, legacy.changed, reloadTick]);

  // 범위 밖 page는 서버가 고친 쪽으로, 허용 밖 size는 50으로 URL을 고친다(응답을 받은 뒤에만).
  useEffect(() => {
    if (loading || !data || dataKey !== apiKey) return;
    const next = new URLSearchParams(searchParams);
    let changed = false;
    const rawPage = searchParams.get(PAGE_KEY);
    if (rawPage !== null && rawPage !== String(data.page)) {
      if (data.page === 1) next.delete(PAGE_KEY);
      else next.set(PAGE_KEY, String(data.page));
      changed = true;
    }
    const rawSize = searchParams.get('size');
    if (rawSize !== null && rawSize !== String(query.size)) {
      next.delete('size');
      changed = true;
    }
    if (changed) setSearchParams(next, { replace: true });
  }, [loading, data, dataKey, apiKey, searchParams, setSearchParams, query.size]);

  const since = data ? (data.latestDetectedAt ?? data.anchor) : null;
  const newCount = useNewIncidentCount(Boolean(data) && !data?.snapshot, since, pollKey);

  /** URL 쿼리를 바꾼다. 기본은 쪽 번호를 지운다(1쪽으로). */
  function updateParams(changes: Record<string, string | null>, opts: { keepPage?: boolean } = {}) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!opts.keepPage && !(PAGE_KEY in changes)) next.delete(PAGE_KEY);
    setSearchParams(next);
  }

  function updateParam(key: string, value: string) {
    updateParams({ [key]: value || null });
  }

  /** 거르기(수집원·필터·띠)를 모두 지운다. 기간·쪽 크기는 남긴다. */
  function handleResetFilters() {
    const next = new URLSearchParams();
    const period = searchParams.get('period');
    if (period) next.set('period', period);
    const size = searchParams.get('size');
    if (size) next.set('size', size);
    setAssetDraft('');
    setSearchParams(next);
  }

  function handleAssetSubmit(e: React.FormEvent) {
    e.preventDefault();
    updateParam('asset', assetDraft.trim());
  }

  function handleSort(key: SortKey) {
    const dir: SortDir = key === query.sortKey ? (query.sortDir === 'asc' ? 'desc' : 'asc') : DEFAULT_SORT_DIR[key];
    updateParams({ sort: key, dir });
  }

  function handlePeriod(value: string) {
    updateParams({ period: value === DEFAULT_PERIOD ? null : value });
  }

  /** 수집원 선택: '' = 전체, 'src:live|imported' = 종류 전체, 'cap:<id>' = 캡처 하나 */
  function handleSource(value: string) {
    if (value.startsWith('cap:')) {
      updateParams({ captureId: value.slice(4), source: null });
    } else if (value.startsWith('src:')) {
      updateParams({ source: value.slice(4), captureId: null });
    } else {
      updateParams({ source: null, captureId: null });
    }
  }

  /** 새 인시던트 불러오기: 탐지 시각 최근순 1쪽을 다시 부르고 새 행에 표지를 붙인다. */
  function handleLoadNew() {
    pendingHighlightRef.current = since;
    const next = new URLSearchParams(searchParams);
    next.set('sort', 'detected');
    next.set('dir', 'desc');
    next.delete(PAGE_KEY);
    setSearchParams(next);
    setReloadTick((n) => n + 1);
  }

  const listQuery = useMemo(() => searchParams.toString(), [searchParams]);

  const chips = useMemo(() => {
    const list: { key: string; label: string; raw?: string }[] = [];
    if (query.pickedBy) {
      const model = lookupLabel('detectionModel', query.pickedBy);
      list.push(
        model.known
          ? { key: 'pickedBy', label: `탐지 모델: ${model.text}` }
          : { key: 'pickedBy', label: '탐지 모델', raw: query.pickedBy },
      );
    }
    if (query.role) list.push({ key: 'role', label: `통신 방향: ${labelText('hostRole', query.role)}` });
    if (query.status) list.push({ key: 'status', label: `인시던트 상태: ${labelText('incidentStatus', query.status)}` });
    if (query.hasReport)
      list.push({ key: 'hasReport', label: `AI 리포트: ${query.hasReport === 'true' ? '리포트 있음' : '리포트 없음'}` });
    if (query.wouldSend)
      list.push({ key: 'wouldSend', label: `발송 판단: ${query.wouldSend === 'true' ? '발송' : '보류'}` });
    if (query.asset) list.push({ key: 'asset', label: '자산 검색', raw: query.asset });
    if (query.priority) list.push({ key: 'priority', label: `우선순위: ${labelText('priority', query.priority)}` });
    if (query.reviewPending) list.push({ key: 'reviewPending', label: '에스컬레이션 대기만' });
    if (query.alerted) list.push({ key: 'alerted', label: '경보 발송만' });
    return list;
  }, [query.pickedBy, query.role, query.status, query.hasReport, query.wouldSend, query.asset, query.priority, query.reviewPending, query.alerted]);

  function toggleStripFilter(key: (typeof STRIP_FILTER_KEYS)[number], value: string) {
    const current = searchParams.get(key);
    updateParams({ [key]: current === value ? null : value });
  }

  const panelFilterCount = PANEL_FILTER_KEYS.filter((k) => (searchParams.get(k) ?? '') !== '').length;
  const anyFilter =
    chips.length > 0 || query.source !== null || query.captureId !== null;
  const sourceValue = query.captureId ? `cap:${query.captureId}` : query.source ? `src:${query.source}` : '';
  const items = data?.items ?? [];

  return (
    <AppShell title="인시던트" subtitle="허용된 모든 수집원의 인시던트를 탐지 시각 기준으로 모아 우선순위 순으로 봅니다">
      <div className="space-y-3">
        {legacyNotice && (
          <div
            role="status"
            className="flex items-start justify-between gap-3 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-xs text-slate-200"
          >
            <span className="flex items-start gap-2">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
              {LEGACY_JOB_NOTICE}
            </span>
            <button
              type="button"
              onClick={() => setLegacyNotice(false)}
              aria-label="안내 닫기"
              className="rounded p-0.5 text-slate-400 hover:text-slate-100"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        )}

        <SummaryStrip
          summary={data?.summary ?? null}
          priorityFilter={query.priority}
          reviewPendingFilter={query.reviewPending}
          alertedFilter={query.alerted}
          onToggle={toggleStripFilter}
        />

        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <div className="flex items-center gap-2" role="group" aria-label="기간">
              <span className="shrink-0 text-xs font-medium text-slate-400" aria-hidden="true">
                기간
              </span>
              <div className="flex overflow-hidden rounded-md border border-slate-700">
                {PERIODS.map((p) => {
                  const active = p.value === query.period;
                  return (
                    <button
                      key={p.value}
                      type="button"
                      aria-pressed={active}
                      onClick={() => handlePeriod(p.value)}
                      title={p.value === 'all' ? '탐지 시각 조건 없이 전체' : `기준 시각에서 최근 ${p.label} 안에 탐지된 인시던트`}
                      className={`border-l border-slate-700 px-2 py-1 text-xs tabular-nums first:border-l-0 ${
                        active ? 'bg-cyan-500/15 font-semibold text-cyan-200' : 'text-slate-300 hover:bg-slate-800'
                      }`}
                    >
                      {p.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="flex min-w-0 flex-1 basis-full items-center gap-2 sm:basis-auto sm:flex-none">
              <label htmlFor="filter-source" className="shrink-0 text-xs font-medium text-slate-400">
                수집원
              </label>
              <SourceSelect sources={data?.sources ?? []} value={sourceValue} onChange={handleSource} />
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
              {panelFilterCount > 0 && (
                <span className="rounded bg-cyan-500/20 px-1.5 text-[11px] tabular-nums text-cyan-200">
                  {panelFilterCount}
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

            <div className="ml-auto flex items-center gap-2">
              {data?.snapshot && (
                <span
                  className="inline-flex items-center gap-1 text-[11px] text-slate-400"
                  title="데이터가 더 늘지 않는 고정 스냅샷이라 새 인시던트를 확인하지 않습니다"
                >
                  <Lock className="h-3 w-3" aria-hidden="true" />
                  고정 스냅샷 · 자동 갱신 꺼짐
                </span>
              )}
              <button
                type="button"
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 transition hover:text-slate-100"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                필터 초기화
              </button>
            </div>
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
                  value={query.pickedBy}
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
                  value={query.role}
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
                  value={query.status}
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
                  value={query.hasReport}
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
                  value={query.wouldSend}
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

        {newCount > 0 && (
          <div
            role="status"
            className="flex items-center justify-between gap-3 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100"
          >
            <span className="flex items-center gap-2">
              <BellRing className="h-3.5 w-3.5 text-cyan-300" aria-hidden="true" />
              새 인시던트 {formatNumber(newCount)}건
            </span>
            <button type="button" onClick={handleLoadNew} className="soc-btn-secondary px-2.5 py-1 text-xs">
              불러오기
            </button>
          </div>
        )}

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadQueue()} />}

        {loading && !data ? (
          <LoadingPanel label="인시던트 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            {items.length === 0 ? (
              <EmptyState
                data={data}
                anyFilter={anyFilter}
                onAllPeriod={() => handlePeriod('all')}
                onReset={handleResetFilters}
              />
            ) : (
              <>
                <QueueTable
                  rows={items}
                  sortKey={query.sortKey}
                  sortDir={query.sortDir}
                  onSort={handleSort}
                  listQuery={listQuery}
                  anchor={data?.anchor ?? null}
                  snapshot={Boolean(data?.snapshot)}
                  highlightAfter={highlightAfter}
                />
                <QueueMobileList
                  rows={items}
                  listQuery={listQuery}
                  anchor={data?.anchor ?? null}
                  snapshot={Boolean(data?.snapshot)}
                  highlightAfter={highlightAfter}
                />
              </>
            )}
            <Pagination
              total={data?.total ?? 0}
              page={data?.page ?? 1}
              pageCount={data?.pageCount ?? 1}
              pageSize={data?.size ?? query.size}
              onPage={(p) => updateParams({ [PAGE_KEY]: p === 1 ? null : String(p) }, { keepPage: true })}
              onSize={(s) => updateParams({ size: s === DEFAULT_PAGE_SIZE ? null : String(s) })}
            />
          </div>
        )}
      </div>
    </AppShell>
  );
}

/* ───────────────────────── 수집원 선택 ───────────────────────── */

function SourceSelect({
  sources,
  value,
  onChange,
}: {
  sources: QueueSource[];
  value: string;
  onChange: (value: string) => void;
}) {
  const groups: SourceType[] = ['live', 'imported'];
  const known = new Set(sources.map((s) => `cap:${s.captureId}`));
  const selectedCapture = value.startsWith('cap:') ? value.slice(4) : null;
  return (
    <select
      id="filter-source"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="soc-select w-full py-1.5 text-xs sm:w-72"
      title={selectedCapture ? captureInfo(selectedCapture).tooltip || undefined : undefined}
    >
      <option value="">전체 수집원</option>
      {groups.map((g) => {
        const members = sources.filter((s) => s.sourceType === g);
        return [
          <option key={`src-${g}`} value={`src:${g}`}>
            {SOURCE_TYPE_LABEL[g]} 전체
          </option>,
          members.length > 0 ? (
            <optgroup key={`grp-${g}`} label={SOURCE_TYPE_LABEL[g]}>
              {members.map((s) => {
                const info = captureInfo(s.captureId);
                return (
                  <option key={s.captureId} value={`cap:${s.captureId}`} title={info.tooltip}>
                    {info.text}
                  </option>
                );
              })}
            </optgroup>
          ) : null,
        ];
      })}
      {/* 옛 링크의 captureId가 목록에 없으면(허용 밖 등) 그대로 보여 준다. 서버가 403으로 답한다. */}
      {selectedCapture && !known.has(value) && <option value={value}>{captureInfo(selectedCapture).text}</option>}
    </select>
  );
}

/* ───────────────────────── 빈 결과 ───────────────────────── */

function EmptyState({
  data,
  anyFilter,
  onAllPeriod,
  onReset,
}: {
  data: UnifiedQueueResponse | null;
  anyFilter: boolean;
  onAllPeriod: () => void;
  onReset: () => void;
}) {
  if (data && data.newestOutsidePeriod) {
    return (
      <div className="space-y-2 px-4 py-12 text-center text-sm text-slate-300" data-empty="period">
        <p>
          이 기간에 탐지된 인시던트가 없습니다. 가장 최근 탐지:{' '}
          <span className="tabular-nums text-slate-100">{formatDateTime(data.newestOutsidePeriod)}</span>
        </p>
        <div className="flex flex-wrap items-center justify-center gap-2">
          <button type="button" onClick={onAllPeriod} className="soc-btn-secondary px-3 py-1.5 text-xs">
            기간: 전체로 보기
          </button>
          {anyFilter && (
            <button type="button" onClick={onReset} className="soc-btn-secondary px-3 py-1.5 text-xs">
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              필터 초기화
            </button>
          )}
        </div>
      </div>
    );
  }
  if (anyFilter) {
    return (
      <p className="px-4 py-12 text-center text-sm text-slate-400" data-empty="filter">
        조건에 맞는 인시던트가 없습니다. 필터를 줄이거나 [필터 초기화]를 누르세요.
      </p>
    );
  }
  return (
    <p className="px-4 py-12 text-center text-sm text-slate-400" data-empty="none">
      {data && data.period !== 'all'
        ? `최근 ${periodLabel(data.period as Parameters<typeof periodLabel>[0])} 동안 탐지된 인시던트가 없습니다.`
        : '표시할 인시던트가 없습니다.'}
    </p>
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
  summary: UnifiedQueueResponse['summary'] | null;
  priorityFilter: Priority | null;
  reviewPendingFilter: boolean;
  alertedFilter: boolean;
  onToggle: (key: 'priority' | 'reviewPending' | 'alerted', value: string) => void;
}) {
  const s = summary ?? { total: 0, high: 0, medium: 0, low: 0, reviewPending: 0, alerted: 0, byStatus: {} };
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
        <span className="text-lg font-bold tabular-nums text-slate-100">{formatNumber(s.total)}</span>
      </div>

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      {PRIORITY_VALUES.map((p) => (
        <StripButton
          key={p}
          pressed={priorityFilter === p}
          onClick={() => onToggle('priority', p)}
          ariaLabel={`우선순위 ${labelText('priority', p)} ${s[p]}건만 보기`}
          title={PRIORITY_TOOLTIP}
        >
          <span className={`h-2 w-2 rounded-full ${priorityDot[p]}`} aria-hidden="true" />
          <span className="text-slate-400">{labelText('priority', p)}</span>
          <span className={`text-base font-bold tabular-nums ${priorityNum[p]}`}>{formatNumber(s[p])}</span>
        </StripButton>
      ))}

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      <div className="flex items-center">
        <StripButton
          pressed={reviewPendingFilter}
          onClick={() => onToggle('reviewPending', 'true')}
          ariaLabel={`에스컬레이션 대기 ${s.reviewPending}건만 보기`}
        >
          <span className="text-slate-400">에스컬레이션 대기</span>
          <span
            className={`text-base font-bold tabular-nums ${s.reviewPending > 0 ? 'text-amber-300' : 'text-slate-300'}`}
          >
            {formatNumber(s.reviewPending)}
          </span>
        </StripButton>
        <Link to="/reviews?pendingOnly=true" className="px-1 text-[11px] text-cyan-300 hover:underline">
          에스컬레이션으로 이동
        </Link>
      </div>

      <StripButton
        pressed={alertedFilter}
        onClick={() => onToggle('alerted', 'true')}
        ariaLabel={`경보 발송 ${s.alerted}건만 보기`}
      >
        <Bell className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
        <span className="text-slate-400">경보 발송</span>
        <span className="text-base font-bold tabular-nums text-slate-100">{formatNumber(s.alerted)}</span>
      </StripButton>

      <details className="relative ml-auto">
        <summary className="flex cursor-pointer list-none items-center gap-1 rounded-md px-2 py-1 text-[11px] text-slate-400 transition hover:text-slate-100 [&::-webkit-details-marker]:hidden">
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
          자동 분류 기준
        </summary>
        <div className="soc-card absolute right-0 top-full z-20 mt-1 w-80 max-w-[calc(100vw-2rem)] p-3 text-xs leading-relaxed text-slate-300">
          <p className="mb-2 text-slate-400">
            우선순위는 파이프라인 결과로 서버가 자동 계산한 값입니다. 분석가 판정이 아닙니다.
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
          <p className="mt-2 text-slate-400">
            기본 정렬은 우선순위, 같으면 탐지 시각 최근 순입니다. 기간은 탐지 시각(인시던트가 처음 탐지된 분석 완료
            시각) 기준입니다.
          </p>
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
  detected: '탐지 시각',
  start: '발생 시각',
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
      className={`soc-th-compact px-1.5 2xl:px-2 ${align === 'right' ? 'text-right' : ''} ${className}`}
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

function hiddenInfoTitle(item: UnifiedQueueItem): string {
  const review = item.zeekadReviewPending
    ? '대기'
    : item.zeekadReviewAction
      ? labelText('reviewAction', item.zeekadReviewAction.toLowerCase())
      : '-';
  return `통신 방향 ${labelText('hostRole', item.zeekadRole)} · 세션 ${formatNumber(item.connectionCount)}건 · 에스컬레이션 ${review}`;
}

function isNewRow(item: UnifiedQueueItem, highlightAfter: string | null): boolean {
  if (!highlightAfter || !item.detectedAt) return false;
  return new Date(item.detectedAt).getTime() > new Date(highlightAfter).getTime();
}

/** 탐지 시각: 기준 시각에서 얼마 전인지만 글로 보이고 절대 시각(KST)은 툴팁에 둔다(T23 7절 목록 밀도). */
function DetectedCell({ item, anchor }: { item: UnifiedQueueItem; anchor: string | null }) {
  if (!item.detectedAt) {
    return <span className="text-slate-500">-</span>;
  }
  return (
    <span title={`탐지 시각 ${formatDateTime(item.detectedAt)}`} className="whitespace-nowrap text-slate-200">
      {formatRelativeTo(item.detectedAt, anchor)}
    </span>
  );
}

/**
 * 수집원(한 줄): 종류 아이콘 + 표시 이름(넘치면 말줄임). 종류 문구·표시 이름 전체·캡처 ID는 툴팁에 둔다.
 * 종류 문구는 수집원 조건과 상세 헤더에 글자로 보인다.
 * T26(T23 review-4 L2): 역할 없는 span의 aria-label은 화면 판독기가 읽지 않을 수 있어, 보이는 표시 이름은 그대로 읽히게 두고
 * 종류 문구·캡처 ID는 sr-only 글자로 더한다(행의 접근성 이름에 "수집원: 종류 · 표시 이름 · 캡처 ID"가 들어간다).
 */
function SourceCell({ item }: { item: UnifiedQueueItem }) {
  const info = captureInfo(item.captureId);
  const typeText = SOURCE_TYPE_LABEL[item.sourceType] ?? '-';
  const label = `${typeText} · ${info.text} · 캡처 ID: ${item.captureId}`;
  const Icon = item.sourceType === 'live' ? Radio : Database;
  return (
    <span title={label} className="flex max-w-[5.5rem] items-center gap-1 2xl:max-w-[13rem]">
      <Icon className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
      <span className="sr-only">{`수집원: ${typeText} · `}</span>
      <span className="min-w-0 truncate text-slate-300">{info.text}</span>
      <span className="sr-only">{` · 캡처 ID: ${item.captureId}`}</span>
    </span>
  );
}

/** 발생 시각(한 줄): 초를 빼고, 기준 시각과 같은 해면 연도를 뺀다(해가 다르면 연도를 보인다). 전체 구간은 칸 툴팁. */
function compactOccurrence(iso: string | null, anchor: string | null): string {
  const full = formatDateTime(iso);
  if (full.length !== 19) return full;
  const anchorYear = anchor ? formatDateTime(anchor).slice(0, 4) : '';
  return full.slice(0, 4) === anchorYear ? full.slice(5, 16) : full.slice(0, 16);
}

function QueueTable({
  rows,
  sortKey,
  sortDir,
  onSort,
  listQuery,
  anchor,
  snapshot,
  highlightAfter,
}: {
  rows: UnifiedQueueItem[];
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  listQuery: string;
  anchor: string | null;
  snapshot: boolean;
  highlightAfter: string | null;
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
  // 1536px(2xl) 미만에서 통신 방향·세션 수는 숨긴다(값은 상세·행 툴팁에 있다). 지금 정렬 기준인 열은 숨기지 않는다.
  const connectionsCell = sortKey === 'connections' ? '' : 'hidden 2xl:table-cell';
  return (
    <div className="hidden overflow-x-auto md:block" data-queue-table-wrap="">
      <table className="w-full border-collapse text-left">
        <caption className="sr-only">인시던트 목록. 호스트 링크나 행을 누르거나 행에서 Enter 키를 누르면 인시던트 상세로 갑니다.</caption>
        <thead>
          <tr>
            <SortHeader column="priority" label="우선순위" title={PRIORITY_TOOLTIP} {...headerProps} />
            <SortHeader
              column="detected"
              label="탐지 시각"
              title="인시던트가 처음 탐지된 분석 완료 시각"
              {...headerProps}
            />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              호스트
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              수집원
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2 hidden 2xl:table-cell">
              통신 방향
            </th>
            <SortHeader
              column="start"
              label="발생 시각 · 지속"
              title="트래픽이 관측된 시각(원본 그대로)"
              {...headerProps}
            />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              탐지 모델
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2" title="AI 분석 리포트 · 검증 · 발송 판단">
              리포트·판단
            </th>
            <SortHeader column="status" label="상태 · 판정" {...headerProps} />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2 hidden lg:table-cell">
              에스컬레이션
            </th>
            <SortHeader
              column="connections"
              label="세션 수"
              align="right"
              className={connectionsCell}
              {...headerProps}
            />
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => {
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
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <div className="flex items-center gap-1">
                    <PriorityBadge priority={item.priority} />
                    {isNewRow(item, highlightAfter) && <NewRowBadge />}
                  </div>
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2 tabular-nums">
                  <DetectedCell item={item} anchor={anchor} />
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <div className="flex max-w-[8.5rem] items-baseline gap-1.5 2xl:max-w-[17rem]">
                    {/* 화면 판독기가 행을 링크로 알 수 있게 실제 링크를 둔다(T18 L3). 행 클릭과 겹치지 않게 전파를 막는다. */}
                    <Link
                      to={url}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`인시던트 상세: ${item.hostIp} · ${captureInfo(item.captureId).text}`}
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
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <SourceCell item={item} />
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2 hidden text-slate-300 2xl:table-cell">
                  <CodeLabel dict="hostRole" value={item.zeekadRole} />
                </td>
                <td
                  className="soc-td-compact px-1.5 2xl:px-2 tabular-nums"
                  title={`발생 구간 ${formatDateTimeRange(item.eventStart, item.eventEnd)}`}
                >
                  <span className="text-slate-200">{compactOccurrence(item.eventStart, anchor)}</span>
                  <span className="mx-1 text-slate-600" aria-hidden="true">
                    ·
                  </span>
                  <span className="text-slate-400">{formatDuration(item.eventStart, item.eventEnd)}</span>
                  {item.ongoing && (
                    <span className="ml-1 inline-block align-middle">
                      <OngoingBadge snapshot={snapshot} />
                    </span>
                  )}
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <DetectionModelName id={item.zeekadPickedBy} className="font-semibold text-slate-100" />
                  <AlsoFlagged models={item.zeekadAlsoFlaggedBy} />
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <SignalChips item={item} />
                </td>
                <td
                  className="soc-td-compact px-1.5 2xl:px-2"
                  title={item.statusUpdatedAt ? `상태 갱신 ${formatDateTime(item.statusUpdatedAt)}` : undefined}
                >
                  <div className="flex items-center gap-1">
                    <IncidentStatusBadge status={item.zeekadStatus} />
                    <ResolutionBadge resolution={item.zeekadResolution} />
                  </div>
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2 hidden lg:table-cell">
                  <ReviewActionBadge action={item.zeekadReviewAction} pending={item.zeekadReviewPending} />
                </td>
                <td className={`soc-td-compact px-1.5 2xl:px-2 soc-num text-slate-300 ${connectionsCell}`} data-col="connections">
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
      className="ml-1 rounded border border-slate-700 bg-slate-800/80 px-1 text-[11px] tabular-nums text-slate-300"
    >
      <span aria-hidden="true">+{list.length}</span>
      <span className="sr-only">교차 탐지 모델 {list.length}개</span>
    </span>
  );
}

const CHIP_BASE = 'inline-flex h-5 w-5 items-center justify-center rounded border';

/** 리포트·검증·발송 판단을 묶은 아이콘 칩(T21: 세 번째 칩은 발송 판단 zeekadWouldSend이며 "경보 발송"이 아니다). 각 칩은 접근성 이름과 툴팁을 가진다. */
function SignalChips({ item }: { item: UnifiedQueueItem }) {
  const hasReport = item.zeekadReportJobId !== null;
  const kind = labelText('reportKind', item.zeekadReportKind);
  return (
    <div className="flex items-center gap-0.5 2xl:gap-1">
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

function QueueMobileList({
  rows,
  listQuery,
  anchor,
  snapshot,
  highlightAfter,
}: {
  rows: UnifiedQueueItem[];
  listQuery: string;
  anchor: string | null;
  snapshot: boolean;
  highlightAfter: string | null;
}) {
  return (
    <ul className="divide-y divide-slate-800/80 md:hidden" aria-label="인시던트 목록">
      {rows.map((item) => (
        <li key={`${item.jobId}-${item.queueRank}-${item.incidentId}`}>
          <Link
            to={detailUrl(item, listQuery)}
            className="block px-3 py-2.5 transition hover:bg-slate-800/40 focus:outline-none focus-visible:bg-slate-800/50"
          >
            <div className="flex items-center gap-2">
              <PriorityBadge priority={item.priority} />
              {isNewRow(item, highlightAfter) && <NewRowBadge />}
              <span className="shrink-0 font-mono text-sm font-semibold text-slate-100">{item.hostIp}</span>
              {item.hostName[0] !== undefined && (
                <span className="min-w-0 truncate font-mono text-[11px] text-slate-400">{item.hostName[0]}</span>
              )}
              <span className="ml-auto shrink-0 text-[11px] tabular-nums text-slate-400" title={`탐지 시각 ${formatDateTime(item.detectedAt)}`}>
                탐지 {formatRelativeTo(item.detectedAt, anchor)}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
              {/* T26: 링크의 접근성 이름에 "수집원: 종류 표시 이름 · 캡처 ID"가 들어가게 판독기용 글자를 더한다 */}
              <span className="sr-only">수집원: </span>
              <SourceTypeBadge type={item.sourceType} />
              <CaptureName id={item.captureId} className="min-w-0 truncate text-[11px] text-slate-400" />
              <span className="sr-only">{` · 캡처 ID: ${item.captureId}`}</span>
              {item.ongoing && <OngoingBadge snapshot={snapshot} />}
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
  page,
  pageCount,
  pageSize,
  onPage,
  onSize,
}: {
  total: number;
  page: number;
  pageCount: number;
  pageSize: number;
  onPage: (page: number) => void;
  onSize: (size: number) => void;
}) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav
      aria-label="쪽 이동"
      className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 px-3 py-2 text-xs text-slate-400"
    >
      <span className="tabular-nums" aria-live="polite">
        전체 {formatNumber(total)}건 중 {formatNumber(from)}–{formatNumber(to)}
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
            onClick={() => onPage(page - 1)}
            disabled={page <= 1}
            aria-label="이전 쪽"
            className="rounded p-1 hover:bg-slate-800 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" aria-hidden="true" />
          </button>
          {pageList(page, pageCount).map((p, i) =>
            p === 'gap' ? (
              <span key={`gap-${i}`} className="px-1 text-slate-600" aria-hidden="true">
                …
              </span>
            ) : (
              <button
                key={p}
                type="button"
                onClick={() => onPage(p)}
                aria-current={p === page ? 'page' : undefined}
                aria-label={`${p}쪽`}
                className={`min-w-[1.75rem] rounded px-1.5 py-0.5 tabular-nums ${
                  p === page ? 'bg-cyan-500/15 font-semibold text-cyan-200' : 'hover:bg-slate-800 hover:text-slate-100'
                }`}
              >
                {p}
              </button>
            ),
          )}
          <button
            type="button"
            onClick={() => onPage(page + 1)}
            disabled={page >= pageCount}
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
