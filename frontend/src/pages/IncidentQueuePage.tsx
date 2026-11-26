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
  ClipboardList,
  Database,
  Download,
  FileText,
  FileX,
  Filter,
  Info,
  Lock,
  Radio,
  RotateCcw,
  ShieldCheck,
  UserCheck,
  X,
} from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { AppShell } from '../components/AppShell';
import { AckOverdueBadge, AssigneeName, elapsedText } from '../components/incident/AssignmentBits';
import { PeriodButtons, SourceField, sourceSelectChanges, sourceSelectValue } from '../components/ConditionBar';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import { EmptyPeriodText, hasOutsideToShow, OutsidePeriodNotice } from '../components/OutsidePeriodNotice';
import {
  CaptureName,
  CodeLabel,
  CriticalAssetBadge,
  DetectionModelName,
  IncidentStatusBadge,
  NewRowBadge,
  OngoingBadge,
  PRIORITY_COLUMN_TOOLTIP,
  PRIORITY_TOOLTIP,
  PriorityBadge,
  ResolutionBadge,
  ReviewActionBadge,
  SOURCE_TYPE_LABEL,
  SourceTypeBadge,
} from '../components/StatusBadge';
import type { UnifiedQueueItem, UnifiedQueueResponse } from '../types/api';
import {
  formatDateTime,
  formatDateTimeRange,
  formatDuration,
  formatNumber,
  formatCompactDateTime,
  formatRelativeTo,
} from '../utils/format';
import { attackFilterLabel } from '../utils/attackFilter';
import { downloadQueueCsv } from '../utils/incidentExport';
import { hostIpKind } from '../utils/ipScope';
import { incidentPath } from '../utils/incidentLink';
import {
  captureInfo,
  captureShortNames,
  detectionModelInfo,
  labelText,
  lookupLabel,
  REPORT_KIND_DESCRIPTION,
  shortNameOf,
  unregisteredTitle,
  VERIFICATION_DESCRIPTION,
} from '../utils/labels';
import {
  DEFAULT_PAGE_SIZE,
  DEFAULT_PERIOD,
  DEFAULT_SORT_DIR,
  LEGACY_JOB_NOTICE,
  migrateLegacyQueueParams,
  PAGE_SIZES,
  PANEL_FILTER_KEYS,
  customUrlChanges,
  parseQueueQuery,
  periodScopeText,
  presetUrlChanges,
  PRIORITY_VALUES,
  parseAssignee,
  queueApiParams,
  STRIP_FILTER_KEYS,
  type PresetPeriod,
  type Priority,
  type SortDir,
  type SortKey,
} from '../utils/triage';

/** 자동 갱신 주기(T23): 60초마다 새 인시던트 수를 묻는다. 화면이 숨겨지면 멈춘다. */
export const NEW_INCIDENT_POLL_MS = 60_000;

/** T42: 성공한 큐 응답과 그 조건 키. apiKey = 요청 전체(행·쪽 표시), summaryKey = 쪽·정렬·크기를 뺀 조건(띠 합계 등) */
interface QueueLoaded {
  apiKey: string;
  summaryKey: string;
  res: UnifiedQueueResponse;
  loadedAt: string;
}

/** 필터·정렬·쪽 크기 변경 때 지우는 쪽 번호 키 */
const PAGE_KEY = 'page';

/**
 * 상세 주소. 목록의 쿼리(기간·수집원·거르기·정렬·쪽)를 `from=`으로 넘겨 상세의 이전·다음(neighbors API)과 목록 복귀가 같은 조건을 쓴다.
 */
function detailUrl(item: UnifiedQueueItem, listQuery: string): string {
  // T27: 번호가 있으면 고정 주소, 없으면 옛 주소
  return incidentPath(item, new URLSearchParams({ from: listQuery })) ?? '/incidents';
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
  const { user } = useAuth();
  /** 담당 선택(T25): VIEWER는 담당자가 될 수 없어 "내 담당"을 보이지 않는다 */
  const canBeAssignee = user?.role === 'ANALYST' || user?.role === 'ADMIN';
  /** 마지막으로 성공한 응답과 그 응답의 조건 키(T42). 키가 지금 조건과 같을 때만 그린다 */
  const [loaded, setLoaded] = useState<QueueLoaded | null>(null);
  /** 조건과 상관없는 값(수집원 목록·짧은 이름·모델·역할 선택지·스냅샷 여부): 마지막 성공 응답의 것을 조건이 바뀌어도 쓴다 */
  const [barData, setBarData] = useState<UnifiedQueueResponse | null>(null);
  const requestSeq = useRef(0);
  /** 서버가 쪽 번호를 고쳐 준 응답의 키. 주소를 그 쪽으로 고친 뒤 같은 요청을 다시 보내지 않는다 */
  const skipLoadKeyRef = useRef<string | null>(null);
  const [loading, setLoading] = useState(true);
  /** 마지막 실패와 그 요청 키. 같은 키의 다음 성공 때 지운다 */
  const [failure, setFailure] = useState<{ apiKey: string; notice: ErrorNotice } | null>(null);
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
  /** 띠 합계·새 건수·기간 밖 안내의 조건 키(T42): 쪽·정렬·크기를 뺀 조건(기간은 넣는다). 합계는 쪽·정렬과 무관하다 */
  const summaryKey = JSON.stringify(queueApiParams(query, { paging: false, sort: false }));

  const [assetDraft, setAssetDraft] = useState(query.asset);
  useEffect(() => {
    setAssetDraft(query.asset);
  }, [query.asset]);

  const loadQueue = useCallback(async () => {
    const seq = ++requestSeq.current;
    setLoading(true);
    const params = JSON.parse(apiKey) as Record<string, string | undefined>;
    try {
      const res = await incidentsApi.queue(params);
      if (seq !== requestSeq.current) return;
      // 서버가 쪽 번호를 고쳐 준 응답(없는 쪽 → 마지막 쪽)은 고친 쪽의 값으로 기억한다.
      // 주소를 그 쪽으로 고치면 지금 조건과 키가 같아져 숨기지 않고, 같은 요청을 다시 보내지 않는다.
      let key = apiKey;
      if (params.page !== undefined && params.page !== String(res.page)) {
        key = JSON.stringify({ ...params, page: String(res.page) });
        skipLoadKeyRef.current = key;
      }
      setLoaded({ apiKey: key, summaryKey, res, loadedAt: new Date().toISOString() });
      setBarData(res);
      setFailure(null);
      setHighlightAfter(pendingHighlightRef.current);
      pendingHighlightRef.current = null;
    } catch (err) {
      if (seq !== requestSeq.current) return;
      setFailure({ apiKey, notice: errorNotice(err, '인시던트 목록을 불러오지 못했습니다.') });
      pendingHighlightRef.current = null;
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [apiKey, summaryKey]);

  useEffect(() => {
    if (legacy.changed) return;
    if (skipLoadKeyRef.current !== null && skipLoadKeyRef.current === apiKey) {
      // 서버가 고쳐 준 쪽으로 주소만 고친 경우: 이미 그 쪽의 값이 있다
      skipLoadKeyRef.current = null;
      return;
    }
    skipLoadKeyRef.current = null;
    void loadQueue();
    // reloadTick: 같은 쿼리로 다시 부를 때(새 인시던트 불러오기)
  }, [loadQueue, legacy.changed, reloadTick, apiKey]);

  /** 행·쪽 표시: 요청 전체(apiKey)가 지금 조건과 같은 성공 응답만 */
  const rowsLoaded = loaded !== null && loaded.apiKey === apiKey ? loaded : null;
  /** 띠 합계·새 건수·기간 밖 안내: 쪽·정렬·크기를 뺀 조건이 같은 성공 응답만 */
  const summaryLoaded = loaded !== null && loaded.summaryKey === summaryKey ? loaded : null;
  const data = rowsLoaded?.res ?? null;
  const summaryData = summaryLoaded?.res ?? null;
  const failed = failure !== null && failure.apiKey === apiKey ? failure.notice : null;
  /** 같은 조건으로 성공한 행을 남긴 채 다시 불러오기가 실패한 상태(최신이 아니다) */
  const stale = failed !== null && rowsLoaded !== null;

  // 범위 밖 page는 서버가 고친 쪽으로, 허용 밖 size는 50으로 URL을 고친다(지금 요청의 응답을 받은 뒤에만).
  // 서버가 쪽을 고쳤으면 rowsLoaded가 아직 없다(키가 고친 쪽이라). 그때는 loaded의 원래 요청 쪽을 본다.
  useEffect(() => {
    if (loading || !loaded) return;
    const data = loaded.res;
    const requested = JSON.parse(apiKey) as Record<string, string | undefined>;
    const matches =
      loaded.apiKey === apiKey ||
      (skipLoadKeyRef.current === loaded.apiKey &&
        loaded.apiKey === JSON.stringify({ ...requested, page: String(data.page) }));
    if (!matches) return;
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
  }, [loading, loaded, apiKey, searchParams, setSearchParams, query.size]);

  // T42: since는 지금 조건(쪽·정렬 제외)의 성공 응답에서만 가져온다. 없으면 묻지 않는다
  // (앞 조건의 최신 시각으로 지금 조건을 세면 틀린 "새 인시던트 N건"이 뜬다).
  const since = summaryData ? (summaryData.latestDetectedAt ?? summaryData.anchor) : null;
  /** 짧은 수집원 이름(허용 캡처 목록 안에서 겹치면 연도를 붙인다). 조건과 상관없는 값 */
  const shortNames = useMemo(() => captureShortNames((barData?.sources ?? []).map((s) => s.captureId)), [barData]);
  // T34: 지정 기간은 지난 구간을 조사하는 화면이라 "새 인시던트" 확인(new-count)을 하지 않는다
  const customPeriod = query.period === 'custom';
  const newCount = useNewIncidentCount(
    summaryData !== null && !summaryData.snapshot && !customPeriod,
    since,
    pollKey,
  );

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
    // T34: 지정 기간은 시작·끝도 남긴다
    if (period === 'custom') {
      for (const key of ['start', 'end']) {
        const v = searchParams.get(key);
        if (v) next.set(key, v);
      }
    }
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

  function handlePeriod(value: PresetPeriod) {
    updateParams(presetUrlChanges(value, DEFAULT_PERIOD));
  }

  /** 수집원 선택: '' = 전체, 'src:live|imported' = 종류 전체, 'cap:<id>' = 캡처 하나 */
  function handleSource(value: string) {
    updateParams(sourceSelectChanges(value));
  }

  /** 새 인시던트 불러오기: 탐지 시각 최근순 1쪽을 다시 부르고 새 행에 표지를 붙인다. */
  function handleLoadNew() {
    pendingHighlightRef.current = since;
    const next = new URLSearchParams(searchParams);
    next.set('sort', 'detected');
    next.set('dir', 'desc');
    next.delete(PAGE_KEY);
    const nextQuery = parseQueueQuery(next);
    if (JSON.stringify(queueApiParams(nextQuery)) === apiKey) {
      // 기본 정렬 1쪽: 같은 조건 다시 불러오기(주소는 그대로라 요청은 reloadTick 한 번)
      setReloadTick((n) => n + 1);
    } else {
      // 다른 정렬·쪽: 조건 변경이다. 주소 변경만으로 한 번 부른다(reloadTick을 함께 올리지 않는다)
      setSearchParams(next);
    }
  }

  const listQuery = useMemo(() => searchParams.toString(), [searchParams]);

  const chips = useMemo(() => {
    const list: { key: string; label: string; raw?: string; title?: string }[] = [];
    // T40 알림 묶음 조건(상세 Slack 탭의 "같은 묶음 인시던트 N건 보기"에서 온다)
    if (query.thread !== null)
      list.push({
        key: 'thread',
        label: `알림 묶음 #${query.thread}`,
        title: `최초 알림 인시던트 #${query.thread}의 Slack 스레드에 묶인 인시던트만 봅니다`,
      });
    // T45 호스트 정확 일치(상세 헤더의 호스트 링크에서 온다). 형식이 틀린 값도 칩으로 남겨 지울 수 있게 한다
    if (query.hostIp) {
      const kind = hostIpKind(query.hostIp);
      list.push({
        key: 'hostIp',
        label: kind === 'masked' ? '호스트 대역' : '호스트',
        raw: query.hostIp,
        title:
          kind === 'masked'
            ? '호스트 IP가 이 대역인 인시던트만 봅니다'
            : kind === 'exact'
              ? '호스트 IP가 이 주소와 정확히 같은 인시던트만 봅니다'
              : undefined,
      });
    }
    // T45 ATT&CK 기법 ID·전술
    if (query.attack) {
      const attack = attackFilterLabel(query.attack);
      const title = '리포트의 관련 ATT&CK 기법 후보(확정이 아닌 가설)에 이 값이 있는 인시던트만 봅니다';
      list.push(
        attack.kind === 'technique' || attack.value === query.attack
          ? { key: 'attack', label: attack.label, raw: attack.value, title }
          : { key: 'attack', label: `${attack.label}: ${attack.value}`, title },
      );
    }
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
    if (query.overdue) list.push({ key: 'overdue', label: '착수 지연만' });
    return list;
  }, [query.thread, query.hostIp, query.attack, query.pickedBy, query.role, query.status, query.hasReport, query.wouldSend, query.asset, query.priority, query.reviewPending, query.alerted, query.overdue]);

  function toggleStripFilter(key: (typeof STRIP_FILTER_KEYS)[number], value: string) {
    const current = searchParams.get(key);
    updateParams({ [key]: current === value ? null : value });
  }

  const panelFilterCount = PANEL_FILTER_KEYS.filter((k) => (searchParams.get(k) ?? '') !== '').length;
  const anyFilter =
    chips.length > 0 || query.source !== null || query.captureId !== null || query.assignee !== null;
  const sourceValue = sourceSelectValue(query.source, query.captureId);
  const items = data?.items ?? [];

  return (
    <AppShell title="인시던트">
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
          summary={summaryData?.summary ?? null}
          priorityFilter={query.priority}
          reviewPendingFilter={query.reviewPending}
          alertedFilter={query.alerted}
          overdueFilter={query.overdue}
          onToggle={toggleStripFilter}
        />

        <OutsidePeriodNotice queue={summaryData} onAllPeriod={() => handlePeriod('all')} />

        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <PeriodButtons
              value={query.period}
              range={query.range}
              onChange={handlePeriod}
              onApplyRange={(r) => updateParams(customUrlChanges(r))}
              current={
                summaryData
                  ? { periodStart: summaryData.periodStart, periodEnd: summaryData.periodEnd, anchor: summaryData.anchor }
                  : null
              }
            />

            <SourceField
              sources={barData?.sources ?? []}
              value={sourceValue}
              onChange={handleSource}
              anchor={barData?.anchor ?? null}
              snapshot={Boolean(barData?.snapshot)}
            />

            <AssigneeField
              value={query.assignee}
              showMine={canBeAssignee}
              onChange={(v) => updateParams({ assignee: parseAssignee(v) })}
            />

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
                      title={chip.title}
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

            <div className="ml-auto flex max-w-full flex-wrap items-center gap-2">
              {barData?.snapshot && (
                <span
                  className="inline-flex items-center gap-1 text-[11px] text-slate-400"
                  title="데이터가 더 늘지 않는 고정 스냅샷이라 새 인시던트를 확인하지 않습니다"
                >
                  <Lock className="h-3 w-3" aria-hidden="true" />
                  고정 스냅샷 · 자동 갱신 꺼짐
                </span>
              )}
              {/* T44: 지금 보이는 쪽만, 추가 요청 없이. 값이 없거나 최신이 아니면(T42) 내려받지 않는다 */}
              <button
                type="button"
                disabled={!data || stale || items.length === 0}
                onClick={() => downloadQueueCsv(items)}
                className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-200 transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-50"
                title="지금 보이는 쪽의 인시던트를 CSV 파일로 내려받습니다"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                CSV 내보내기
              </button>
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
                  {(barData?.availableModels ?? []).map((m) => (
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
                  {(barData?.availableRoles ?? []).map((r) => (
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

        {customPeriod && summaryData && !summaryData.snapshot && (
          <p className="text-[11px] text-slate-400" data-testid="new-count-off">
            기간을 지정하면 새 인시던트 알림을 멈춥니다(지난 구간을 보는 동안 목록이 움직이지 않게).
          </p>
        )}

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

        {failed && stale && (
          <StaleNotice
            notice={failed}
            loadedAt={rowsLoaded?.loadedAt ?? null}
            loading={loading}
            onRetry={() => void loadQueue()}
          />
        )}
        {failed && !stale && (
          <ErrorAlert message={failed.message} rateLimited={failed.rateLimited} onRetry={() => void loadQueue()} />
        )}

        {/* T42: 지금 조건(요청 전체)의 성공 응답이 없으면 행·빈 목록 문구·쪽 표시를 그리지 않는다.
            조건을 바꾼 뒤 불러오는 동안에는 앞 조건의 행 대신 불러오는 중 표시를 둔다(실패면 위 배너만). */}
        {!data ? (
          loading ? <LoadingPanel label="인시던트 목록을 불러오는 중..." /> : null
        ) : (
          <div className="soc-card overflow-hidden">
            {items.length === 0 ? (
              <EmptyState
                data={data}
                anyFilter={anyFilter}
                sourceValue={sourceValue}
                onAllPeriod={() => handlePeriod('all')}
                onReset={handleResetFilters}
              />
            ) : (
              <>
                <QueueTable
                  rows={items}
                  shortNames={shortNames}
                  sortKey={query.sortKey}
                  sortDir={query.sortDir}
                  onSort={handleSort}
                  listQuery={listQuery}
                  anchor={data?.anchor ?? null}
                  snapshot={Boolean(data?.snapshot)}
                  highlightAfter={highlightAfter}
                  masked={Boolean(data?.maskedView)}
                />
                <QueueMobileList
                  rows={items}
                  listQuery={listQuery}
                  anchor={data?.anchor ?? null}
                  snapshot={Boolean(data?.snapshot)}
                  highlightAfter={highlightAfter}
                  masked={Boolean(data?.maskedView)}
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

/* ───────────────────────── 빈 결과 ───────────────────────── */

function EmptyState({
  data,
  anyFilter,
  sourceValue,
  onAllPeriod,
  onReset,
}: {
  data: UnifiedQueueResponse | null;
  anyFilter: boolean;
  sourceValue: string;
  onAllPeriod: () => void;
  onReset: () => void;
}) {
  if (data && hasOutsideToShow(data)) {
    return (
      <div className="space-y-2 px-4 py-12 text-center text-sm text-slate-300" data-empty="period">
        <EmptyPeriodText queue={data} sourceValue={sourceValue} />
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
      {data && data.period === 'custom' && data.periodStart && data.periodEnd
        ? `${periodScopeText({ period: 'custom', range: { start: data.periodStart, end: data.periodEnd } }, data.anchor)} 동안 탐지된 인시던트가 없습니다.`
        : data && data.period !== 'all' && data.period !== 'custom'
          ? `${periodScopeText({ period: data.period as PresetPeriod, range: null })} 동안 탐지된 인시던트가 없습니다.`
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
  overdueFilter,
  onToggle,
}: {
  summary: UnifiedQueueResponse['summary'] | null;
  priorityFilter: Priority | null;
  reviewPendingFilter: boolean;
  alertedFilter: boolean;
  overdueFilter: boolean;
  onToggle: (key: 'priority' | 'reviewPending' | 'alerted' | 'overdue', value: string) => void;
}) {
  // T42: 지금 조건의 성공 응답이 없으면 수를 지어내지 않는다(0이 아니라 값 없음 "-"). 거르기 버튼은 그대로 누를 수 있다
  const has = summary !== null;
  const s = summary ?? { total: 0, high: 0, medium: 0, low: 0, reviewPending: 0, alerted: 0, byStatus: {}, overdue: 0 };
  const n = (v: number) => (has ? formatNumber(v) : formatNumber(null));
  const countText = (v: number) => (has ? ` ${v}건` : '');
  const overdue = s.overdue ?? 0;
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
        <span className="text-lg font-bold tabular-nums text-slate-100">{n(s.total)}</span>
      </div>

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      {PRIORITY_VALUES.map((p) => (
        <StripButton
          key={p}
          pressed={priorityFilter === p}
          onClick={() => onToggle('priority', p)}
          ariaLabel={`우선순위 ${labelText('priority', p)}${countText(s[p])}만 보기`}
          title={PRIORITY_TOOLTIP}
        >
          <span className={`h-2 w-2 rounded-full ${priorityDot[p]}`} aria-hidden="true" />
          <span className="text-slate-400">{labelText('priority', p)}</span>
          <span className={`text-base font-bold tabular-nums ${priorityNum[p]}`}>{n(s[p])}</span>
        </StripButton>
      ))}

      <span className="mx-1 hidden h-6 w-px bg-slate-800 sm:block" aria-hidden="true" />

      <div className="flex items-center">
        <StripButton
          pressed={reviewPendingFilter}
          onClick={() => onToggle('reviewPending', 'true')}
          ariaLabel={`에스컬레이션 대기${countText(s.reviewPending)}만 보기`}
        >
          <span className="text-slate-400">에스컬레이션 대기</span>
          <span
            className={`text-base font-bold tabular-nums ${s.reviewPending > 0 ? 'text-amber-300' : 'text-slate-300'}`}
          >
            {n(s.reviewPending)}
          </span>
        </StripButton>
        <Link to="/reviews?pendingOnly=true" className="px-1 text-[11px] text-cyan-300 hover:underline">
          에스컬레이션으로 이동
        </Link>
      </div>

      <StripButton
        pressed={alertedFilter}
        onClick={() => onToggle('alerted', 'true')}
        ariaLabel={`경보 발송${countText(s.alerted)}만 보기`}
      >
        <Bell className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
        <span className="text-slate-400">경보 발송</span>
        <span className="text-base font-bold tabular-nums text-slate-100">{n(s.alerted)}</span>
      </StripButton>

      <StripButton
        pressed={overdueFilter}
        onClick={() => onToggle('overdue', 'true')}
        ariaLabel={`착수 지연${countText(overdue)}만 보기`}
        title="실습망 신규 인시던트가 우선순위별 착수 목표 시간을 넘긴 수"
      >
        <span className="text-slate-400">착수 지연</span>
        <span className={`text-base font-bold tabular-nums ${overdue > 0 ? 'text-rose-300' : 'text-slate-300'}`}>
          {n(overdue)}
        </span>
      </StripButton>

      <details className="relative ml-auto">
        <summary className="flex cursor-pointer list-none items-center gap-1 rounded-md px-2 py-1 text-[11px] text-slate-400 transition hover:text-slate-100 [&::-webkit-details-marker]:hidden">
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
          자동 분류 기준
        </summary>
        <div className="soc-card absolute right-0 top-full z-20 mt-1 w-80 max-w-[calc(100vw-2rem)] p-3 text-xs leading-relaxed text-slate-300">
          <p className="mb-2 text-slate-400">
            우선순위는 파이프라인 결과와 중요 자산 등록으로 서버가 자동 계산한 값입니다. 분석가 판정이 아닙니다.
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
            <li>중요 자산으로 등록된 호스트의 인시던트는 한 단계 올립니다(Low → Medium, Medium → High).</li>
            <li>같은 우선순위 안에서는 중요 자산이 먼저 옵니다.</li>
          </ul>
          <p className="mt-2 text-slate-400">
            기본 정렬은 우선순위, 같으면 탐지 시각 최근 순입니다. 기간은 탐지 시각(인시던트가 처음 탐지된 분석 완료
            시각) 기준입니다.
          </p>
          <p className="mt-2 text-slate-400">
            착수 목표: 실습망 신규 인시던트는 탐지 뒤 High 30분·Medium 4시간·Low 24시간(기본값) 안에 조사를 시작해야
            합니다. 넘기면 &lsquo;착수 지연&rsquo;입니다. 가져온 데이터는 재생 데이터라 따지지 않습니다.
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

/** T27 행 링크 접근성 이름 앞머리: "인시던트 번호 1042, "(번호가 없으면 빈 글) */
function noLabel(item: UnifiedQueueItem): string {
  return typeof item.incidentNo === 'number' ? `인시던트 번호 ${item.incidentNo}, ` : '';
}

function isNewRow(item: UnifiedQueueItem, highlightAfter: string | null): boolean {
  if (!highlightAfter || !item.detectedAt) return false;
  return new Date(item.detectedAt).getTime() > new Date(highlightAfter).getTime();
}

/**
 * 탐지 · 경과(T25, 한 줄): 탐지 시각(같은 해면 연도 생략)과 기준 시각까지의 경과. 종결이면 "처리 N"(종결 − 탐지).
 * 착수 지연이면 빨간 "착수 지연" 표지를 단다. 전체 탐지 시각(KST)은 툴팁에 둔다.
 */
function DetectedCell({ item, anchor }: { item: UnifiedQueueItem; anchor: string | null }) {
  if (!item.detectedAt) {
    return <span className="text-slate-500">-</span>;
  }
  const el = elapsedText(item.detectedAt, item.zeekadStatus, item.statusUpdatedAt, anchor);
  const detectedTitle = `탐지 시각 ${formatDateTime(item.detectedAt)}`;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap" data-detected-cell="" title={detectedTitle}>
      {/* T27: 1920px 미만은 탐지 시각을 빼고 경과와 표지만 보인다(탐지 시각은 툴팁과 판독기 글자) */}
      <span className="hidden text-slate-300 min-[1920px]:inline" data-detected-time="">
        {compactOccurrence(item.detectedAt, anchor)}
      </span>
      <span className="sr-only min-[1920px]:hidden">{`${detectedTitle} · `}</span>
      {el && (
        <>
          <span className="hidden text-slate-600 min-[1920px]:inline" aria-hidden="true">
            ·
          </span>
          <span
            className={el.kind === 'handled' ? 'text-slate-400' : 'text-slate-100'}
            title={el.kind === 'handled' ? '처리 시간: 종결 시각 − 탐지 시각' : '탐지 뒤 경과(기준 시각까지)'}
          >
            {el.text}
          </span>
        </>
      )}
      {item.ackOverdue && <AckOverdueBadge dueAt={item.ackDueAt} detectedAt={item.detectedAt} compact />}
    </span>
  );
}

/**
 * 수집원(한 줄): 종류 아이콘 + 짧은 수집원 이름(T24, "CIC 수"·"실습 11-19"). 종류 문구·전체 이름·캡처 ID는 툴팁에 둔다.
 * T26: 역할 없는 span의 aria-label은 화면 판독기가 읽지 않을 수 있어 sr-only 글자를 쓴다.
 * T24: 보이는 짧은 이름은 판독기에서 감추고(aria-hidden), 판독기 글자에 "수집원: 종류 · 전체 이름 · 캡처 ID"를 둔다.
 */
function SourceCell({ item, shortNames }: { item: UnifiedQueueItem; shortNames: Map<string, string> }) {
  const info = captureInfo(item.captureId);
  const typeText = SOURCE_TYPE_LABEL[item.sourceType] ?? '-';
  const label = `${typeText} · ${info.text} · 캡처 ID: ${item.captureId}`;
  const Icon = item.sourceType === 'live' ? Radio : Database;
  return (
    <span title={label} className="flex max-w-[5.5rem] items-center gap-1 2xl:max-w-[13rem]" data-source-cell="">
      <Icon className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
      <span className="min-w-0 truncate text-slate-300" aria-hidden="true" data-short-name="">
        {shortNameOf(shortNames, item.captureId)}
      </span>
      <span className="sr-only">{`수집원: ${typeText} · ${info.text} · 캡처 ID: ${item.captureId}`}</span>
    </span>
  );
}

/** 발생 시각(한 줄): 초를 빼고, 기준 시각과 같은 해면 연도를 뺀다(해가 다르면 연도를 보인다). 전체 구간은 칸 툴팁. */
function compactOccurrence(iso: string | null, anchor: string | null): string {
  return formatCompactDateTime(iso, anchor);
}

function QueueTable({
  rows,
  shortNames,
  sortKey,
  sortDir,
  onSort,
  listQuery,
  anchor,
  snapshot,
  highlightAfter,
  masked,
}: {
  rows: UnifiedQueueItem[];
  shortNames: Map<string, string>;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (key: SortKey) => void;
  listQuery: string;
  anchor: string | null;
  snapshot: boolean;
  highlightAfter: string | null;
  /** 조회자 화면: 중요 자산 이름을 쓰지 않는다(서버도 주지 않는다) */
  masked: boolean;
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
  // 1536px(2xl) 미만에서 통신 방향·세션 수·발생 시각 · 지속은 숨긴다(값은 상세·행 툴팁에 있다). T25: 담당 칸을 더하며
  // 1280px 행을 한 줄로 두려고 발생 시각 · 지속도 2xl부터 보인다. 지금 정렬 기준인 열은 숨기지 않는다.
  // T27: 1536~1919px에서는 번호 칸을 더하며 통신 방향과 세션 수도 숨긴다(1920px부터 보임, 정렬 기준이면 숨기지 않음)
  const connectionsCell = sortKey === 'connections' ? '' : 'hidden min-[1920px]:table-cell';
  const occurrenceCell = sortKey === 'start' ? '' : 'hidden 2xl:table-cell';
  return (
    <div className="hidden overflow-x-auto md:block" data-queue-table-wrap="">
      <table className="w-full border-collapse text-left">
        <caption className="sr-only">인시던트 목록. 호스트 링크나 행을 누르거나 행에서 Enter 키를 누르면 인시던트 상세로 갑니다.</caption>
        <thead>
          <tr>
            {/* T27: 인시던트 번호는 1536px(2xl)부터 맨 앞 칸. 정렬은 없다. 좁은 화면은 행 링크 이름에 번호가 있다 */}
            <th scope="col" className="soc-th-compact hidden px-1.5 2xl:table-cell 2xl:px-2" data-col-head="incident-no">
              번호
            </th>
            <SortHeader column="priority" label="우선순위" title={PRIORITY_COLUMN_TOOLTIP} {...headerProps} />
            <SortHeader
              column="detected"
              label="탐지 · 경과"
              title="인시던트가 처음 탐지된 분석 완료 시각과 그 뒤 지난 시간(종결이면 처리 시간)"
              {...headerProps}
            />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              호스트
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              수집원
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2 hidden min-[1920px]:table-cell">
              통신 방향
            </th>
            <SortHeader
              column="start"
              label="발생 시각 · 지속"
              title="트래픽이 관측된 시각(원본 그대로)"
              className={occurrenceCell}
              {...headerProps}
            />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2">
              탐지 모델
            </th>
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2" title="리포트(AI 작성·템플릿) · 검증 · 발송 판단">
              리포트·판단
            </th>
            <SortHeader column="status" label="상태 · 판정" {...headerProps} />
            <th scope="col" className="soc-th-compact px-1.5 2xl:px-2" title="이 인시던트를 맡은 분석가">
              담당
            </th>
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
                <td
                  className="soc-td-compact hidden px-1.5 font-mono tabular-nums text-slate-300 2xl:table-cell 2xl:px-2"
                  data-col="incident-no"
                >
                  {typeof item.incidentNo === 'number' ? `#${item.incidentNo}` : '-'}
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <div className="flex items-center gap-1">
                    {/* T62: 중요 자산 왕관은 우선순위 배지 오른쪽 위 모서리에 겹쳐 둔다(칸 폭을 늘리지 않는다. 배지 오른쪽 여백 안에 걸친다) */}
                    <span className={`relative inline-flex ${item.assetCritical ? 'mr-1.5' : ''}`}>
                      <PriorityBadge priority={item.priority} />
                      {item.assetCritical && (
                        <span className="absolute -right-1.5 -top-1.5 inline-flex">
                          <QueueCriticalBadge item={item} masked={masked} iconOnly />
                        </span>
                      )}
                    </span>
                    {isNewRow(item, highlightAfter) && <NewRowBadge />}
                  </div>
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2 tabular-nums">
                  <DetectedCell item={item} anchor={anchor} />
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  {/* T27: 호스트 칸 최대 폭은 1920px부터 15rem. IP는 그대로이고 호스트 이름 최대 폭은
                      1536px 미만 2.5rem · 1536~1919px 4rem · 1920px부터 제한 없음(칸 최대 폭 안에서 말줄임) */}
                  <div className="flex items-baseline gap-1.5 min-[1920px]:max-w-[15rem]">
                    {/* 화면 판독기가 행을 링크로 알 수 있게 실제 링크를 둔다(T18). 행 클릭과 겹치지 않게 전파를 막는다. */}
                    <Link
                      to={url}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`${noLabel(item)}인시던트 상세: ${item.hostIp} · ${captureInfo(item.captureId).text}`}
                      className="shrink-0 font-mono font-semibold text-slate-100 hover:text-cyan-200 hover:underline focus:outline-none focus-visible:underline"
                    >
                      {item.hostIp}
                    </Link>
                    {firstName !== undefined && (
                      <span
                        className="min-w-0 max-w-[2.5rem] truncate font-mono text-[11px] text-slate-400 2xl:max-w-[4rem] min-[1920px]:max-w-none"
                        title={item.hostName.join(', ')}
                        data-host-name=""
                      >
                        {firstName}
                        {moreNames > 0 && <span className="ml-1 font-sans text-slate-500">외 {moreNames}</span>}
                      </span>
                    )}
                  </div>
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2">
                  <SourceCell item={item} shortNames={shortNames} />
                </td>
                <td className="soc-td-compact px-1.5 2xl:px-2 hidden text-slate-300 min-[1920px]:table-cell">
                  <CodeLabel dict="hostRole" value={item.zeekadRole} />
                </td>
                <td
                  className={`soc-td-compact px-1.5 2xl:px-2 tabular-nums ${occurrenceCell}`}
                  title={`발생 구간 ${formatDateTimeRange(item.eventStart, item.eventEnd)}`}
                  data-col="occurrence"
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
                  <div className="flex items-center gap-1">
                    <SignalChips item={item} />
                    <ThreadBadge item={item} />
                  </div>
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
                <td className="soc-td-compact px-1.5 2xl:px-2" data-col="assignee">
                  {/* T27: 담당 최대 폭 1536px 미만 4.5rem · 1536~1919px 6rem · 1920px부터 7.5rem(전체 이름은 툴팁) */}
                  <AssigneeName assignee={item.assignee} className="max-w-[4.5rem] text-xs 2xl:max-w-[6rem] min-[1920px]:max-w-[7.5rem]" />
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

/**
 * T45 알림 묶음 표지: 이 인시던트가 든 가장 큰 Slack 알림 묶음의 건수. 누르면 그 묶음의 인시던트 목록(전체 기간)으로 간다.
 * 건수는 지금 조건(기간·수집원)과 무관하게 볼 수 있는 수집원 전체에서 센 값이라 가는 목록의 건수와 같다.
 * 행 클릭(상세로 이동)과 겹치지 않게 전파를 막는다. 값이 없으면 아무것도 그리지 않는다.
 */
export function ThreadBadge({ item }: { item: UnifiedQueueItem }) {
  const head = item.threadHeadNo;
  const count = item.threadMemberCount;
  if (typeof head !== 'number' || typeof count !== 'number') {
    return null;
  }
  const label = `알림 묶음 ${formatNumber(count)}건 · 최초 알림 인시던트 #${head}`;
  return (
    <Link
      to={`/incidents?period=all&thread=${head}`}
      onClick={(e) => e.stopPropagation()}
      title={label}
      aria-label={label}
      data-thread-badge=""
      className="shrink-0 whitespace-nowrap rounded border border-slate-700 bg-slate-800/80 px-1 text-[11px] tabular-nums text-slate-300 hover:border-cyan-500/60 hover:text-cyan-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
    >
      묶음 {formatNumber(count)}건
    </Link>
  );
}

const CHIP_BASE = 'inline-flex h-5 w-5 items-center justify-center rounded border';

/** 리포트·검증·발송 판단을 묶은 아이콘 칩(T21: 세 번째 칩은 발송 판단 zeekadWouldSend이며 "경보 발송"이 아니다). 각 칩은 접근성 이름과 툴팁을 가진다. */
export function SignalChips({ item }: { item: UnifiedQueueItem }) {
  const hasReport = item.zeekadReportJobId !== null;
  const kindLookup = lookupLabel('reportKind', item.zeekadReportKind);
  const kind = kindLookup.text;
  const kindNorm = (item.zeekadReportKind ?? '').trim().toLowerCase();
  return (
    <div className="flex items-center gap-0.5 2xl:gap-1">
      {hasReport && kindNorm === 'template' ? (
        // T43: 템플릿 리포트는 다른 아이콘·주의 색조로 그려 마우스를 올리지 않아도 AI 작성 리포트와 구분된다
        <span
          role="img"
          aria-label={REPORT_KIND_DESCRIPTION.template}
          title={`${REPORT_KIND_DESCRIPTION.template} · 리포트 작업 ${item.zeekadReportJobId}`}
          data-report-kind="template"
          className={`${CHIP_BASE} border-amber-500/40 bg-amber-500/10 text-amber-200`}
        >
          <ClipboardList className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : hasReport && kindNorm === 'llm' ? (
        <span
          role="img"
          aria-label={`${REPORT_KIND_DESCRIPTION.llm} 있음`}
          title={`${REPORT_KIND_DESCRIPTION.llm} · 리포트 작업 ${item.zeekadReportJobId}`}
          data-report-kind="llm"
          className={`${CHIP_BASE} border-slate-600 bg-slate-800 text-slate-100`}
        >
          <FileText className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : hasReport ? (
        <span
          role="img"
          aria-label={`AI 분석 리포트 있음: ${kind}`}
          title={`${kind} 리포트 · 리포트 작업 ${item.zeekadReportJobId}${
            !kindLookup.known && item.zeekadReportKind ? `
${unregisteredTitle(item.zeekadReportKind)}` : ''
          }`}
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
          aria-label={VERIFICATION_DESCRIPTION.passed}
          title={VERIFICATION_DESCRIPTION.passed}
          className={`${CHIP_BASE} border-emerald-500/35 bg-emerald-500/10 text-emerald-300`}
        >
          <ShieldCheck className="h-3 w-3" aria-hidden="true" />
        </span>
      ) : hasReport && item.zeekadVerificationPassed === false ? (
        <span
          role="img"
          aria-label={VERIFICATION_DESCRIPTION.failedQueue}
          title={VERIFICATION_DESCRIPTION.failedQueue}
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

/* ───────────────────────── 담당 선택(T25) ───────────────────────── */

/** 담당 조건: 전체 · 내 담당 · 미배정. VIEWER에게는 "내 담당"을 보이지 않는다(담당자가 될 수 없다). */
function AssigneeField({
  value,
  showMine,
  onChange,
}: {
  value: 'me' | 'none' | null;
  showMine: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-slate-400">
      <UserCheck className="h-3.5 w-3.5" aria-hidden="true" />
      <span>담당</span>
      <select
        aria-label="담당"
        value={value === 'me' && !showMine ? '' : (value ?? '')}
        onChange={(e) => onChange(e.target.value)}
        className="soc-select py-1 text-xs"
      >
        <option value="">전체</option>
        {showMine && <option value="me">내 담당</option>}
        <option value="none">미배정</option>
      </select>
    </label>
  );
}

/* ───────────────────────── 휴대폰 목록 ───────────────────────── */

function MobileElapsed({ item, anchor }: { item: UnifiedQueueItem; anchor: string | null }) {
  const el = elapsedText(item.detectedAt, item.zeekadStatus, item.statusUpdatedAt, anchor);
  if (!el) return null;
  return (
    <span className="tabular-nums text-slate-300">
      {el.kind === 'elapsed' ? `경과 ${el.text}` : el.text}
    </span>
  );
}

/**
 * T52 큐 행의 중요 자산 표지(우선순위 배지 옆). T62: 데스크톱 표(iconOnly)는 왕관 아이콘만 보인다(글 표지가 우선순위 칸을
 * 넓혀 1280px 표가 넘쳤다). 툴팁·화면 읽기 글은 같고 휴대폰 카드는 글 표지 그대로다.
 */
function QueueCriticalBadge({ item, masked, iconOnly = false }: { item: UnifiedQueueItem; masked: boolean; iconOnly?: boolean }) {
  return (
    <CriticalAssetBadge
      priority={item.priority}
      priorityBase={item.priorityBase}
      name={item.criticalAssetName}
      masked={masked}
      iconOnly={iconOnly}
    />
  );
}

function QueueMobileList({
  rows,
  listQuery,
  anchor,
  snapshot,
  highlightAfter,
  masked,
}: {
  rows: UnifiedQueueItem[];
  listQuery: string;
  anchor: string | null;
  snapshot: boolean;
  highlightAfter: string | null;
  masked: boolean;
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
              {typeof item.incidentNo === 'number' && (
                <span
                  className="shrink-0 font-mono text-xs font-semibold tabular-nums text-cyan-200"
                  aria-label={`인시던트 번호 ${item.incidentNo}`}
                  data-card-incident-no=""
                >
                  #{item.incidentNo}
                </span>
              )}
              <PriorityBadge priority={item.priority} />
              {item.assetCritical && <QueueCriticalBadge item={item} masked={masked} />}
              {isNewRow(item, highlightAfter) && <NewRowBadge />}
              <span className="shrink-0 font-mono text-sm font-semibold text-slate-100">{item.hostIp}</span>
              {item.hostName[0] !== undefined && (
                <span
                  className="min-w-0 truncate font-mono text-[11px] text-slate-400"
                  title={item.hostName.join(', ')}
                  data-card-host-name=""
                >
                  {item.hostName[0]}
                </span>
              )}
              <span className="ml-auto shrink-0 text-[11px] tabular-nums text-slate-400" title={`탐지 시각 ${formatDateTime(item.detectedAt)}`}>
                탐지 {formatRelativeTo(item.detectedAt, anchor)}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs" data-mobile-handling="">
              <span className="text-[11px] text-slate-500">담당</span>
              <AssigneeName assignee={item.assignee} className="max-w-[9rem] text-xs" />
              <MobileElapsed item={item} anchor={anchor} />
              {item.ackOverdue && <AckOverdueBadge dueAt={item.ackDueAt} detectedAt={item.detectedAt} />}
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
          {/* T45: 묶음 표지는 카드 링크 밖에 둔다(링크 안에 링크를 넣지 않는다) */}
          {typeof item.threadHeadNo === 'number' && typeof item.threadMemberCount === 'number' && (
            <div className="-mt-1 px-3 pb-2.5" data-mobile-thread="">
              <ThreadBadge item={item} />
            </div>
          )}
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

export function Pagination({
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
