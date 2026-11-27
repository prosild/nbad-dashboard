import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Activity, ArrowRight, Bell, List, RefreshCw, Server } from 'lucide-react';
import { ApiError, errorNotice, type ErrorNotice } from '../api/client';
import { dashboardApi, incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { PeriodButtons, SourceField, sourceSelectChanges, sourceSelectValue } from '../components/ConditionBar';
import { EmptyPeriodText, hasOutsideToShow, OutsidePeriodNotice } from '../components/OutsidePeriodNotice';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import { ALERTED_COUNT_TOOLTIP, CodeLabel, DetectionModelName, IncidentStatusBadge, PriorityBadge, SocBadge } from '../components/StatusBadge';
import { PanelHeader } from '../components/dashboard/PanelHeader';
import { SourceStatusList } from '../components/dashboard/SourceStatus';
import { ThreatPanels } from '../components/dashboard/ThreatPanels';
import { TrendChart } from '../components/dashboard/TrendChart';
import type { DashboardOverviewResponse, UnifiedQueueItem, UnifiedQueueResponse } from '../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime, formatNumber, formatRelativeTo } from '../utils/format';
import { incidentPath } from '../utils/incidentLink';
import { captureInfo, captureShortNames, shortNameOf } from '../utils/labels';
import type { PeriodRange } from '../utils/periodRange';
import {
  customUrlChanges,
  parsePeriodSelection,
  parseSource,
  periodScopeText as selectionScopeText,
  presetUrlChanges,
  setPeriodParams,
  type Period,
  type PeriodSelection,
  type PresetPeriod,
} from '../utils/triage';

/** 현황판 자동 갱신 주기(T24): 60초. 화면이 숨겨지면 멈추고 다시 보이면 곧바로 한 번 부른다. 고정 스냅샷이면 끈다. */
export const DASHBOARD_REFRESH_MS = 60_000;
/** 현황판 기본 기간 */
export const DASHBOARD_DEFAULT_PERIOD: PresetPeriod = '24h';
/** 최근 인시던트 줄 수. 큐 API 쪽 크기는 25·50·100만 받으므로 25건을 받아 앞 8건을 보인다. */
export const RECENT_ROWS = 8;
const RECENT_PAGE_SIZE = '25';

interface Condition {
  period: Period;
  /** T34 지정 기간(period=custom일 때만) */
  range: PeriodRange | null;
  source: string | null;
  captureId: string | null;
}

/** 조건 → 인시던트 큐 쿼리(period=P[&start&end]&source=S 또는 captureId) */
export function conditionQuery(c: Condition, extra: Record<string, string> = {}): string {
  const q = setPeriodParams(new URLSearchParams(), { period: c.period, range: c.range });
  if (c.captureId) q.set('captureId', c.captureId);
  else if (c.source) q.set('source', c.source);
  for (const [k, v] of Object.entries(extra)) q.set(k, v);
  return q.toString();
}

/** 기간 범위 글: "최근 24시간" / "전체 기간" / 지정 기간이면 "11-19 09:00 – 11-19 12:00" */
export function periodScopeText(period: Period | PeriodSelection, anchor?: string | null): string {
  const sel: PeriodSelection = typeof period === 'string' ? { period, range: null } : period;
  return selectionScopeText(sel, anchor);
}

/** 기간 전체 조건(에스컬레이션 대기처럼 기간과 상관없는 값) */
function allPeriod(c: Condition): Condition {
  return { ...c, period: 'all', range: null };
}

/**
 * 주기 갱신(T24): enabled일 때 intervalMs마다 부른다. 화면이 숨겨지면 멈추고, 다시 보이면 곧바로 한 번 부른 뒤 다시 센다.
 */
export function useAutoRefresh(enabled: boolean, refresh: () => void, intervalMs: number) {
  const fn = useRef(refresh);
  fn.current = refresh;
  useEffect(() => {
    if (!enabled) return undefined;
    let timer: ReturnType<typeof setInterval> | undefined;
    const stop = () => {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    };
    const start = () => {
      stop();
      timer = setInterval(() => fn.current(), intervalMs);
    };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        stop();
      } else {
        fn.current();
        start();
      }
    };
    if (document.visibilityState !== 'hidden') start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, intervalMs]);
}

/** 한 번의 불러오기에서 overview·큐(기간 조건)가 모두 성공한 값. 어느 조건(condKey)으로 받았는지 함께 기억한다(T41). */
interface LoadedData {
  condKey: string;
  overview: DashboardOverviewResponse;
  queue: UnifiedQueueResponse;
  /** 마지막으로 성공한 시각 */
  loadedAt: string;
}

/**
 * T41: 갱신 실패 뒤에도 60초 자동 갱신을 이어 가는 실패인가. 429·5xx·네트워크 오류(응답 없음)만 이어 간다.
 * 401·403과 그 밖의 4xx는 멈춘다(로그아웃·권한 없음 상태에서 거부 요청과 감사 기록을 되풀이하지 않는다).
 */
export function keepsAutoRefresh(err: unknown): boolean {
  if (err instanceof ApiError) return err.rateLimited || err.status >= 500;
  return true;
}

export function DashboardPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const sel = parsePeriodSelection(searchParams, DASHBOARD_DEFAULT_PERIOD);
  const cond: Condition = {
    period: sel.period,
    range: sel.range,
    source: parseSource(searchParams.get('source')),
    captureId: searchParams.get('captureId') || null,
  };
  const condKey = conditionQuery(cond);
  const [loaded, setLoaded] = useState<LoadedData | null>(null);
  /** 에스컬레이션 대기(현재, 기간 무관). 불러오지 못하면 null. 셋째 요청이라 따로 다룬다 */
  const [pending, setPending] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  /** 마지막 불러오기의 실패와 그 조건. 다음 성공 때 지운다 */
  const [failure, setFailure] = useState<{ condKey: string; notice: ErrorNotice } | null>(null);
  const [pendingError, setPendingError] = useState(false);
  /** 마지막으로 성공한 응답이 고정 스냅샷이었나(조건과 상관없이). null = 아직 한 번도 성공하지 못해 모른다 */
  const [lastSnapshot, setLastSnapshot] = useState<boolean | null>(null);
  /** 401·403 등 이어 가지 않는 실패로 자동 갱신을 멈췄나. 다음 성공 때 풀린다 */
  const [refreshHalted, setRefreshHalted] = useState(false);
  /** 조건 줄의 수집원 목록(마지막 성공 값, 조건과 상관없이) */
  const [barQueue, setBarQueue] = useState<UnifiedQueueResponse | null>(null);
  const seq = useRef(0);

  const load = useCallback(async () => {
    const my = ++seq.current;
    const c = Object.fromEntries(new URLSearchParams(condKey)) as Record<string, string>;
    const params = { period: c.period, start: c.start, end: c.end, source: c.source, captureId: c.captureId };
    setLoading(true);
    // 현황판 호출은 셋: overview(P,S), 큐(P,S, 탐지 시각 최근순, summary 포함), 큐(전체 기간, S, 에스컬레이션 대기용)
    const [ov, queue, pendingQueue] = await Promise.allSettled([
      dashboardApi.overview(params),
      incidentsApi.queue({ ...params, sort: 'detected', dir: 'desc', size: RECENT_PAGE_SIZE }),
      incidentsApi.queue({ ...params, period: 'all', start: undefined, end: undefined, size: RECENT_PAGE_SIZE }),
    ]);
    if (my !== seq.current) return;
    setPendingError(pendingQueue.status === 'rejected');
    setPending(pendingQueue.status === 'fulfilled' ? pendingQueue.value.summary.reviewPending : null);
    if (ov.status === 'fulfilled' && queue.status === 'fulfilled') {
      // T41: 한 번의 불러오기는 통째로 반영한다(두 요청 모두 성공했을 때만 값을 바꾼다)
      setLoaded({ condKey, overview: ov.value, queue: queue.value, loadedAt: new Date().toISOString() });
      setBarQueue(queue.value);
      setLastSnapshot(Boolean(ov.value.snapshot ?? queue.value.snapshot));
      setFailure(null);
      setRefreshHalted(false);
    } else {
      const reasons = [ov, queue].flatMap((r) => (r.status === 'rejected' ? [r.reason as unknown] : []));
      setFailure({ condKey, notice: errorNotice(reasons[0], '관제 현황을 불러오지 못했습니다.') });
      setRefreshHalted(!reasons.every(keepsAutoRefresh));
      // 같은 조건으로 성공한 값만 남긴다(다른 조건의 값을 지금 조건의 값처럼 보이지 않는다)
      setLoaded((prev) => (prev && prev.condKey === condKey ? prev : null));
    }
    setLoading(false);
  }, [condKey]);

  useEffect(() => {
    void load();
  }, [load]);

  // T41: 스냅샷 여부는 마지막으로 성공한 응답의 값(조건과 상관없이). 모르는 동안(한 번도 성공 못 함)은 켜 둔다
  const snapshot = lastSnapshot === true;
  // T34: 지정 기간은 지난 구간을 조사하는 화면이라 목록이 움직이지 않게 자동 갱신을 끈다(수동 새로 고침은 그대로)
  const custom = cond.period === 'custom';
  const autoRefresh = !snapshot && !custom && !refreshHalted;
  useAutoRefresh(autoRefresh, () => void load(), DASHBOARD_REFRESH_MS);

  function updateParams(changes: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSearchParams(next);
  }

  // 지금 조건으로 받은 값만 그린다(조건을 바꾼 직후 불러오는 동안에도 옛 조건의 값을 지금 조건의 값처럼 보이지 않는다)
  const current = loaded !== null && loaded.condKey === condKey ? loaded : null;
  const overview = current?.overview ?? null;
  const queue = current?.queue ?? null;
  const failed = failure !== null && failure.condKey === condKey ? failure.notice : null;
  const shortNames = useMemo(() => captureShortNames((queue?.sources ?? []).map((s) => s.captureId)), [queue]);
  /** 같은 조건으로 성공한 값을 남긴 채 실패한 상태(최신이 아니다) */
  const stale = failed !== null && current !== null;

  return (
    <AppShell title="현황판">
      <div className="space-y-4">
        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <PeriodButtons
              value={cond.period}
              range={cond.range}
              onChange={(p) => updateParams(presetUrlChanges(p, DASHBOARD_DEFAULT_PERIOD))}
              onApplyRange={(r) => updateParams(customUrlChanges(r))}
              current={{ periodStart: overview?.periodStart, periodEnd: overview?.periodEnd, anchor: overview?.anchor }}
            />
            <SourceField
              id="dashboard-source"
              sources={barQueue?.sources ?? []}
              value={sourceSelectValue(cond.source, cond.captureId)}
              onChange={(v) => updateParams(sourceSelectChanges(v))}
              anchor={barQueue?.anchor ?? null}
              snapshot={snapshot}
            />
            <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
              <AnchorText overview={overview} />
              {custom && !snapshot && (
                <span data-testid="auto-refresh-off" title="기간을 지정하면 목록이 움직이지 않게 60초 자동 갱신을 멈춥니다">
                  자동 갱신 꺼짐(기간 지정)
                </span>
              )}
              <span>
                불러온 시각 <span className="tabular-nums text-slate-300">{formatDateTime(current?.loadedAt ?? null)}</span>
              </span>
              <button type="button" onClick={() => void load()} disabled={loading} className="soc-btn-secondary py-1 text-xs">
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
                새로 고침
              </button>
            </div>
          </div>
        </section>

        {failed && stale && (
          <StaleNotice
            notice={failed}
            loadedAt={current?.loadedAt ?? null}
            autoRetrySeconds={autoRefresh ? DASHBOARD_REFRESH_MS / 1000 : null}
            loading={loading}
            onRetry={() => void load()}
          />
        )}
        {failed && !stale && (
          <ErrorAlert message={failed.message} rateLimited={failed.rateLimited} onRetry={() => void load()} />
        )}

        {loading && !overview && !queue && !failed ? (
          <LoadingPanel label="관제 현황을 불러오는 중..." />
        ) : !overview || !queue ? null : (
          <>
            <OutsidePeriodNotice queue={queue} onAllPeriod={() => updateParams(presetUrlChanges('all', DASHBOARD_DEFAULT_PERIOD))} />
            <KpiRow cond={cond} queue={queue} pending={pending} pendingError={pendingError} />

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <TrendPanel
                overview={overview}
                queue={queue}
                cond={cond}
                sourceValue={sourceSelectValue(cond.source, cond.captureId)}
                onNavigate={navigate}
                onAllPeriod={() => updateParams(presetUrlChanges('all', DASHBOARD_DEFAULT_PERIOD))}
                className="xl:col-span-3"
              />
              <RecentPanel cond={cond} queue={queue} shortNames={shortNames} className="xl:col-span-2" />
            </div>

            {/* T45b: 같은 overview 응답의 위협 가시성 세 패널. 링크는 지금 조건을 유지한다(알림 묶음만 묶음 전체) */}
            <ThreatPanels overview={overview} listQuery={(extra) => conditionQuery(cond, extra)} />

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <section className="soc-card min-w-0 space-y-3 p-4 xl:col-span-3" aria-label="수집원 상태">
                <PanelHeader
                  icon={Server}
                  title="수집원 상태"
                  note={`${periodScopeText(cond, overview.anchor)} 인시던트 수${overview.snapshot ? ' · 기준 시각까지' : ''}`}
                />
                <SourceStatusList
                  overview={overview}
                  shortNames={shortNames}
                  periodQuery={setPeriodParams(new URLSearchParams(), cond).toString()}
                  allPeriod={queue}
                />
              </section>
              <AlertingPanel overview={overview} cond={cond} shortNames={shortNames} className="xl:col-span-2" />
            </div>

            <p className="text-right text-xs text-slate-400">
              <Link to={`/operations?${conditionQuery(cond)}`} className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
                누적 분석가 판정·모델별 정탐률은 운영 현황에서 보기
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </p>
          </>
        )}
      </div>
    </AppShell>
  );
}

/** 기준 시각: now면 "기준 시각: 현재", 고정 스냅샷이면 맨 위 띠와 같은 값 */
function AnchorText({ overview }: { overview: DashboardOverviewResponse | null }) {
  if (!overview) return null;
  if (!overview.snapshot) {
    return (
      <span title="기간은 지금 시각을 끝으로 계산합니다" data-testid="dashboard-anchor">
        기준 시각: 현재
      </span>
    );
  }
  return (
    <span title="고정 스냅샷: 이 기준 시각을 끝으로 기간을 계산합니다" data-testid="dashboard-anchor">
      기준 시각{' '}
      <span className="font-semibold tabular-nums text-slate-100">{formatDateTime(overview.anchor)}</span> {DISPLAY_TIME_ZONE_LABEL}
    </span>
  );
}

/* ───────────────────────── 핵심 지표 ───────────────────────── */

function KpiCard({
  to,
  label,
  value,
  scope,
  tone = 'default',
  title,
  sub,
}: {
  to: string;
  label: string;
  value: string;
  scope: string;
  tone?: 'default' | 'notice' | 'attention' | 'danger';
  title?: string;
  sub?: React.ReactNode;
}) {
  const valueTone =
    tone === 'attention' ? 'text-amber-200' : tone === 'notice' ? 'text-cyan-200' : tone === 'danger' ? 'text-rose-200' : 'text-slate-50';
  return (
    <Link
      to={to}
      title={title}
      className="soc-card block min-w-0 px-4 py-3 transition hover:border-slate-600 hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-2 text-xs text-slate-400">
        <span>{label}</span>
        <span className="text-[11px] text-slate-500" data-kpi-scope="">
          {scope}
        </span>
      </div>
      <div className={`mt-1 text-2xl font-bold tabular-nums ${valueTone}`} data-kpi-value="">
        {value}
      </div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-400">{sub}</div>}
    </Link>
  );
}

function KpiRow({
  cond,
  queue,
  pending,
  pendingError,
}: {
  cond: Condition;
  queue: UnifiedQueueResponse;
  pending: number | null;
  pendingError: boolean;
}) {
  const s = queue.summary;
  const scope = periodScopeText(cond, queue.anchor);
  return (
    <section aria-label="핵심 지표" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <KpiCard
        to={`/incidents?${conditionQuery(cond)}`}
        label="탐지된 인시던트"
        value={formatNumber(s.total)}
        scope={scope}
        title={`${scope} 동안 탐지된 인시던트 수입니다(탐지 시각 기준). 누르면 같은 조건의 인시던트 목록으로 갑니다.`}
      />
      <KpiCard
        to={`/incidents?${conditionQuery(cond, { priority: 'high' })}`}
        label="High(미종결)"
        value={formatNumber(s.high)}
        scope={scope}
        tone={s.high > 0 ? 'danger' : 'default'}
        title="자동 분류 우선순위 High인 인시던트 수입니다(종결은 우선순위가 없어 빠집니다)."
      />
      <KpiCard
        to={`/incidents?${conditionQuery(cond, { alerted: 'true' })}`}
        label="경보 발송"
        value={formatNumber(s.alerted)}
        scope={scope}
        tone={s.alerted > 0 ? 'notice' : 'default'}
        title={ALERTED_COUNT_TOOLTIP}
      />
      <KpiCard
        to={`/incidents?${conditionQuery(allPeriod(cond), { reviewPending: 'true' })}`}
        label="에스컬레이션 대기"
        value={pending === null ? '-' : formatNumber(pending)}
        scope="현재"
        tone={pending !== null && pending > 0 ? 'attention' : 'default'}
        sub={pendingError ? '불러오지 못했습니다' : undefined}
        title="분석가 검토를 기다리는 인시던트 수입니다(기간 무관, 최신 분석 결과 기준). 에스컬레이션 화면에는 최신 분석 결과에 없는 인시던트의 요청(그 인시던트의 가장 최근 요청)도 보이지만, 이 수는 최신 분석 결과에 있는 인시던트만 셉니다."
      />
    </section>
  );
}

/* ───────────────────────── 탐지 추이 ───────────────────────── */

function TrendPanel({
  overview,
  queue,
  cond,
  sourceValue,
  onAllPeriod,
  onNavigate,
  className = '',
}: {
  overview: DashboardOverviewResponse;
  queue: UnifiedQueueResponse;
  cond: Condition;
  sourceValue: string;
  onAllPeriod: () => void;
  onNavigate: (href: string) => void;
  className?: string;
}) {
  const trend = overview.trend;
  const bucketed = trend.buckets.reduce((sum, b) => sum + b.total, 0);
  const unbucketed = trend.unbucketed.noDetectedAt + trend.unbucketed.afterAnchor;
  const unitText: Record<string, string> = { '5m': '5분', '1h': '1시간', '6h': '6시간', '1d': '1일', '1w': '1주' };
  return (
    <section className={`soc-card min-w-0 space-y-3 p-4 ${className}`} aria-label="탐지 추이">
      <PanelHeader
        icon={Activity}
        title="탐지 추이"
        note={`${periodScopeText(cond, overview.anchor)} · 구간 ${unitText[trend.bucket] ?? trend.bucket} · ${DISPLAY_TIME_ZONE_LABEL}`}
      />
      {bucketed === 0 && unbucketed === 0 ? (
        hasOutsideToShow(queue) ? (
          <div className="space-y-2 px-2 py-8 text-center text-sm text-slate-300" data-empty="period">
            <EmptyPeriodText queue={queue} sourceValue={sourceValue} />
            <button type="button" onClick={onAllPeriod} className="soc-btn-secondary px-3 py-1.5 text-xs">
              기간: 전체로 보기
            </button>
          </div>
        ) : (
          <p className="px-2 py-8 text-center text-sm text-slate-400" data-empty="none">
            표시할 인시던트가 없습니다.
          </p>
        )
      ) : (
        <>
          {trend.buckets.length > 0 && (
            <TrendChart
              trend={trend}
              anchor={overview.anchor}
              periodStart={overview.periodStart ?? null}
              periodEnd={overview.periodEnd ?? null}
              // T34: 막대를 누르면 그 구간(기간 경계·기준 시각으로 자름)의 큐로 간다. 수집원 조건은 그대로다
              bucketHref={(r) => `/incidents?${conditionQuery({ ...cond, period: 'custom', range: r })}`}
              onNavigate={onNavigate}
            />
          )}
          {unbucketed > 0 && (
            <p className="text-[11px] text-slate-400" data-unbucketed="">
              추이에 넣지 않은 인시던트: 탐지 시각 없음 {formatNumber(trend.unbucketed.noDetectedAt)}건 · 기준 시각 뒤 탐지{' '}
              {formatNumber(trend.unbucketed.afterAnchor)}건(목록 수에는 들어 있습니다)
            </p>
          )}
        </>
      )}
    </section>
  );
}

/* ───────────────────────── 최근 인시던트 ───────────────────────── */

function recentDetailUrl(item: UnifiedQueueItem, listQuery: string): string {
  // T27: 번호가 있으면 고정 주소, 없으면 옛 주소
  return incidentPath(item, new URLSearchParams({ from: listQuery })) ?? '/incidents';
}

function RecentPanel({
  cond,
  queue,
  shortNames,
  className = '',
}: {
  cond: Condition;
  queue: UnifiedQueueResponse;
  shortNames: Map<string, string>;
  className?: string;
}) {
  const listQuery = conditionQuery(cond, { sort: 'detected', dir: 'desc' });
  const rows = queue.items.slice(0, RECENT_ROWS);
  return (
    <section className={`soc-card min-w-0 space-y-3 p-4 ${className}`} aria-label="최근 인시던트">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <List className="h-4 w-4 text-slate-400" />
          최근 인시던트
        </h2>
        <Link to={`/incidents?${listQuery}`} className="text-xs text-cyan-300 hover:text-cyan-200">
          모두 보기
        </Link>
      </div>
      {rows.length === 0 ? (
        <p className="px-2 py-6 text-center text-xs text-slate-400">{periodScopeText(cond, queue.anchor)} 동안 탐지된 인시던트가 없습니다.</p>
      ) : (
        <ul className="divide-y divide-slate-800/80" aria-label="최근 인시던트 목록">
          {rows.map((item) => {
            const info = captureInfo(item.captureId);
            return (
              <li key={`${item.jobId}-${item.queueRank}`}>
                <Link
                  to={recentDetailUrl(item, listQuery)}
                  className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 rounded px-1 py-1.5 text-xs transition hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
                  data-recent-row=""
                >
                  <PriorityBadge priority={item.priority} />
                  <span className="min-w-0 truncate font-mono text-slate-100" title={item.hostName?.join(', ') || undefined}>
                    {item.hostIp}
                  </span>
                  <span className="text-slate-400" title={`${info.text} · 캡처 ID: ${item.captureId}`}>
                    <span aria-hidden="true">{shortNameOf(shortNames, item.captureId)}</span>
                    <span className="sr-only">{`수집원: ${info.text} · 캡처 ID: ${item.captureId}`}</span>
                  </span>
                  {/* T25(T24 후속): 640px 미만에서도 탐지 모델 이름을 보인다(줄은 flex-wrap으로 넘긴다) */}
                  <DetectionModelName id={item.zeekadPickedBy} className="min-w-0 break-words text-slate-300" />
                  <span className="ml-auto flex shrink-0 items-center gap-2">
                    <span className="whitespace-nowrap tabular-nums text-slate-400" title={`탐지 시각 ${formatDateTime(item.detectedAt)}`}>
                      {formatRelativeTo(item.detectedAt, queue.anchor)}
                    </span>
                    <IncidentStatusBadge status={item.zeekadStatus} />
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/* ───────────────────────── Slack 일일 요약 상태 ───────────────────────── */

function AlertingPanel({
  overview,
  cond,
  shortNames,
  className = '',
}: {
  overview: DashboardOverviewResponse;
  cond: Condition;
  shortNames: Map<string, string>;
  className?: string;
}) {
  const a = overview.alerting;
  const latestAt = a.latestDeliveredAt ?? a.latestCreatedAt;
  return (
    <section className={`soc-card min-w-0 space-y-3 p-4 ${className}`} aria-label="Slack 일일 요약 상태">
      <PanelHeader icon={Bell} title="Slack 일일 요약 상태" />
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
        <dt className="text-slate-400">발송 방식</dt>
        <dd className="flex flex-wrap items-center gap-1.5">
          {a.latestDeliveryMode ? (
            a.latestDryRun ? (
              <SocBadge tone="muted" title="Slack에 실제로 보내지 않고 기록만 남겼습니다">
                Dry-run
              </SocBadge>
            ) : (
              <CodeLabel dict="slackDeliveryMode" value={a.latestDeliveryMode} className="text-slate-100" />
            )
          ) : (
            <span className="text-slate-500">-</span>
          )}
        </dd>
        <dt className="text-slate-400">최근 일일 요약</dt>
        <dd className="tabular-nums text-slate-100">
          {latestAt ? formatDateTime(latestAt) : '기록 없음'}
          {/* T25(T24 후속): 보이는 글은 짧은 수집원 이름, 전체 이름은 툴팁·판독기 글자 */}
          {a.latestCaptureId && (
            <span
              className="ml-2 text-slate-400"
              title={`${captureInfo(a.latestCaptureId).text} · 캡처 ID: ${a.latestCaptureId}`}
              data-alerting-capture=""
            >
              <span aria-hidden="true">{shortNameOf(shortNames, a.latestCaptureId)}</span>
              <span className="sr-only">{`수집원: ${captureInfo(a.latestCaptureId).text} · 캡처 ID: ${a.latestCaptureId}`}</span>
            </span>
          )}
        </dd>
        <dt className="text-slate-400">{periodScopeText(cond, overview.anchor)} 일일 요약</dt>
        <dd className="tabular-nums text-slate-100">{formatNumber(a.summariesInPeriod)}건</dd>
      </dl>
    </section>
  );
}
