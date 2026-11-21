import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, ArrowRight, Bell, List, RefreshCw, Server } from 'lucide-react';
import { ApiError } from '../api/client';
import { dashboardApi, incidentsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { PeriodButtons, SourceField, sourceSelectChanges, sourceSelectValue } from '../components/ConditionBar';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { CodeLabel, DetectionModelName, IncidentStatusBadge, PriorityBadge, SocBadge } from '../components/StatusBadge';
import { SourceStatusList } from '../components/dashboard/SourceStatus';
import { TrendChart } from '../components/dashboard/TrendChart';
import type { DashboardOverviewResponse, UnifiedQueueItem, UnifiedQueueResponse } from '../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime, formatNumber, formatRelativeTo } from '../utils/format';
import { captureInfo, captureShortNames, shortNameOf } from '../utils/labels';
import { parsePeriod, parseSource, periodLabel, type Period } from '../utils/triage';

/** 현황판 자동 갱신 주기(T24): 60초. 화면이 숨겨지면 멈추고 다시 보이면 곧바로 한 번 부른다. 고정 스냅샷이면 끈다. */
export const DASHBOARD_REFRESH_MS = 60_000;
/** 현황판 기본 기간 */
export const DASHBOARD_DEFAULT_PERIOD: Period = '24h';
/** 최근 인시던트 줄 수. 큐 API 쪽 크기는 25·50·100만 받으므로 25건을 받아 앞 8건을 보인다. */
export const RECENT_ROWS = 8;
const RECENT_PAGE_SIZE = '25';

interface Condition {
  period: Period;
  source: string | null;
  captureId: string | null;
}

/** 조건 → 인시던트 큐 쿼리(period=P&source=S 또는 captureId) */
export function conditionQuery(c: Condition, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams();
  q.set('period', c.period);
  if (c.captureId) q.set('captureId', c.captureId);
  else if (c.source) q.set('source', c.source);
  for (const [k, v] of Object.entries(extra)) q.set(k, v);
  return q.toString();
}

/** 기간 범위 글: "최근 24시간" / "전체 기간" */
export function periodScopeText(period: Period): string {
  return period === 'all' ? '전체 기간' : `최근 ${periodLabel(period)}`;
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

interface DashboardData {
  overview: DashboardOverviewResponse | null;
  queue: UnifiedQueueResponse | null;
  /** 에스컬레이션 대기(현재, 기간 무관). 불러오지 못하면 null */
  pending: number | null;
  loadedAt: string | null;
}

export function DashboardPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const cond: Condition = {
    period: searchParams.get('period') ? parsePeriod(searchParams.get('period')) : DASHBOARD_DEFAULT_PERIOD,
    source: parseSource(searchParams.get('source')),
    captureId: searchParams.get('captureId') || null,
  };
  const condKey = conditionQuery(cond);
  const [data, setData] = useState<DashboardData>({ overview: null, queue: null, pending: null, loadedAt: null });
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [pendingError, setPendingError] = useState(false);
  const seq = useRef(0);

  const load = useCallback(async () => {
    const my = ++seq.current;
    const c = Object.fromEntries(new URLSearchParams(condKey)) as Record<string, string>;
    const params = { period: c.period, source: c.source, captureId: c.captureId };
    setLoading(true);
    setErrorMsg(null);
    // 현황판 호출은 셋: overview(P,S), 큐(P,S, 탐지 시각 최근순, summary 포함), 큐(전체 기간, S, 에스컬레이션 대기용)
    const [ov, queue, pendingQueue] = await Promise.allSettled([
      dashboardApi.overview(params),
      incidentsApi.queue({ ...params, sort: 'detected', dir: 'desc', size: RECENT_PAGE_SIZE }),
      incidentsApi.queue({ ...params, period: 'all', size: RECENT_PAGE_SIZE }),
    ]);
    if (my !== seq.current) return;
    const failed = [ov, queue].find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined;
    if (failed) {
      setErrorMsg(failed.reason instanceof ApiError ? failed.reason.message : '관제 현황을 불러오지 못했습니다.');
    }
    setPendingError(pendingQueue.status === 'rejected');
    setData((prev) => ({
      overview: ov.status === 'fulfilled' ? ov.value : failed ? null : prev.overview,
      queue: queue.status === 'fulfilled' ? queue.value : failed ? null : prev.queue,
      pending: pendingQueue.status === 'fulfilled' ? pendingQueue.value.summary.reviewPending : null,
      loadedAt: new Date().toISOString(),
    }));
    setLoading(false);
  }, [condKey]);

  useEffect(() => {
    void load();
  }, [load]);

  const snapshot = Boolean(data.overview?.snapshot ?? data.queue?.snapshot);
  useAutoRefresh(Boolean(data.overview) && !snapshot, () => void load(), DASHBOARD_REFRESH_MS);

  function updateParams(changes: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSearchParams(next);
  }

  const shortNames = useMemo(
    () => captureShortNames((data.queue?.sources ?? []).map((s) => s.captureId)),
    [data.queue],
  );
  const overview = data.overview;
  const queue = data.queue;

  return (
    <AppShell title="현황판" subtitle="기간 안에 무엇이 탐지됐고 수집원이 정상인지 한 화면에서 봅니다">
      <div className="space-y-4">
        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <PeriodButtons value={cond.period} onChange={(p) => updateParams({ period: p === DASHBOARD_DEFAULT_PERIOD ? null : p })} />
            <SourceField
              id="dashboard-source"
              sources={queue?.sources ?? []}
              value={sourceSelectValue(cond.source, cond.captureId)}
              onChange={(v) => updateParams(sourceSelectChanges(v))}
            />
            <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
              <AnchorText overview={overview} />
              <span>
                불러온 시각 <span className="tabular-nums text-slate-300">{formatDateTime(data.loadedAt)}</span>
              </span>
              <button type="button" onClick={() => void load()} disabled={loading} className="soc-btn-secondary py-1 text-xs">
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
                새로 고침
              </button>
            </div>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void load()} />}

        {loading && !overview && !queue ? (
          <LoadingPanel label="관제 현황을 불러오는 중..." />
        ) : !overview || !queue ? null : (
          <>
            <KpiRow cond={cond} queue={queue} pending={data.pending} pendingError={pendingError} />

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <TrendPanel
                overview={overview}
                queue={queue}
                cond={cond}
                onAllPeriod={() => updateParams({ period: 'all' })}
                className="xl:col-span-3"
              />
              <RecentPanel cond={cond} queue={queue} shortNames={shortNames} className="xl:col-span-2" />
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <section className="soc-card min-w-0 space-y-3 p-4 xl:col-span-3" aria-label="수집원 상태">
                <PanelHeader
                  icon={Server}
                  title="수집원 상태"
                  note={`${periodScopeText(cond.period)} 인시던트 수${overview.snapshot ? ' · 기준 시각 기준' : ''}`}
                />
                <SourceStatusList overview={overview} shortNames={shortNames} period={cond.period} />
              </section>
              <AlertingPanel overview={overview} period={cond.period} className="xl:col-span-2" />
            </div>

            <p className="text-right text-xs text-slate-400">
              <Link to={`/operations?${conditionQuery({ ...cond, period: cond.period })}`} className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
                누적 판정·탐지 모델 성능은 운영 현황
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </p>
          </>
        )}
      </div>
    </AppShell>
  );
}

/** 기준 시각: now면 "기준 시각 = 현재", 고정 스냅샷이면 맨 위 띠와 같은 값 */
function AnchorText({ overview }: { overview: DashboardOverviewResponse | null }) {
  if (!overview) return null;
  if (!overview.snapshot) {
    return (
      <span title="기간은 지금 시각에서 거꾸로 셉니다" data-testid="dashboard-anchor">
        기준 시각 = 현재
      </span>
    );
  }
  return (
    <span title="고정 스냅샷: 기간을 이 기준 시각에서 거꾸로 셉니다" data-testid="dashboard-anchor">
      기준 시각{' '}
      <span className="font-semibold tabular-nums text-slate-100">{formatDateTime(overview.anchor)}</span> {DISPLAY_TIME_ZONE_LABEL}
    </span>
  );
}

function PanelHeader({ icon: Icon, title, note }: { icon: React.ComponentType<{ className?: string }>; title: string; note?: string }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
        <Icon className="h-4 w-4 text-slate-400" />
        {title}
      </h2>
      {note && <span className="text-[11px] text-slate-400">{note}</span>}
    </div>
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
  const scope = periodScopeText(cond.period);
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
        title="상태 알림이 아닌 Slack 발송 기록이 있는 인시던트 수입니다."
      />
      <KpiCard
        to={`/incidents?${conditionQuery({ ...cond, period: 'all' }, { reviewPending: 'true' })}`}
        label="에스컬레이션 대기"
        value={pending === null ? '-' : formatNumber(pending)}
        scope="현재"
        tone={pending !== null && pending > 0 ? 'attention' : 'default'}
        sub={pendingError ? '불러오지 못했습니다' : undefined}
        title="분석가 검토를 기다리는 인시던트 수입니다(기간 무관, 최신 분석 결과 기준). 에스컬레이션 화면의 대기 목록과 정의가 조금 다를 수 있습니다."
      />
    </section>
  );
}

/* ───────────────────────── 탐지 추이 ───────────────────────── */

function TrendPanel({
  overview,
  queue,
  cond,
  onAllPeriod,
  className = '',
}: {
  overview: DashboardOverviewResponse;
  queue: UnifiedQueueResponse;
  cond: Condition;
  onAllPeriod: () => void;
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
        note={`${periodScopeText(cond.period)} · 구간 ${unitText[trend.bucket] ?? trend.bucket} · ${DISPLAY_TIME_ZONE_LABEL}`}
      />
      {bucketed === 0 && unbucketed === 0 ? (
        queue.newestOutsidePeriod ? (
          <div className="space-y-2 px-2 py-8 text-center text-sm text-slate-300" data-empty="period">
            <p>
              이 기간에 탐지된 인시던트가 없습니다. 가장 최근 탐지:{' '}
              <span className="tabular-nums text-slate-100">{formatDateTime(queue.newestOutsidePeriod)}</span>
            </p>
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
          {trend.buckets.length > 0 && <TrendChart trend={trend} />}
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
  return `/incidents/${item.jobId}/rank/${item.queueRank}?${new URLSearchParams({ from: listQuery }).toString()}`;
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
        <p className="px-2 py-6 text-center text-xs text-slate-400">{periodScopeText(cond.period)} 동안 탐지된 인시던트가 없습니다.</p>
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
                  <DetectionModelName id={item.zeekadPickedBy} className="hidden text-slate-300 sm:inline" />
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

/* ───────────────────────── 경보 발송 상태 ───────────────────────── */

function AlertingPanel({ overview, period, className = '' }: { overview: DashboardOverviewResponse; period: Period; className?: string }) {
  const a = overview.alerting;
  const latestAt = a.latestDeliveredAt ?? a.latestCreatedAt;
  return (
    <section className={`soc-card min-w-0 space-y-3 p-4 ${className}`} aria-label="경보 발송 상태">
      <PanelHeader icon={Bell} title="경보 발송 상태" note="Slack 일일 요약" />
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
          {a.latestCaptureId && <span className="ml-2 text-slate-400">{captureInfo(a.latestCaptureId).text}</span>}
        </dd>
        <dt className="text-slate-400">{periodScopeText(period)} 일일 요약</dt>
        <dd className="tabular-nums text-slate-100">{formatNumber(a.summariesInPeriod)}건</dd>
      </dl>
    </section>
  );
}
