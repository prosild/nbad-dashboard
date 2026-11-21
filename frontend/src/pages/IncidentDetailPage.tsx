import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, ChevronLeft, ChevronRight } from 'lucide-react';
import { ApiError } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { ActionPanel } from '../components/incident/ActionPanel';
import { DetailHeader } from '../components/incident/DetailHeader';
import { EvidenceSection } from '../components/incident/EvidenceSection';
import { buildTimeline, HistoryTimeline } from '../components/incident/HistoryTimeline';
import { ReportSection } from '../components/incident/ReportSection';
import { SendDecisionSection } from '../components/incident/SendDecisionSection';
import { SlackThreadsSection } from '../components/incident/SlackThreadsSection';
import { SummaryTab } from '../components/incident/SummaryTab';
import type { IncidentDetailApiResponse, IncidentQueueItem } from '../types/api';
import {
  findNeighbors,
  orderQueue,
  parseQueueView,
  SERVER_FILTER_KEYS,
  sortIncidents,
} from '../utils/triage';

/** 상세 탭. URL `tab=`에 남긴다(요약은 기본이라 남기지 않는다). */
export const DETAIL_TABS = [
  { key: 'summary', label: '요약' },
  { key: 'evidence', label: '증적' },
  { key: 'report', label: 'AI 리포트' },
  { key: 'decision', label: '경보 판단' },
  { key: 'slack', label: 'Slack' },
  { key: 'history', label: '이력' },
] as const;

export type DetailTab = (typeof DETAIL_TABS)[number]['key'];

function isDetailTab(value: string | null): value is DetailTab {
  return DETAIL_TABS.some((t) => t.key === value);
}

interface NavState {
  /** 목록 쿼리로 만든 순서면 'list', 쿼리가 없어 파이프라인 순위 순이면 'pipeline' */
  basis: 'list' | 'pipeline';
  ordered: IncidentQueueItem[];
}

/**
 * 이전·다음 순서(M1). 목록이 넘긴 `from=` 쿼리로 `GET /api/incidents`를 한 번 불러 목록과 같은 함수(orderQueue)로 순서를 만든다.
 * 쿼리가 없으면 같은 캡처·탐지 작업의 목록을 파이프라인 순위 순으로 쓴다.
 */
function useNeighborOrder(fromQuery: string | null, captureId: string | null, jobId: number | null) {
  const [nav, setNav] = useState<NavState | null>(null);
  const key = fromQuery !== null ? `from:${fromQuery}` : captureId ? `job:${captureId}|${jobId}` : null;
  // 같은 목록 안에서 이전·다음으로 옮겨 가도 다시 부르지 않도록 key가 바뀔 때만 부른다.
  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    setNav(null);
    void (async () => {
      try {
        if (fromQuery !== null) {
          const params = new URLSearchParams(fromQuery);
          const filters: Record<string, string | undefined> = {
            captureId: params.get('captureId') || undefined,
            jobId: params.get('jobId') || undefined,
          };
          for (const k of SERVER_FILTER_KEYS) filters[k] = params.get(k) || undefined;
          const res = await incidentsApi.list(filters);
          if (!cancelled) setNav({ basis: 'list', ordered: orderQueue(res.incidents, parseQueueView(params)) });
        } else {
          const res = await incidentsApi.list({ captureId: captureId ?? undefined, jobId: jobId ?? undefined });
          if (!cancelled) setNav({ basis: 'pipeline', ordered: sortIncidents(res.incidents, 'rank', 'asc') });
        }
      } catch {
        if (!cancelled) setNav({ basis: fromQuery !== null ? 'list' : 'pipeline', ordered: [] });
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return nav;
}

export function IncidentDetailPage() {
  const { jobId, queueRank } = useParams<{ jobId: string; queueRank: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const [data, setData] = useState<IncidentDetailApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const rawTab = searchParams.get('tab');
  const tab: DetailTab = isDetailTab(rawTab) ? rawTab : 'summary';
  const fromQuery = searchParams.get('from');

  // 허용 밖 tab은 요약으로 보이고 URL을 고친다(L2).
  useEffect(() => {
    if (rawTab !== null && !isDetailTab(rawTab)) {
      const next = new URLSearchParams(searchParams);
      next.delete('tab');
      setSearchParams(next, { replace: true });
    }
  }, [rawTab, searchParams, setSearchParams]);

  const loadDetail = useCallback(async () => {
    if (!jobId || !queueRank) {
      setErrorMsg('잘못된 인시던트 경로입니다.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await incidentsApi.detail(jobId, queueRank);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '인시던트 정보를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [jobId, queueRank]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  const detail = data?.detail;
  const incident = detail?.incident;
  // 다른 인시던트로 옮겨 가는 중에는 이전 인시던트 내용을 보이지 않는다.
  const current =
    incident && String(incident.jobId) === jobId && String(incident.queueRank) === queueRank ? detail : undefined;

  const nav = useNeighborOrder(fromQuery, incident?.captureId ?? null, incident?.jobId ?? null);
  const neighbors = useMemo(
    () => (nav && jobId && queueRank ? findNeighbors(nav.ordered, Number(jobId), Number(queueRank)) : null),
    [nav, jobId, queueRank],
  );

  function linkTo(item: IncidentQueueItem): string {
    const next = new URLSearchParams();
    if (fromQuery !== null) next.set('from', fromQuery);
    if (tab !== 'summary') next.set('tab', tab);
    const qs = next.toString();
    return `/incidents/${item.jobId}/rank/${item.queueRank}${qs ? `?${qs}` : ''}`;
  }

  const backUrl =
    fromQuery !== null
      ? `/incidents${fromQuery ? `?${fromQuery}` : ''}`
      : incident
        ? `/incidents?captureId=${encodeURIComponent(incident.captureId)}`
        : '/incidents';

  function selectTab(next: DetailTab) {
    const params = new URLSearchParams(searchParams);
    if (next === 'summary') params.delete('tab');
    else params.set('tab', next);
    setSearchParams(params, { replace: true });
  }

  function onTabKey(e: React.KeyboardEvent<HTMLButtonElement>, idx: number) {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const n = DETAIL_TABS.length;
    const target =
      e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : (idx + (e.key === 'ArrowRight' ? 1 : n - 1)) % n;
    selectTab(DETAIL_TABS[target].key);
    document.getElementById(`detail-tab-${DETAIL_TABS[target].key}`)?.focus();
  }

  const navBasisLabel = nav?.basis === 'pipeline' ? '파이프라인 순위 순' : '목록 순서';
  const navActions = (
    <nav aria-label="인시던트 이동" className="flex flex-wrap items-center gap-1.5">
      <Link to={backUrl} className="soc-btn-secondary py-1.5 text-xs">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
        인시던트 목록으로
      </Link>
      <NeighborLink item={neighbors?.prev ?? null} to={linkTo} label="이전 인시던트" icon="prev" />
      {neighbors && neighbors.index >= 0 && (
        <span className="text-[11px] tabular-nums text-slate-400" title={`이전·다음 기준: ${navBasisLabel}`}>
          {neighbors.index + 1} / {neighbors.total}
        </span>
      )}
      <NeighborLink item={neighbors?.next ?? null} to={linkTo} label="다음 인시던트" icon="next" />
    </nav>
  );

  const readOnly = user?.role === 'VIEWER';
  const timeline = current ? buildTimeline(current.statusHistory, current.analystReview) : [];

  return (
    <AppShell
      title="인시던트 상세"
      actions={navActions}
      stickyBar={current ? <DetailHeader detail={current} /> : undefined}
    >
      <div className="space-y-4">
        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadDetail()} />}

        {loading && !current ? (
          <LoadingPanel label="인시던트 정보를 불러오는 중..." />
        ) : current ? (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
            {/* 조치 패널: 넓은 화면은 오른쪽 고정, 좁은 화면은 헤더 바로 아래. 길면 패널 안에서 스크롤(L3). */}
            <aside
              aria-label="조치 패널"
              className="xl:sticky xl:top-[8.5rem] xl:col-start-2 xl:row-start-1 xl:max-h-[calc(100vh-9.5rem)] xl:self-start xl:overflow-y-auto"
            >
              <ActionPanel
                key={`${current.incident.jobId}-${current.incident.queueRank}`}
                detail={current}
                readOnly={readOnly}
                onRefresh={loadDetail}
                onShowHistory={() => selectTab('history')}
              />
            </aside>

            <div className="soc-card min-w-0 xl:col-start-1 xl:row-start-1">
              <div
                role="tablist"
                aria-label="인시던트 상세 내용"
                className="flex gap-1 overflow-x-auto border-b border-slate-800 px-3"
              >
                {DETAIL_TABS.map((t, idx) => {
                  const active = t.key === tab;
                  return (
                    <button
                      key={t.key}
                      id={`detail-tab-${t.key}`}
                      type="button"
                      role="tab"
                      aria-selected={active}
                      aria-controls={`detail-panel-${t.key}`}
                      tabIndex={active ? 0 : -1}
                      onClick={() => selectTab(t.key)}
                      onKeyDown={(e) => onTabKey(e, idx)}
                      className={`-mb-px whitespace-nowrap border-b-2 px-3 py-2.5 text-xs font-semibold transition focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70 ${
                        active
                          ? 'border-cyan-400 text-cyan-200'
                          : 'border-transparent text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* 비활성 탭도 숨긴 채 DOM에 둔다(용어 회귀·XSS 검사가 모든 탭을 덮도록, M5). */}
              {DETAIL_TABS.map((t) => (
                <div
                  key={t.key}
                  id={`detail-panel-${t.key}`}
                  role="tabpanel"
                  aria-labelledby={`detail-tab-${t.key}`}
                  hidden={t.key !== tab}
                  tabIndex={0}
                  className="p-4 focus:outline-none sm:p-5"
                >
                  {t.key === 'summary' && <SummaryTab detail={current} />}
                  {t.key === 'evidence' && <EvidenceSection evidence={current.evidence} assetNames={current.assetNames} />}
                  {t.key === 'report' && <ReportSection report={current.report} />}
                  {t.key === 'decision' && <SendDecisionSection sendDecision={current.sendDecision} />}
                  {t.key === 'slack' && <SlackThreadsSection threadGroups={current.slackThreadGroups} />}
                  {t.key === 'history' && (
                    <HistoryTimeline events={timeline} emptyText="아직 상태 변경·에스컬레이션 이력이 없습니다." />
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </AppShell>
  );
}

function NeighborLink({
  item,
  to,
  label,
  icon,
}: {
  item: IncidentQueueItem | null;
  to: (item: IncidentQueueItem) => string;
  label: string;
  icon: 'prev' | 'next';
}) {
  const Icon = icon === 'prev' ? ChevronLeft : ChevronRight;
  if (!item) {
    return (
      <span
        role="link"
        aria-disabled="true"
        aria-label={label}
        className="soc-btn-secondary cursor-not-allowed px-2 py-1.5 text-xs opacity-40"
      >
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      </span>
    );
  }
  return (
    <Link
      to={to(item)}
      aria-label={label}
      title={`${label}: ${item.hostIp} · ${item.queueRank}위`}
      className="soc-btn-secondary px-2 py-1.5 text-xs"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
    </Link>
  );
}
