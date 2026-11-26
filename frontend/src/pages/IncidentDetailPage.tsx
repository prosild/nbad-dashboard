import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, ChevronLeft, ChevronRight, Info, RefreshCw } from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../api/client';
import { incidentsApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { STALE_ACTION_BLOCKED_DETAIL, StaleNotice } from '../components/StaleNotice';
import { ActionPanel } from '../components/incident/ActionPanel';
import { DetailHeader } from '../components/incident/DetailHeader';
import { EvidenceSection } from '../components/incident/EvidenceSection';
import { buildTimeline, HistoryTimeline } from '../components/incident/HistoryTimeline';
import { ReportSection } from '../components/incident/ReportSection';
import { SendDecisionSection } from '../components/incident/SendDecisionSection';
import { SlackThreadsSection } from '../components/incident/SlackThreadsSection';
import { RelatedHostIncidents } from '../components/incident/RelatedHostIncidents';
import { SummaryTab } from '../components/incident/SummaryTab';
import type { IncidentDetailApiResponse, IncidentNoLocation, QueueNeighborKey, QueueNeighborsResponse } from '../types/api';
import { incidentPath, parseIncidentNo } from '../utils/incidentLink';
import { parseQueueQuery, queueApiParams } from '../utils/triage';

/** 상세 탭. URL `tab=`에 남긴다(요약은 기본이라 남기지 않는다). */
export const DETAIL_TABS = [
  { key: 'summary', label: '요약' },
  { key: 'evidence', label: '증적' },
  { key: 'report', label: 'AI 리포트' },
  { key: 'decision', label: '발송 판단' },
  { key: 'slack', label: 'Slack' },
  { key: 'history', label: '이력' },
] as const;

export type DetailTab = (typeof DETAIL_TABS)[number]['key'];

function isDetailTab(value: string | null): value is DetailTab {
  return DETAIL_TABS.some((t) => t.key === value);
}

interface NavState {
  result: QueueNeighborsResponse | null;
  /** 이동 목록 조회 실패(T21: 헤더에 안내와 다시 시도를 둔다) */
  failed: boolean;
}

/** 이동 목록 조회 실패 안내(T21) */
export const NAV_LOAD_FAILED_TEXT = '이동 목록을 불러오지 못했습니다';
/** 거르기 결과에 이 인시던트가 없을 때(T23) */
export const NAV_NOT_IN_LIST_TEXT = '목록이 갱신되어 이 인시던트가 지금 목록에 없습니다';
/** 보고 있는 탐지 작업이 최신이 아닐 때(T23) */
export const NEWER_RESULT_TEXT = '이 인시던트의 더 새로운 분석 결과가 있습니다';
/** T49: 조치 패널이 있을 때 본문(안내 줄과 카드)이 넓은 화면에서 비우는 오른쪽 폭(패널 22rem + 간격 1rem) */
const BODY_WITH_PANEL = 'xl:pr-[23rem]';
/** T27 번호 위치가 최신 큐가 아닐 때 */
export const NOT_LATEST_TEXT = '최신 탐지 결과에는 이 인시던트가 없습니다. 마지막으로 나온 탐지 결과를 보여 줍니다.';

/**
 * 이전·다음(T23). 목록이 넘긴 `from=` 쿼리(기간·수집원·거르기·정렬)로 서버 neighbors API를 부른다.
 * 쿼리가 없으면 기본 큐(기간 24시간, 우선순위 순) 조건을 쓴다. 목록 전체를 받지 않는다.
 */
function useNeighbors(
  fromQuery: string | null,
  jobId: string | undefined,
  queueRank: string | undefined,
): { nav: NavState | null; retry: () => void } {
  const [nav, setNav] = useState<NavState | null>(null);
  const [attempt, setAttempt] = useState(0);
  const key = jobId && queueRank ? `${jobId}|${queueRank}|${fromQuery ?? ''}#${attempt}` : null;
  useEffect(() => {
    if (key === null || !jobId || !queueRank) return undefined;
    let cancelled = false;
    setNav(null);
    void (async () => {
      try {
        const query = parseQueueQuery(new URLSearchParams(fromQuery ?? ''));
        const res = await incidentsApi.neighbors(jobId, queueRank, queueApiParams(query, { paging: false }));
        if (!cancelled) setNav({ result: res, failed: false });
      } catch {
        if (!cancelled) setNav({ result: null, failed: true });
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  return { nav, retry };
}

/**
 * T27 상세 화면. 고정 주소 `/incidents/{번호}`는 번호 API로 지금 위치(작업·순위)를 받은 뒤 기존 상세·조치 API를 그 위치로 부른다.
 * 옛 주소 `/incidents/{작업}/rank/{순위}`는 상세를 부르고, 응답에 번호가 있으면 같은 쿼리를 붙인 번호 주소로 바꾼다(replace).
 */
export function IncidentDetailPage() {
  const params = useParams<{ jobId?: string; queueRank?: string; incidentNo?: string }>();
  const navigate = useNavigate();
  const numberMode = params.incidentNo !== undefined;
  const incidentNo = numberMode ? parseIncidentNo(params.incidentNo) : null;
  const [location, setLocation] = useState<IncidentNoLocation | null>(null);
  const [locateAttempt, setLocateAttempt] = useState(0);
  const [locateError, setLocateError] = useState<ErrorNotice | null>(null);
  const jobId = numberMode ? (location ? String(location.jobId) : undefined) : params.jobId;
  const queueRank = numberMode ? (location ? String(location.queueRank) : undefined) : params.queueRank;
  const [searchParams, setSearchParams] = useSearchParams();
  const { user, timeContext } = useAuth();
  const [data, setData] = useState<IncidentDetailApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  /** 마지막 상세 실패와 그 인시던트 키(T42). 같은 키의 다음 성공 때 지운다 */
  const [failure, setFailure] = useState<{ key: string; notice: ErrorNotice } | null>(null);
  /** data를 받은 시각(최신 값이 아닙니다 표시의 마지막 성공 시각) */
  const [loadedAt, setLoadedAt] = useState<string | null>(null);
  /** 늦게 온 앞 인시던트의 응답을 버리기 위한 요청 순번(T42) */
  const detailSeq = useRef(0);
  const detailKey = `${jobId ?? ''}|${queueRank ?? ''}`;

  const rawTab = searchParams.get('tab');
  const tab: DetailTab = isDetailTab(rawTab) ? rawTab : 'summary';
  const fromQuery = searchParams.get('from');

  // 허용 밖 tab은 요약으로 보이고 URL을 고친다.
  useEffect(() => {
    if (rawTab !== null && !isDetailTab(rawTab)) {
      const next = new URLSearchParams(searchParams);
      next.delete('tab');
      setSearchParams(next, { replace: true });
    }
  }, [rawTab, searchParams, setSearchParams]);

  // T27 번호 주소: 번호 → 지금 위치. "새로 고침"은 다시 받는다(주소는 그대로).
  useEffect(() => {
    if (!numberMode) return undefined;
    if (incidentNo === null) {
      setLocateError({ message: '잘못된 인시던트 경로입니다.', rateLimited: false });
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    setLocateError(null);
    incidentsApi
      .locate(incidentNo)
      .then((res) => {
        if (!cancelled) setLocation(res);
      })
      .catch((err) => {
        if (cancelled) return;
        setLocation(null);
        setLoading(false);
        setLocateError(errorNotice(err, '인시던트 정보를 불러오지 못했습니다.'));
      });
    return () => {
      cancelled = true;
    };
  }, [numberMode, incidentNo, locateAttempt]);

  const loadDetail = useCallback(async () => {
    if (numberMode && (!jobId || !queueRank)) {
      return; // 위치를 받기 전
    }
    const key = `${jobId ?? ''}|${queueRank ?? ''}`;
    const my = ++detailSeq.current;
    if (!jobId || !queueRank) {
      setFailure({ key, notice: { message: '잘못된 인시던트 경로입니다.', rateLimited: false } });
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await incidentsApi.detail(jobId, queueRank);
      // 다른 인시던트로 옮긴 뒤 늦게 온 앞 인시던트의 응답은 버린다
      if (my !== detailSeq.current) return;
      setData(res);
      setLoadedAt(new Date().toISOString());
      setFailure(null);
    } catch (err) {
      if (my !== detailSeq.current) return;
      setFailure({ key, notice: errorNotice(err, '인시던트 정보를 불러오지 못했습니다.') });
    } finally {
      if (my === detailSeq.current) setLoading(false);
    }
    // T27: 번호 위치를 다시 받으면(새로 고침) 같은 위치여도 다시 부른다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [numberMode, jobId, queueRank, location]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  // T27 옛 주소: 번호가 있으면 같은 쿼리를 붙인 번호 주소로 바꾼다(그 인시던트의 지금 결과가 열린다)
  const loadedNo = data?.incidentNo ?? null;
  const loadedJob = data?.detail?.incident?.jobId;
  const loadedRank = data?.detail?.incident?.queueRank;
  useEffect(() => {
    if (numberMode || loadedNo === null || loadedNo === undefined) return;
    if (String(loadedJob) !== params.jobId || String(loadedRank) !== params.queueRank) return;
    const target = incidentPath({ incidentNo: loadedNo }, searchParams);
    if (target) navigate(target, { replace: true });
  }, [numberMode, loadedNo, loadedJob, loadedRank, params.jobId, params.queueRank, searchParams, navigate]);

  const detail = data?.detail;
  const incident = detail?.incident;
  // 다른 인시던트로 옮겨 가는 중에는 이전 인시던트 내용을 보이지 않는다.
  const current =
    incident && String(incident.jobId) === jobId && String(incident.queueRank) === queueRank ? detail : undefined;
  const failedNotice = failure !== null && failure.key === detailKey ? failure.notice : null;
  /** T42: 같은 인시던트의 값을 남긴 채 다시 읽기가 실패한 상태. 이 동안 조치 버튼을 막는다 */
  const staleDetail = failedNotice !== null && current !== undefined;

  const { nav, retry: retryNav } = useNeighbors(fromQuery, jobId, queueRank);
  const neighbors = nav?.result ?? null;
  const currentKey = neighbors?.current ?? null;
  const stale =
    currentKey !== null && (String(currentKey.jobId) !== jobId || String(currentKey.queueRank) !== queueRank);
  // T27: 번호 주소에서 위치가 최신이 아님(latest=false). 새 결과 띠는 이웃 API의 current가 다른 위치를 가리킬 때만이다.
  const notLatest = numberMode && location !== null && !location.latest;

  function linkTo(item: QueueNeighborKey): string {
    const next = new URLSearchParams();
    if (fromQuery !== null) next.set('from', fromQuery);
    if (tab !== 'summary') next.set('tab', tab);
    return incidentPath(item, next) ?? '/incidents';
  }

  // 목록으로: 넘겨받은 목록 쿼리로 돌아가고, 없으면 기본 큐다(캡처 쿼리를 새로 만들지 않는다).
  const backUrl = fromQuery ? `/incidents?${fromQuery}` : '/incidents';

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

  const navBasisLabel = fromQuery !== null ? '목록 순서' : '기본 목록 순서';
  const navActions = (
    <nav aria-label="인시던트 이동" className="flex flex-wrap items-center gap-1.5 xl:flex-nowrap">
      <Link to={backUrl} className="soc-btn-secondary py-1.5 text-xs">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
        인시던트 목록으로
      </Link>
      <NeighborLink item={neighbors?.prev ?? null} to={linkTo} label="이전 인시던트" icon="prev" />
      {nav?.failed && (
        <span role="alert" className="inline-flex items-center gap-1.5 text-[11px] text-amber-200">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
          {NAV_LOAD_FAILED_TEXT}
          <button type="button" onClick={retryNav} className="soc-btn-secondary px-2 py-1 text-[11px]">
            <RefreshCw className="h-3 w-3" aria-hidden="true" />
            다시 시도
          </button>
        </span>
      )}
      {neighbors && neighbors.position !== null && (
        <span className="text-[11px] tabular-nums text-slate-400" title={`이전·다음 기준: ${navBasisLabel}`}>
          {neighbors.position} / {neighbors.total}
        </span>
      )}
      {neighbors && neighbors.position === null && (
        <span className="inline-flex items-center gap-1 text-[11px] text-slate-400" data-nav-missing="">
          <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          {NAV_NOT_IN_LIST_TEXT}
        </span>
      )}
      <NeighborLink item={neighbors?.next ?? null} to={linkTo} label="다음 인시던트" icon="next" />
    </nav>
  );

  const readOnly = user?.role === 'VIEWER';
  const timeline = current
    ? buildTimeline(current.statusHistory, current.analystReview, data?.assignmentHistory ?? [], data?.responseActions ?? [])
    : [];

  return (
    <AppShell
      title="인시던트 상세"
      actions={navActions}
      stickyBar={
        current ? (
          <DetailHeader
            detail={current}
            meta={data?.queueMeta ?? null}
            snapshot={Boolean(timeContext?.snapshot)}
            incidentNo={data?.incidentNo ?? null}
            responseActions={data?.responseActions}
          />
        ) : undefined
      }
      sidePanelLabel="조치 패널"
      sidePanel={
        // T49: 조치 패널은 AppShell이 머리말과 한 상자에 그린다(넓은 화면은 머리말 바로 아래 오른쪽에 붙고
        // 좁은 화면은 머리말 다음에 놓인다). 길면 패널 안에서 스크롤한다.
        current ? (
          <ActionPanel
            key={`${current.incident.jobId}-${current.incident.queueRank}`}
            detail={current}
            readOnly={readOnly}
            onRefresh={loadDetail}
            onShowHistory={() => selectTab('history')}
            assignment={data?.assignment ?? null}
            assignmentHistory={data?.assignmentHistory ?? []}
            canAssign={Boolean(data?.canAssign)}
            responseActions={data?.responseActions}
            canRecordResponse={Boolean(data?.canRecordResponse)}
            blockedReason={staleDetail ? STALE_ACTION_BLOCKED_DETAIL : null}
            currentUsername={user?.username ?? null}
          />
        ) : undefined
      }
    >
      {/* T49: 패널이 있으면 넓은 화면에서 오른쪽(패널 22rem + 간격 1rem)을 비운다. 안내 줄도 카드와 같은 폭이 된다. */}
      <div className={current ? `space-y-4 ${BODY_WITH_PANEL}` : 'space-y-4'}>
        {stale && currentKey && (
          <div
            role="status"
            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-sky-500/35 bg-sky-500/10 px-3 py-2 text-xs text-sky-100"
          >
            <span className="flex items-center gap-2">
              <Info className="h-3.5 w-3.5 shrink-0 text-sky-300" aria-hidden="true" />
              {NEWER_RESULT_TEXT}
            </span>
            {numberMode ? (
              <button
                type="button"
                onClick={() => setLocateAttempt((n) => n + 1)}
                className="soc-btn-secondary px-2.5 py-1 text-xs"
              >
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
                새로 고침
              </button>
            ) : (
              <Link to={linkTo(currentKey)} className="soc-btn-secondary px-2.5 py-1 text-xs">
                최신 보기
              </Link>
            )}
          </div>
        )}
        {notLatest && current && (
          <div
            role="status"
            data-not-latest=""
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-slate-200"
          >
            <Info className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
            {NOT_LATEST_TEXT}
          </div>
        )}
        {locateError && (
          <ErrorAlert message={locateError.message} rateLimited={locateError.rateLimited} onRetry={incidentNo !== null ? () => setLocateAttempt((n) => n + 1) : undefined} />
        )}
        {failedNotice && staleDetail && (
          <StaleNotice notice={failedNotice} loadedAt={loadedAt} loading={loading} onRetry={() => void loadDetail()} />
        )}
        {failedNotice && !staleDetail && (
          <ErrorAlert message={failedNotice.message} rateLimited={failedNotice.rateLimited} onRetry={() => void loadDetail()} />
        )}

        {loading && !current && !locateError ? (
          <LoadingPanel label="인시던트 정보를 불러오는 중..." />
        ) : current ? (
          <div className="grid grid-cols-1 gap-4">
            <div className="soc-card min-w-0">
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

              {/* 비활성 탭도 숨긴 채 DOM에 둔다(용어 회귀·XSS 검사가 모든 탭을 덮도록). */}
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
                  {t.key === 'summary' && (
                    <SummaryTab
                      detail={current}
                      related={
                        // T46: 상세가 뜬 뒤 따로 부른다. 상세를 다시 불러오면(loadedAt) 함께 다시 부른다
                        <RelatedHostIncidents
                          jobId={current.incident.jobId}
                          queueRank={current.incident.queueRank}
                          hostIp={current.incident.hostIp}
                          eventStart={current.incident.eventStart}
                          maskedView={Boolean(data?.maskedView)}
                          reloadKey={loadedAt}
                        />
                      }
                    />
                  )}
                  {t.key === 'evidence' && (
                    <EvidenceSection evidence={current.evidence} assetNames={current.assetNames} incident={current.incident} />
                  )}
                  {t.key === 'report' && <ReportSection report={current.report} />}
                  {t.key === 'decision' && <SendDecisionSection sendDecision={current.sendDecision} />}
                  {t.key === 'slack' && <SlackThreadsSection threadGroups={current.slackThreadGroups} />}
                  {t.key === 'history' && (
                    <HistoryTimeline events={timeline} emptyText="아직 상태 변경·에스컬레이션·담당·대응 조치 이력이 없습니다." />
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
  item: QueueNeighborKey | null;
  to: (item: QueueNeighborKey) => string;
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
      title={item.hostIp ? `${label}: ${item.hostIp}` : label}
      className="soc-btn-secondary px-2 py-1.5 text-xs"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
    </Link>
  );
}
