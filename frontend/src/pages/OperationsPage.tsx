import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, BarChart3, Bell, ChevronDown, ChevronRight, Info, Layers, MessageSquare, Server, UserCheck } from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../api/client';
import { dashboardApi, operationsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { PeriodButtons, SourceField, sourceSelectChanges, sourceSelectValue, withoutLastDetected } from '../components/ConditionBar';
import { SensorHealthBadge, SourceStatusTable, sensorHealthTooltip } from '../components/dashboard/SourceStatus';
import { HandlingTimesPanel, WorkloadPanel } from '../components/dashboard/HandlingPanels';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import {
  ALERTED_COUNT_TOOLTIP,
  CaptureName,
  CodeLabel,
  DetectionModelName,
  JobStatusBadge,
  SocBadge,
  type BadgeTone,
} from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { DashboardOverviewResponse, FeedbackSummaryRecord, OperationsApiResponse, ScoringJob } from '../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime, formatNumber } from '../utils/format';
import { captureShortNames } from '../utils/labels';
import {
  customUrlChanges,
  parsePeriodSelection,
  parseSource,
  periodApiParams,
  periodScopeText,
  presetUrlChanges,
  type PresetPeriod,
} from '../utils/triage';
import {
  SAMPLE_MIN,
  alertPrecisionSummaryText,
  effectiveAlertedResolved,
  isAllModelRow,
  isQuietRow,
  precisionSummaryText,
  precisionValue,
  sampleShortTooltip,
  selectSummaryRows,
  sumAllRows,
  totalsAsRow,
} from '../utils/operations';

/** 판정 건수 배지: 0이면 색을 쓰지 않는다 */
function ResolutionCountBadge({ code, count, tone }: { code: string; count: number; tone: BadgeTone }) {
  return (
    <SocBadge tone={count > 0 ? tone : 'muted'}>
      <CodeLabel dict="resolution" value={code} />
      <span className="tabular-nums">{formatNumber(count)}</span>
    </SocBadge>
  );
}

interface SummaryGroup {
  all: FeedbackSummaryRecord;
  models: FeedbackSummaryRecord[];
}

/** '모든 모델 합계' 행마다 같은 캡처·모델 버전의 탐지 모델별 행을 묶는다. */
function groupSummaries(rows: FeedbackSummaryRecord[]): SummaryGroup[] {
  const groups: SummaryGroup[] = [];
  const byKey = new Map<string, SummaryGroup>();
  for (const row of rows) {
    if (!isAllModelRow(row)) continue;
    const group = { all: row, models: [] as FeedbackSummaryRecord[] };
    byKey.set(`${row.captureId}|${row.bundleId}`, group);
    groups.push(group);
  }
  for (const row of rows) {
    if (isAllModelRow(row)) continue;
    const group = byKey.get(`${row.captureId}|${row.bundleId}`);
    if (group) group.models.push(row);
  }
  return groups;
}

/** 운영 현황 기본 기간(T24) */
export const OPERATIONS_DEFAULT_PERIOD: PresetPeriod = '7d';

/** 누적 판정 표의 모델 버전 선택용: latestJobs의 최신 성공 작업(기간 무관) */
export function latestSucceededJobs(data: OperationsApiResponse): ScoringJob[] {
  return (data.latestJobs ?? [])
    .map((l) => l.latestSucceeded)
    .filter((j): j is NonNullable<typeof j> => j !== null)
    .map(
      (j) =>
        ({
          jobId: j.jobId,
          captureId: j.captureId,
          bundleId: j.bundleId ?? '',
          status: j.status ?? 'succeeded',
          startedAt: j.startedAt,
          finishedAt: j.finishedAt,
          error: j.error,
          incidentCount: null,
        }) as unknown as ScoringJob,
    );
}

/** T42: 받은 값과 그 조건 키·받은 시각 */
interface Keyed<T> {
  condKey: string;
  value: T;
  loadedAt: string;
}

export function OperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  /** T42: 받은 값마다 그 조건 키를 기억하고, 키가 지금 조건과 같을 때만 그린다(운영 현황 API·overview 따로) */
  const [opsLoaded, setOpsLoaded] = useState<Keyed<OperationsApiResponse> | null>(null);
  const [ovLoaded, setOvLoaded] = useState<Keyed<DashboardOverviewResponse> | null>(null);
  const opsRef = useRef<Keyed<OperationsApiResponse> | null>(null);
  const ovRef = useRef<Keyed<DashboardOverviewResponse> | null>(null);
  /** 조건 줄의 수집원 목록(마지막 성공 값, 조건과 상관없이) */
  const [barSources, setBarSources] = useState<NonNullable<OperationsApiResponse['sources']>>([]);
  const [loading, setLoading] = useState(true);
  /** 마지막 실패와 그 조건. keptOld = 실패한 쪽에 같은 조건의 앞 값을 남겼는가(최신 값이 아님) */
  const [failure, setFailure] = useState<{ condKey: string; notice: ErrorNotice; keptOld: boolean } | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const seq = useRef(0);

  // URL이 상태의 원본이다. 옛 captureId 링크는 수집원 선택 안의 캡처로 읽는다.
  const sel = parsePeriodSelection(searchParams, OPERATIONS_DEFAULT_PERIOD);
  const period = sel.period;
  const rangeStart = sel.range?.start;
  const rangeEnd = sel.range?.end;
  const source = parseSource(searchParams.get('source'));
  const captureId = searchParams.get('captureId') || null;

  const condKey = JSON.stringify([period, rangeStart ?? null, rangeEnd ?? null, source, captureId]);

  const loadOperations = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    const params = {
      ...periodApiParams({ period, range: rangeStart && rangeEnd ? { start: rangeStart, end: rangeEnd } : null }),
      source: captureId ? undefined : (source ?? undefined),
      captureId: captureId ?? undefined,
    };
    const [ops, ov] = await Promise.allSettled([operationsApi.get(params), dashboardApi.overview(params)]);
    if (my !== seq.current) return;
    // 한쪽만 실패하면 받은 쪽은 그대로 보이고 오류를 알린다(수집원 상태는 overview, 나머지는 운영 현황 API).
    // T42: 실패한 쪽은 같은 조건으로 받은 앞 값만 남긴다(다른 조건의 값을 지금 조건의 값처럼 보이지 않는다).
    const loadedAt = new Date().toISOString();
    const keep = <T,>(prev: Keyed<T> | null) => (prev && prev.condKey === condKey ? prev : null);
    const nextOps = ops.status === 'fulfilled' ? { condKey, value: ops.value, loadedAt } : keep(opsRef.current);
    const nextOv = ov.status === 'fulfilled' ? { condKey, value: ov.value, loadedAt } : keep(ovRef.current);
    opsRef.current = nextOps;
    ovRef.current = nextOv;
    setOpsLoaded(nextOps);
    setOvLoaded(nextOv);
    if (ops.status === 'fulfilled') setBarSources(ops.value.sources ?? []);
    const failed = [ops, ov].find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined;
    if (failed) {
      const keptOld =
        (ops.status === 'rejected' && nextOps !== null) || (ov.status === 'rejected' && nextOv !== null);
      setFailure({ condKey, notice: errorNotice(failed.reason, '운영 현황을 불러오지 못했습니다.'), keptOld });
    } else {
      setFailure(null);
    }
    setLoading(false);
  }, [period, rangeStart, rangeEnd, source, captureId, condKey]);

  useEffect(() => {
    void loadOperations();
  }, [loadOperations]);

  function updateParams(changes: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSearchParams(next);
  }

  const data = opsLoaded !== null && opsLoaded.condKey === condKey ? opsLoaded.value : null;
  const overview = ovLoaded !== null && ovLoaded.condKey === condKey ? ovLoaded.value : null;
  const failed = failure !== null && failure.condKey === condKey ? failure : null;
  /** 같은 조건으로 받은 앞 값을 남긴 채 다시 불러오기가 실패한 상태(최신 값이 아니다) */
  const stale = failed !== null && failed.keptOld;
  const lastLoadedAt = [opsLoaded, ovLoaded]
    .filter((x): x is Keyed<OperationsApiResponse> | Keyed<DashboardOverviewResponse> => x !== null && x.condKey === condKey)
    .map((x) => x.loadedAt)
    .sort()[0] ?? null;

  const groups = useMemo(() => groupSummaries(data?.feedbackSummaries ?? []), [data]);
  const shortNames = useMemo(() => captureShortNames(barSources.map((x) => x.captureId)), [barSources]);
  const status = useMemo(() => {
    if (!data) return null;
    const { allRows } = selectSummaryRows(data.feedbackSummaries, latestSucceededJobs(data));
    return { totalsRow: totalsAsRow(sumAllRows(allRows)) };
  }, [data]);
  const scope = periodScopeText(sel, overview?.anchor ?? data?.anchor);
  /** 착수 지연 수(T25)를 누르면 같은 수집원 조건의 큐 착수 지연(기간 전체)로 간다 */
  const overdueLink = useMemo(() => {
    const q = new URLSearchParams({ period: 'all', overdue: 'true' });
    if (captureId) q.set('captureId', captureId);
    else if (source) q.set('source', source);
    return `/incidents?${q.toString()}`;
  }, [captureId, source]);
  const sensors = overview?.sensors ?? [];
  const importedFailed = (overview?.captures ?? []).filter((c) => c.sensorKey === null && c.state === 'failed').length;
  const importedCount = (overview?.captures ?? []).filter((c) => c.sensorKey === null).length;

  const groupKey = (g: SummaryGroup) => `${g.all.captureId}|${g.all.bundleId}`;
  const allExpanded = groups.length > 0 && groups.every((g) => g.models.length === 0 || expanded.has(groupKey(g)));

  function toggleGroup(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function toggleAll() {
    setExpanded(allExpanded ? new Set() : new Set(groups.map(groupKey)));
  }

  return (
    <AppShell title="운영 현황">
      <div className="space-y-4">
        <section className="soc-card px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <PeriodButtons
              value={period}
              range={sel.range}
              onChange={(p) => updateParams(presetUrlChanges(p, OPERATIONS_DEFAULT_PERIOD))}
              onApplyRange={(r) => updateParams(customUrlChanges(r))}
              current={{
                periodStart: data?.periodStart ?? overview?.periodStart,
                periodEnd: data?.periodEnd ?? overview?.periodEnd,
                anchor: overview?.anchor ?? data?.anchor,
              }}
            />
            <SourceField
              id="ops-source"
              sources={withoutLastDetected(barSources)}
              value={sourceSelectValue(source, captureId)}
              onChange={(v) => updateParams(sourceSelectChanges(v))}
            />
            <div className="ml-auto flex flex-wrap gap-x-3 gap-y-1 text-xs tabular-nums text-slate-400">
              {overview && (
                <span data-testid="ops-anchor">
                  {overview.snapshot ? (
                    <>
                      기준 시각 <span className="text-slate-200">{formatDateTime(overview.anchor)}</span> {DISPLAY_TIME_ZONE_LABEL}
                    </>
                  ) : (
                    '기준 시각: 현재'
                  )}
                </span>
              )}
              <span>
                {scope} 탐지 작업 {data ? `${formatNumber(data.jobsTotal ?? data.jobs.length)}건` : '-'}
              </span>
              <span>· Slack 일일 요약 {data ? `${formatNumber(data.slackSummaries.length)}건` : '-'}</span>
            </div>
          </div>
        </section>

        {failed && stale && (
          <StaleNotice
            notice={failed.notice}
            loadedAt={lastLoadedAt}
            loading={loading}
            onRetry={() => void loadOperations()}
          />
        )}
        {failed && !stale && (
          <ErrorAlert message={failed.notice.message} rateLimited={failed.notice.rateLimited} onRetry={() => void loadOperations()} />
        )}

        {/* T42: 지금 조건의 값이 하나도 없으면(불러오는 중·실패) 0건·"없습니다" 문구를 그리지 않는다 */}
        {!data && !overview ? (
          loading ? <LoadingPanel label="운영 현황을 불러오는 중..." /> : null
        ) : (
          <>
            {status && (
              <section aria-label="상태 요약" className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <StatusCard
                  icon={Server}
                  title="수집원"
                  tone={!overview ? 'neutral' : sensors.some((x) => x.health !== 'ok') || importedFailed > 0 ? 'attention' : 'ok'}
                >
                  {!overview ? (
                    <div className="text-sm text-slate-400" data-testid="ops-sources-missing">
                      {loading ? '불러오는 중...' : '- 불러오지 못했습니다'}
                    </div>
                  ) : sensors.length === 0 ? (
                    <div className="text-sm text-slate-400">조건에 맞는 센서가 없습니다</div>
                  ) : (
                    <ul className="space-y-1">
                      {sensors.map((x) => (
                        <li key={x.sensorKey} className="flex flex-wrap items-center gap-2 text-sm font-semibold text-slate-50">
                          {x.label}
                          <SensorHealthBadge
                            health={x.health}
                            title={sensorHealthTooltip(
                              x.health,
                              overview?.staleAfterSeconds ?? 900,
                              overview?.downAfterSeconds ?? 3600,
                              Boolean(overview?.snapshot),
                            )}
                          />
                        </li>
                      ))}
                    </ul>
                  )}
                  {overview && (
                  <div className="text-xs text-slate-400" title="가장 최근 탐지 작업이 실패한 가져온 데이터 캡처 수">
                    가져온 데이터 실패{' '}
                    <span className={`tabular-nums ${importedFailed > 0 ? 'text-amber-300' : 'text-slate-300'}`}>
                      {formatNumber(importedFailed)}개
                    </span>{' '}
                    / {formatNumber(importedCount)}개 캡처
                  </div>
                  )}
                </StatusCard>
                <StatusCard icon={UserCheck} title="분석가 판정" tone="neutral">
                  <div
                    className="text-base font-semibold text-slate-50"
                    title={
                      (status.totalsRow.resolved ?? 0) > 0 && (status.totalsRow.resolved ?? 0) < SAMPLE_MIN
                        ? sampleShortTooltip('정탐률', status.totalsRow.resolved ?? 0, status.totalsRow.zeekadPrecision)
                        : undefined
                    }
                  >
                    {precisionSummaryText(status.totalsRow)}
                  </div>
                  <div className="text-xs text-slate-400">
                    미판정{' '}
                    <span className="tabular-nums text-slate-300">
                      {formatNumber((status.totalsRow.incidents ?? 0) - (status.totalsRow.resolved ?? 0))}건
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">캡처마다 최신 탐지 작업의 모든 모델 합계 기준</div>
                </StatusCard>
                <StatusCard icon={Bell} title="경보" tone="neutral">
                  <div className="text-base font-semibold text-slate-50" title={ALERTED_COUNT_TOOLTIP}>
                    경보 발송 {formatNumber(status.totalsRow.alerted)}건
                  </div>
                  <div className="text-xs text-slate-300">{alertPrecisionSummaryText(status.totalsRow)}</div>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    최근 일일 요약{' '}
                    <span className="tabular-nums text-slate-300">
                      {overview && (overview.alerting.latestDeliveredAt ?? overview.alerting.latestCreatedAt)
                        ? formatDateTime(overview.alerting.latestDeliveredAt ?? overview.alerting.latestCreatedAt)
                        : overview
                          ? '기록 없음'
                          : '-'}
                    </span>
                    {overview?.alerting.latestDryRun && <SocBadge tone="muted">Dry-run</SocBadge>}
                  </div>
                </StatusCard>
              </section>
            )}

            {overview && (
              <section className="soc-card space-y-3 p-4" aria-label="수집원 상태 표">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                  <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <Server className="h-4 w-4 text-slate-400" />
                    수집원 상태
                  </h2>
                  <span className="text-[11px] text-slate-400">
                    인시던트·High·경보 발송·실패 작업은 {scope}
                    {overview.snapshot ? ' · 기준 시각까지' : ''}
                  </span>
                </div>
                <SourceStatusTable overview={overview} shortNames={shortNames} />
              </section>
            )}

            {data && (
            <>
            {data?.handlingTimes && <HandlingTimesPanel times={data.handlingTimes} scope={scope} />}
            {data?.workload && <WorkloadPanel workload={data.workload} overdueLink={overdueLink} />}

            <section className="soc-card space-y-3 p-4" aria-label="분석가 판정 집계">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                  <BarChart3 className="h-4 w-4 text-slate-400" />
                  분석가 판정 집계
                  <span className="text-xs font-normal text-slate-400" data-testid="cumulative-note">
                    누적(기간 없음)
                  </span>
                </h2>
                {groups.some((g) => g.models.length > 0) && (
                  <button type="button" onClick={toggleAll} className="soc-btn-secondary py-1 text-xs">
                    {allExpanded ? '탐지 모델별 행 모두 접기' : '탐지 모델별 행 모두 펼치기'}
                  </button>
                )}
              </div>
              <p className="flex items-center gap-1.5 text-xs text-slate-400">
                <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                미탐(재현율)은 이 집계로 알 수 없음 — 이 표는 탐지된 인시던트만 셉니다. 정탐률은 판정 {SAMPLE_MIN}건 미만이면
                표본 부족으로 보입니다.
              </p>

              {groups.length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
                  아직 분석가 판정이 기록된 인시던트가 없습니다.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left">
                    <thead>
                      <tr>
                        <th className="soc-th">캡처 · 모델 버전</th>
                        <th className="soc-th" title="탐지 모델별 행은 주 탐지 기준 인시던트 수입니다(교차 탐지를 빼지 않음)">
                          탐지 모델
                        </th>
                        <th className="soc-th text-right">인시던트 / 경보 발송 / 분석가 판정</th>
                        <th className="soc-th">판정 분포</th>
                        <th className="soc-th">정탐률</th>
                        <th className="soc-th">경보 정탐률 · 분석가 판정 수</th>
                      </tr>
                    </thead>
                    <tbody>
                      {groups.map((group) => {
                        const key = groupKey(group);
                        const open = expanded.has(key);
                        return (
                          <Fragment key={key}>
                            <SummaryRow row={group.all} isAll>
                              {group.models.length > 0 && (
                                <button
                                  type="button"
                                  onClick={() => toggleGroup(key)}
                                  aria-expanded={open}
                                  className="mt-1 inline-flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200"
                                >
                                  {open ? (
                                    <ChevronDown className="h-3 w-3" aria-hidden="true" />
                                  ) : (
                                    <ChevronRight className="h-3 w-3" aria-hidden="true" />
                                  )}
                                  탐지 모델별 {formatNumber(group.models.length)}개 {open ? '접기' : '펼치기'}
                                </button>
                              )}
                            </SummaryRow>
                            {open && group.models.map((row) => <SummaryRow key={`${key}|${row.zeekadPickedBy}`} row={row} />)}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <CollapsibleSection
              icon={Activity}
              title="탐지 작업 기록"
              count={`${scope} ${formatNumber(data?.jobsTotal ?? data?.jobs.length ?? 0)}건`}
            >
              {data?.jobsTruncated && (
                <p className="mb-2 text-xs text-amber-200" data-testid="jobs-truncated">
                  최근 {formatNumber(data.jobs.length)}건만 보임(전체 {formatNumber(data.jobsTotal ?? 0)}건)
                </p>
              )}
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr>
                      <th className="soc-th">완료 시각</th>
                      <th className="soc-th">캡처</th>
                      <th className="soc-th">모델 버전</th>
                      <th className="soc-th">상태</th>
                      <th className="soc-th text-right">인시던트 수</th>
                      <th className="soc-th">시작 시각</th>
                      <th className="soc-th">오류</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.jobs ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-xs text-slate-400">
                          이 기간에 탐지 작업 기록이 없습니다.
                        </td>
                      </tr>
                    ) : (
                      (data?.jobs ?? []).map((job) => (
                        <tr key={job.jobId} className="hover:bg-slate-800/35">
                          <td
                            className="soc-td whitespace-nowrap text-xs font-semibold tabular-nums text-slate-100"
                            title={`탐지 작업 ${job.jobId}`}
                          >
                            {formatDateTime(job.finishedAt)}
                          </td>
                          <td className="soc-td text-xs">
                            <CaptureName id={job.captureId} />
                          </td>
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
            </CollapsibleSection>

            <CollapsibleSection icon={Layers} title="모델 버전" count={`${formatNumber(data?.bundles.length ?? 0)}개`}>
              {(data?.bundles ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">등록된 모델 버전이 없습니다.</div>
              ) : (
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  {(data?.bundles ?? []).map((bundle) => {
                    const thresholdList = Object.entries(bundle.thresholdEntries ?? {});
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
                          · 버전{' '}
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
                                  <DetectionModelName id={model} />
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
            </CollapsibleSection>

            <CollapsibleSection
              icon={MessageSquare}
              title="Slack 일일 요약"
              count={`${scope} ${formatNumber(data?.slackSummaries.length ?? 0)}건`}
            >
              {(data?.slackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">이 기간에 Slack 일일 요약 기록이 없습니다.</div>
              ) : (
                <div className="space-y-3">
                  {(data?.slackSummaries ?? []).map((summary, idx) => (
                    <div key={`${summary.jobId ?? idx}-${summary.captureId ?? idx}`} className="soc-panel space-y-2 p-4 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <CaptureName id={summary.captureId} className="font-semibold text-slate-100" />
                          {summary.jobId !== null && (
                            <span className="text-[11px] text-slate-500" title={summary.zeekadMessageVersion ? `메시지 형식 ${summary.zeekadMessageVersion}` : undefined}>
                              작업 {summary.jobId}
                            </span>
                          )}
                          {summary.dryRunOrRecorded && <SocBadge tone="muted">Dry-run</SocBadge>}
                        </div>
                        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
                          {formatDateTime(summary.deliveredAt ?? summary.createdAt)}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        채널 <span className="break-all font-mono text-slate-300">{summary.payloadChannel ?? '-'}</span> · 발송 결과{' '}
                        <CodeLabel dict="slackDeliveryStatus" value={summary.zeekadDeliveryStatus} className="text-slate-300" />
                      </div>
                      {/* T64: 미리보기는 페이로드 글 전체(서버 상한 4,000자)라 높이를 정하고 상자 안에서 스크롤한다 */}
                      {summary.payloadTextPreview && (
                        <p className="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-slate-800 bg-[#090f1d] p-3 text-xs text-slate-200 [overflow-wrap:anywhere]">
                          {summary.payloadTextPreview}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CollapsibleSection>
            </>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}

function StatusCard({
  icon: Icon,
  title,
  tone,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  tone: 'ok' | 'attention' | 'neutral';
  children: React.ReactNode;
}) {
  const border = tone === 'attention' ? 'border-l-amber-400' : tone === 'ok' ? 'border-l-emerald-400' : 'border-l-slate-600';
  return (
    <section className={`soc-card space-y-1 border-l-4 px-4 py-3 ${border}`} aria-label={`${title} 상태`}>
      <h2 className="flex items-center gap-1.5 text-xs font-medium text-slate-400">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        {title}
      </h2>
      {children}
    </section>
  );
}

function CollapsibleSection({
  icon: Icon,
  title,
  count,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  count: string;
  children: React.ReactNode;
}) {
  return (
    <details className="soc-card group p-4">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-semibold text-slate-100">
        <ChevronRight className="h-4 w-4 text-slate-400 transition group-open:rotate-90" aria-hidden="true" />
        <Icon className="h-4 w-4 text-slate-400" aria-hidden="true" />
        {title}
        <span className="text-xs font-normal tabular-nums text-slate-400">{count}</span>
      </summary>
      <div className="mt-3 border-t border-slate-800 pt-3">{children}</div>
    </details>
  );
}

function SummaryRow({ row, isAll = false, children }: { row: FeedbackSummaryRecord; isAll?: boolean; children?: React.ReactNode }) {
  const quiet = isQuietRow(row);
  const resolved = row.resolved ?? 0;
  const alertResolved = effectiveAlertedResolved(row) ?? 0;
  const precision = precisionValue(resolved, row.zeekadPrecision);
  const alertPrecision = precisionValue(alertResolved, row.zeekadAlertPrecision);
  return (
    <tr className={isAll ? 'bg-slate-800/40 hover:bg-slate-800/60' : 'hover:bg-slate-800/35'}>
      <td className={`soc-td text-xs ${isAll ? '' : 'pl-8'}`}>
        {isAll ? (
          <>
            <CaptureName id={row.captureId} className="font-semibold text-slate-100" />
            <div className="mt-0.5 font-mono text-[11px] text-slate-400" data-raw="">
              {row.bundleId ?? '-'}
            </div>
            {children}
          </>
        ) : (
          <span className="text-[11px] text-slate-500">└</span>
        )}
      </td>
      <td className="soc-td text-xs">
        {isAll ? (
          <span className="font-semibold text-slate-100">모든 모델 합계</span>
        ) : (
          <DetectionModelName id={row.zeekadPickedBy} className="text-slate-200" />
        )}
      </td>
      <td className="soc-td soc-num text-xs text-slate-200">
        <div>인시던트 {formatNumber(row.incidents)}</div>
        <div className="text-slate-400">
          경보 발송 {formatNumber(row.alerted)} · 분석가 판정 {formatNumber(row.resolved)}
        </div>
      </td>
      {quiet ? (
        <td className="soc-td text-xs text-slate-500" colSpan={3}>
          분석가 판정 없음
        </td>
      ) : (
        <>
          <td className="soc-td text-xs">
            <div className="flex flex-wrap gap-1">
              <ResolutionCountBadge code="true_positive" count={row.truePositive ?? 0} tone="danger" />
              <ResolutionCountBadge code="false_positive" count={row.falsePositive ?? 0} tone="violet" />
              <ResolutionCountBadge code="benign" count={row.benign ?? 0} tone="positive" />
            </div>
          </td>
          <td className="soc-td min-w-[220px] text-xs">
            <div
              className="tabular-nums text-slate-100"
              title={resolved > 0 && precision === null ? sampleShortTooltip('정탐률', resolved, row.zeekadPrecision) : undefined}
            >
              {precisionSummaryText(row)}
            </div>
            {precision !== null && (
              <div className="mt-1.5">
                <SvgProgressBar value={precision} max={1} tone="cyan" label="정탐률" />
              </div>
            )}
          </td>
          <td className="soc-td min-w-[240px] text-xs">
            <div
              className="tabular-nums text-slate-100"
              title={
                alertResolved > 0 && alertPrecision === null
                  ? sampleShortTooltip('경보 정탐률', alertResolved, row.zeekadAlertPrecision)
                  : undefined
              }
            >
              {alertPrecisionSummaryText(row)}
            </div>
            {alertPrecision !== null && (
              <div className="mt-1.5">
                <SvgProgressBar value={alertPrecision} max={1} tone="emerald" label="경보 정탐률" />
              </div>
            )}
          </td>
        </>
      )}
    </tr>
  );
}
