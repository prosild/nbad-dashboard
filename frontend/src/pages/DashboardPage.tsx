import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, Bell, Cpu, Database, RefreshCw } from 'lucide-react';
import { ApiError } from '../api/client';
import { operationsApi, reviewsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { CaptureName, CodeLabel, DetectionModelName, JobStatusBadge, SocBadge } from '../components/StatusBadge';
import type { FeedbackSummaryRecord, OperationsApiResponse } from '../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime, formatNumber } from '../utils/format';
import { captureInfo, captureText } from '../utils/labels';
import {
  SAMPLE_SHORT_LABEL,
  failedJobCount,
  latestJobPerCapture,
  latestSlackSummary,
  latestSucceededJob,
  modelStatuses,
  precisionValue,
  ratioPercent,
  sampleShortTooltip,
  selectSummaryRows,
  sumAllRows,
} from '../utils/operations';

/** 탐지 작업 범위 안내(인계 M7): 툴팁에 쓴다 */
const JOB_SCOPE_NOTE = '열람 허용 캡처의 탐지 작업 기록 전체 기준';

interface DashboardState {
  operations: OperationsApiResponse | null;
  /** 에스컬레이션 대기 건수. 불러오지 못하면 null */
  pendingReviews: number | null;
  loadedAt: string | null;
}

export function DashboardPage() {
  const [state, setState] = useState<DashboardState>({ operations: null, pendingReviews: null, loadedAt: null });
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [reviewError, setReviewError] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    setReviewError(false);
    // 현황판은 API 두 번으로 그린다: 운영 현황(허용 캡처 전체) + 에스컬레이션 대기(캡처 없이 부르면 허용 캡처 전체).
    const [ops, reviews] = await Promise.allSettled([operationsApi.get(), reviewsApi.list(undefined, true)]);
    const loadedAt = new Date().toISOString();
    if (ops.status === 'rejected') {
      setErrorMsg(ops.reason instanceof ApiError ? ops.reason.message : '관제 현황을 불러오지 못했습니다.');
    }
    if (reviews.status === 'rejected') {
      setReviewError(true);
    }
    setState((prev) => ({
      operations: ops.status === 'fulfilled' ? ops.value : prev.operations,
      pendingReviews:
        reviews.status === 'fulfilled' ? reviews.value.reviews.filter((r) => r.pending !== false).length : null,
      loadedAt,
    }));
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const ops = state.operations;
  const view = useMemo(() => {
    if (!ops) return null;
    const { allRows, modelRows } = selectSummaryRows(ops.feedbackSummaries, ops.jobs);
    return {
      allRows,
      totals: sumAllRows(allRows),
      models: modelStatuses(modelRows),
      latestJobs: latestJobPerCapture(ops.jobs),
      latestOk: latestSucceededJob(ops.jobs),
      failed: failedJobCount(ops.jobs),
      latestSlack: latestSlackSummary(ops.slackSummaries),
    };
  }, [ops]);

  return (
    <AppShell title="현황판" subtitle="파이프라인·탐지 모델·경보 상태를 한 화면에서 확인합니다">
      <div className="space-y-4">
        <BaselineStrip
          dataAsOf={view?.latestOk?.finishedAt ?? null}
          failed={view?.failed ?? null}
          loadedAt={state.loadedAt}
          loading={loading}
          onRefresh={() => void load()}
        />

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void load()} />}

        {loading && !ops ? (
          <LoadingPanel label="관제 현황을 불러오는 중..." />
        ) : !view ? null : (
          <>
            <KpiRow totals={view.totals} pendingReviews={state.pendingReviews} reviewError={reviewError} />

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <CapturePanel rows={view.allRows} className="xl:col-span-3" />
              <ModelPanel models={view.models} className="xl:col-span-2" />
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
              <PipelinePanel jobs={view.latestJobs} className="xl:col-span-3" />
              <AlertPanel
                latest={view.latestSlack}
                count={ops?.slackSummaries.length ?? 0}
                alerted={view.totals.alerted}
                className="xl:col-span-2"
              />
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}

function BaselineStrip({
  dataAsOf,
  failed,
  loadedAt,
  loading,
  onRefresh,
}: {
  dataAsOf: string | null;
  failed: number | null;
  loadedAt: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
    <section
      aria-label="기준 시각"
      className="soc-card flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5 text-xs text-slate-400"
    >
      <span title={`가장 최근에 성공한 탐지 작업의 완료 시각(${JOB_SCOPE_NOTE})`}>
        데이터 기준{' '}
        <span className="font-semibold tabular-nums text-slate-100" data-testid="data-as-of">
          {formatDateTime(dataAsOf)}
        </span>{' '}
        {DISPLAY_TIME_ZONE_LABEL}
      </span>
      <span title={`실패로 끝난 탐지 작업 수(${JOB_SCOPE_NOTE})`}>
        실패한 탐지 작업{' '}
        {failed === null ? (
          <span className="text-slate-500">-</span>
        ) : (
          <span className={`font-semibold tabular-nums ${failed > 0 ? 'text-amber-300' : 'text-slate-100'}`}>
            {formatNumber(failed)}건
          </span>
        )}
      </span>
      <span className="ml-auto flex items-center gap-3">
        <span>
          불러온 시각 <span className="tabular-nums text-slate-300">{formatDateTime(loadedAt)}</span>
        </span>
        <button type="button" onClick={onRefresh} disabled={loading} className="soc-btn-secondary py-1 text-xs">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
          새로 고침
        </button>
      </span>
    </section>
  );
}

function KpiCard({
  to,
  label,
  value,
  sub,
  tone = 'default',
  title,
}: {
  to: string;
  label: string;
  value: string;
  sub?: React.ReactNode;
  tone?: 'default' | 'notice' | 'attention';
  title?: string;
}) {
  const valueTone = tone === 'attention' ? 'text-amber-200' : tone === 'notice' ? 'text-cyan-200' : 'text-slate-50';
  return (
    <Link
      to={to}
      title={title}
      className="soc-card block px-4 py-3 transition hover:border-slate-600 hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
    >
      <div className="text-xs text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-bold tabular-nums ${valueTone}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-400">{sub}</div>}
    </Link>
  );
}

function KpiRow({
  totals,
  pendingReviews,
  reviewError,
}: {
  totals: ReturnType<typeof sumAllRows>;
  pendingReviews: number | null;
  reviewError: boolean;
}) {
  return (
    <section aria-label="핵심 지표" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <KpiCard
        to="/incidents?period=all"
        label="전체 인시던트"
        value={formatNumber(totals.incidents)}
        sub="캡처마다 최신 탐지 작업 기준"
        title="캡처별 '모든 모델 합계'의 인시던트 수를 더한 값입니다(기간 없음). 누르면 기간 '전체'의 인시던트 목록으로 갑니다."
      />
      <KpiCard
        to="/incidents?period=all&alerted=true"
        label="경보 발송"
        value={formatNumber(totals.alerted)}
        tone={totals.alerted > 0 ? 'notice' : 'default'}
        sub={totals.incidents > 0 ? `인시던트의 ${ratioPercent(totals.alerted / totals.incidents)}` : undefined}
        title="상태 알림이 아닌 Slack 발송 기록이 있는 인시던트 수입니다(기간 없음). 누르면 기간 '전체'의 인시던트 목록에서 경보 발송 인시던트만 봅니다."
      />
      <KpiCard
        to="/operations"
        label="판정 완료"
        value={formatNumber(totals.resolved)}
        sub={`미판정 ${formatNumber(totals.unresolved)}건`}
        title="판정(정탐·오탐·정상)이 기록된 인시던트 수입니다. 누르면 운영 현황의 판정 집계로 갑니다."
      />
      <KpiCard
        to="/reviews?pendingOnly=true"
        label="에스컬레이션 대기"
        value={pendingReviews === null ? '-' : formatNumber(pendingReviews)}
        tone={pendingReviews !== null && pendingReviews > 0 ? 'attention' : 'default'}
        sub={reviewError ? '불러오지 못했습니다' : '분석가 검토를 기다리는 건'}
        title="누르면 에스컬레이션 대기 목록으로 갑니다."
      />
    </section>
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

/** 캡처별 인시던트·경보 발송·판정 막대(순수 SVG, 가장 큰 인시던트 수 기준 길이) */
function CaptureBars({ incidents, alerted, resolved, max }: { incidents: number; alerted: number; resolved: number; max: number }) {
  const scale = (v: number) => (max > 0 ? Number(((Math.max(0, v) / max) * 100).toFixed(2)) : 0);
  return (
    <svg
      viewBox="0 0 100 14"
      preserveAspectRatio="none"
      className="h-3.5 w-full"
      role="img"
      aria-label={`인시던트 ${incidents}건, 경보 발송 ${alerted}건, 판정 ${resolved}건`}
    >
      <rect x={0} y={0} width={100} height={4} rx={2} fill="#0f172a" />
      <rect x={0} y={0} width={scale(incidents)} height={4} rx={2} fill="#94a3b8" />
      <rect x={0} y={5} width={100} height={4} rx={2} fill="#0f172a" />
      <rect x={0} y={5} width={scale(alerted)} height={4} rx={2} fill="#22d3ee" />
      <rect x={0} y={10} width={100} height={4} rx={2} fill="#0f172a" />
      <rect x={0} y={10} width={scale(resolved)} height={4} rx={2} fill="#a78bfa" />
    </svg>
  );
}

function CapturePanel({ rows, className = '' }: { rows: FeedbackSummaryRecord[]; className?: string }) {
  const max = rows.reduce((m, r) => Math.max(m, r.incidents ?? 0), 0);
  return (
    <section className={`soc-card space-y-3 p-4 ${className}`} aria-label="캡처별 현황">
      <PanelHeader icon={Database} title="캡처별 현황" note="막대: 인시던트 · 경보 발송 · 판정" />
      {rows.length === 0 ? (
        <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">표시할 캡처 집계가 없습니다.</div>
      ) : (
        <ul className="divide-y divide-slate-800/80">
          {rows.map((row) => (
            <li key={`${row.captureId}-${row.bundleId}`}>
              <Link
                to={`/incidents?period=all&captureId=${encodeURIComponent(row.captureId ?? '')}`}
                aria-label={`${captureText(row.captureId)} 인시던트 목록`}
                className="grid grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto] items-center gap-3 rounded px-1 py-2 text-xs transition hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
              >
                <CaptureName id={row.captureId} className="truncate font-medium text-slate-100" />
                <CaptureBars
                  incidents={row.incidents ?? 0}
                  alerted={row.alerted ?? 0}
                  resolved={row.resolved ?? 0}
                  max={max}
                />
                <span className="whitespace-nowrap tabular-nums text-slate-300">
                  {formatNumber(row.incidents)} · <span className="text-cyan-200">{formatNumber(row.alerted)}</span> ·{' '}
                  <span className="text-violet-200">{formatNumber(row.resolved)}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function PrecisionCell({ resolved, precision }: { resolved: number; precision: number | null }) {
  if (resolved <= 0) {
    return <span className="text-slate-500">판정 없음</span>;
  }
  const value = precisionValue(resolved, precision);
  if (value === null) {
    return (
      <span className="text-slate-400" title={sampleShortTooltip('정탐률', resolved, precision)}>
        {SAMPLE_SHORT_LABEL}
      </span>
    );
  }
  return <span className="font-semibold text-slate-100">{ratioPercent(value)}</span>;
}

function ModelPanel({ models, className = '' }: { models: ReturnType<typeof modelStatuses>; className?: string }) {
  return (
    <section className={`soc-card space-y-3 p-4 ${className}`} aria-label="탐지 모델 상태">
      <PanelHeader icon={Cpu} title="탐지 모델 상태" note="주 탐지 기준" />
      {models.length === 0 ? (
        <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">탐지 모델별 집계가 없습니다.</div>
      ) : (
        // T26: 휴대폰 폭에서 표가 페이지를 넓히지 않게 가로 스크롤 상자로 감싸고, 긴 머리글은 md 미만에서 줄인다(뜻은 툴팁).
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr>
                <th className="soc-th">탐지 모델</th>
                <th className="soc-th text-right" title="주 탐지 기준 인시던트 수: 이 모델이 주 탐지 모델인 인시던트 수(교차 탐지를 빼지 않음)">
                  <span className="md:hidden">인시던트</span>
                  <span className="hidden md:inline">주 탐지 기준 인시던트 수</span>
                </th>
                <th className="soc-th text-right">판정</th>
                <th className="soc-th text-right">정탐률</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => (
                <tr key={m.model}>
                  <td className="soc-td">
                    <DetectionModelName id={m.model} className="text-slate-100" />
                  </td>
                  <td className="soc-td soc-num">{formatNumber(m.incidents)}</td>
                  <td className="soc-td soc-num">{formatNumber(m.resolved)}</td>
                  <td className="soc-td text-right tabular-nums">
                    <PrecisionCell resolved={m.resolved} precision={m.precision} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** 휴대폰 폭 완료 시각: 연도·초를 뺀 `MM-DD HH:mm`(KST). 형식이 다르면 그대로 둔다. */
function shortDateTime(iso: string | null | undefined): string {
  const full = formatDateTime(iso);
  return full.length === 19 ? full.slice(5, 16) : full;
}

/**
 * 캡처 표시 이름을 공백에서만 줄바꿈한다(T26). `2026-11-19`·`CIC-IDS2017`처럼 하이픈이 든 조각 안에서는 끊지 않는다.
 * 등록되지 않은 캡처 ID는 원문 그대로(공백이 없어 좁은 칸을 넘지 않게 어디서든 끊는다).
 */
function CaptureNameWords({ id, className = '' }: { id: string | null | undefined; className?: string }) {
  const info = captureInfo(id);
  if (!info.known) {
    return <CaptureName id={id} className={`break-all ${className}`} />;
  }
  return (
    <span className={className} title={info.tooltip || undefined} data-capture-name="">
      {info.text.split(' ').map((word, idx) => (
        <Fragment key={idx}>
          {idx > 0 && ' '}
          <span className="whitespace-nowrap">{word}</span>
        </Fragment>
      ))}
    </span>
  );
}

function jobStatusTitle(job: ReturnType<typeof latestJobPerCapture>[number]): string {
  return job.error ? `오류: ${job.error}` : `탐지 작업 #${job.jobId}`;
}

/**
 * 파이프라인(캡처마다 최근 탐지 작업).
 * T26: md 미만은 카드 목록(캡처 이름 · 상태 / 짧은 완료 시각 · 모델 버전 보조 줄)으로 안쪽 가로 스크롤 없이 읽는다.
 * md 이상은 지금 표 그대로이고, 가로 스크롤 상자로 감싼다.
 */
function PipelinePanel({ jobs, className = '' }: { jobs: ReturnType<typeof latestJobPerCapture>; className?: string }) {
  return (
    <section className={`soc-card space-y-3 p-4 ${className}`} aria-label="파이프라인">
      <PanelHeader icon={Activity} title="파이프라인" note="캡처마다 최근 탐지 작업" />
      {jobs.length === 0 ? (
        <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">탐지 작업 기록이 없습니다.</div>
      ) : (
        <>
          <ul className="divide-y divide-slate-800/80 md:hidden" aria-label="파이프라인 목록">
            {jobs.map((job) => (
              <li key={job.jobId} className="py-2 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <CaptureNameWords id={job.captureId} className="min-w-0 text-slate-100" />
                  <span className="shrink-0" title={jobStatusTitle(job)}>
                    <JobStatusBadge status={job.status} />
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px]">
                  <span className="tabular-nums text-slate-300" title={`완료 시각 ${formatDateTime(job.finishedAt)}`}>
                    완료 {shortDateTime(job.finishedAt)}
                  </span>
                  <span className="break-all font-mono text-slate-500" title="모델 버전" data-raw="">
                    {job.bundleId}
                  </span>
                </div>
              </li>
            ))}
          </ul>
          <div className="hidden overflow-x-auto md:block">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr>
                  <th className="soc-th">캡처</th>
                  <th className="soc-th">상태</th>
                  <th className="soc-th">완료 시각</th>
                  <th className="soc-th">모델 버전</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.jobId}>
                    <td className="soc-td">
                      <CaptureName id={job.captureId} className="text-slate-100" />
                    </td>
                    <td className="soc-td" title={jobStatusTitle(job)}>
                      <JobStatusBadge status={job.status} />
                    </td>
                    <td className="soc-td whitespace-nowrap tabular-nums text-slate-300">{formatDateTime(job.finishedAt)}</td>
                    <td className="soc-td font-mono text-slate-400" data-raw="">
                      {job.bundleId}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function AlertPanel({
  latest,
  count,
  alerted,
  className = '',
}: {
  latest: ReturnType<typeof latestSlackSummary>;
  count: number;
  alerted: number;
  className?: string;
}) {
  return (
    <section className={`soc-card space-y-3 p-4 ${className}`} aria-label="경보">
      <PanelHeader icon={Bell} title="경보" note="Slack 일일 요약" />
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
        <dt className="text-slate-400">경보 발송 인시던트</dt>
        <dd className="tabular-nums text-slate-100">{formatNumber(alerted)}건</dd>
        <dt className="text-slate-400">최근 일일 요약</dt>
        <dd className="tabular-nums text-slate-100">
          {latest ? formatDateTime(latest.deliveredAt ?? latest.createdAt) : '기록 없음'}
          {latest?.captureId && (
            <span className="ml-2 text-slate-400">
              <CaptureName id={latest.captureId} />
            </span>
          )}
        </dd>
        <dt className="text-slate-400">발송 방식</dt>
        <dd className="flex flex-wrap items-center gap-1.5">
          {latest ? (
            <>
              {latest.dryRunOrRecorded ? (
                <SocBadge tone="muted" title="Slack에 실제로 보내지 않고 기록만 남겼습니다">
                  Dry-run
                </SocBadge>
              ) : (
                <CodeLabel dict="slackDeliveryMode" value={latest.zeekadDeliveryMode} className="text-slate-100" />
              )}
              <span className="text-slate-400">
                · 전송 결과{' '}
                <CodeLabel dict="slackDeliveryStatus" value={latest.zeekadDeliveryStatus} className="text-slate-300" />
              </span>
            </>
          ) : (
            <span className="text-slate-500">-</span>
          )}
        </dd>
        <dt className="text-slate-400">일일 요약 기록</dt>
        <dd className="tabular-nums text-slate-100">{formatNumber(count)}건</dd>
      </dl>
    </section>
  );
}
