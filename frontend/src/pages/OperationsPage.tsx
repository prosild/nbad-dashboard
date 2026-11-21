import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, BarChart3, Bell, ChevronDown, ChevronRight, Cpu, Info, Layers, MessageSquare } from 'lucide-react';
import { ApiError } from '../api/client';
import { operationsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import {
  CaptureName,
  CodeLabel,
  DetectionModelName,
  JobStatusBadge,
  SocBadge,
  type BadgeTone,
} from '../components/StatusBadge';
import { SvgProgressBar } from '../components/SvgProgressBar';
import type { FeedbackSummaryRecord, OperationsApiResponse } from '../types/api';
import { formatDateTime, formatNumber } from '../utils/format';
import { captureInfo } from '../utils/labels';
import {
  SAMPLE_MIN,
  alertPrecisionSummaryText,
  effectiveAlertedResolved,
  failedJobCount,
  isAllModelRow,
  isFailedJob,
  isQuietRow,
  latestJobPerCapture,
  latestSlackSummary,
  latestSucceededJob,
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

export function OperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<OperationsApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const captureId = searchParams.get('captureId') ?? '';

  const loadOperations = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await operationsApi.get(captureId || undefined);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '운영 현황을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [captureId]);

  useEffect(() => {
    void loadOperations();
  }, [loadOperations]);

  function handleCaptureChange(value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set('captureId', value);
    else next.delete('captureId');
    setSearchParams(next);
  }

  const groups = useMemo(() => groupSummaries(data?.feedbackSummaries ?? []), [data]);
  const status = useMemo(() => {
    if (!data) return null;
    const { allRows } = selectSummaryRows(data.feedbackSummaries, data.jobs);
    const latestJobs = latestJobPerCapture(data.jobs);
    return {
      totalsRow: totalsAsRow(sumAllRows(allRows)),
      latestJobs,
      latestFailed: latestJobs.filter(isFailedJob).length,
      failedAll: failedJobCount(data.jobs),
      latestOk: latestSucceededJob(data.jobs),
      latestSlack: latestSlackSummary(data.slackSummaries),
    };
  }, [data]);

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
    <AppShell title="운영 현황" subtitle="파이프라인·탐지 모델 판정·경보 상태와 판정 집계를 확인합니다">
      <div className="space-y-4">
        <section className="soc-card flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <label htmlFor="ops-capture" className="text-xs font-medium text-slate-400">
              캡처
            </label>
            <select
              id="ops-capture"
              value={captureId}
              onChange={(e) => handleCaptureChange(e.target.value)}
              className="soc-select py-1.5 text-xs"
            >
              <option value="">열람 허용 캡처 전체</option>
              {(data?.allowedCaptures ?? []).map((cap) => {
                const info = captureInfo(cap);
                return (
                  <option key={cap} value={cap} title={info.tooltip}>
                    {info.text}
                  </option>
                );
              })}
            </select>
          </div>
          <div className="flex flex-wrap gap-3 text-xs tabular-nums text-slate-400">
            <span>탐지 작업 {formatNumber(data?.jobs.length ?? 0)}건</span>
            <span>· 모델 버전 {formatNumber(data?.bundles.length ?? 0)}개</span>
            <span>· Slack 일일 요약 {formatNumber(data?.slackSummaries.length ?? 0)}건</span>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadOperations()} />}

        {loading && !data ? (
          <LoadingPanel label="운영 현황을 불러오는 중..." />
        ) : (
          <>
            {status && (
              <section aria-label="상태 요약" className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <StatusCard icon={Activity} title="파이프라인" tone={status.latestFailed > 0 ? 'attention' : 'ok'}>
                  <div className="text-base font-semibold text-slate-50">
                    {status.latestJobs.length === 0
                      ? '탐지 작업 없음'
                      : status.latestFailed > 0
                        ? `최근 작업 실패 ${formatNumber(status.latestFailed)}개 캡처`
                        : `최근 작업 모두 완료(${formatNumber(status.latestJobs.length)}개 캡처)`}
                  </div>
                  <div className="text-xs text-slate-400" title="가장 최근에 성공한 탐지 작업의 완료 시각">
                    데이터 기준 <span className="tabular-nums text-slate-300">{formatDateTime(status.latestOk?.finishedAt)}</span>
                  </div>
                  <div className="text-xs text-slate-400" title="열람 허용 캡처의 탐지 작업 기록 전체 기준">
                    실패한 탐지 작업 <span className="tabular-nums text-slate-300">{formatNumber(status.failedAll)}건</span>
                  </div>
                </StatusCard>
                <StatusCard icon={Cpu} title="모델 판정" tone="neutral">
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
                    인시던트 <span className="tabular-nums text-slate-300">{formatNumber(status.totalsRow.incidents)}건</span> · 미판정{' '}
                    <span className="tabular-nums text-slate-300">
                      {formatNumber((status.totalsRow.incidents ?? 0) - (status.totalsRow.resolved ?? 0))}건
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">캡처마다 최신 탐지 작업의 모든 모델 합계 기준</div>
                </StatusCard>
                <StatusCard icon={Bell} title="경보" tone="neutral">
                  <div className="text-base font-semibold text-slate-50">
                    경보 발송 {formatNumber(status.totalsRow.alerted)}건
                  </div>
                  <div className="text-xs text-slate-300">{alertPrecisionSummaryText(status.totalsRow)}</div>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    최근 일일 요약{' '}
                    <span className="tabular-nums text-slate-300">
                      {status.latestSlack
                        ? formatDateTime(status.latestSlack.deliveredAt ?? status.latestSlack.createdAt)
                        : '기록 없음'}
                    </span>
                    {status.latestSlack?.dryRunOrRecorded && <SocBadge tone="muted">Dry-run</SocBadge>}
                  </div>
                </StatusCard>
              </section>
            )}

            <section className="soc-card space-y-3 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                  <BarChart3 className="h-4 w-4 text-slate-400" />
                  분석가 판정 집계
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
                        <th className="soc-th text-right">인시던트 / 경보 발송 / 판정</th>
                        <th className="soc-th">판정 분포</th>
                        <th className="soc-th">정탐률</th>
                        <th className="soc-th">경보 정탐률 · 경보 판정률</th>
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

            <CollapsibleSection icon={Activity} title="탐지 작업 기록" count={`${formatNumber(data?.jobs.length ?? 0)}건`}>
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
                          탐지 작업 기록이 없습니다.
                        </td>
                      </tr>
                    ) : (
                      (data?.jobs ?? []).map((job) => (
                        <tr key={job.jobId} className="hover:bg-slate-800/35">
                          <td
                            className="soc-td whitespace-nowrap text-xs font-semibold tabular-nums text-slate-100"
                            title={`탐지 작업 #${job.jobId}`}
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
                          · 판{' '}
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
              count={`${formatNumber(data?.slackSummaries.length ?? 0)}건`}
            >
              {(data?.slackSummaries ?? []).length === 0 ? (
                <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">Slack 일일 요약 기록이 없습니다.</div>
              ) : (
                <div className="space-y-3">
                  {(data?.slackSummaries ?? []).map((summary, idx) => (
                    <div key={`${summary.jobId ?? idx}-${summary.captureId ?? idx}`} className="soc-panel space-y-2 p-4 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <CaptureName id={summary.captureId} className="font-semibold text-slate-100" />
                          {summary.jobId !== null && (
                            <span className="text-[11px] text-slate-500" title={summary.zeekadMessageVersion ? `메시지 형식 ${summary.zeekadMessageVersion}` : undefined}>
                              탐지 작업 #{summary.jobId}
                            </span>
                          )}
                          {summary.dryRunOrRecorded && <SocBadge tone="muted">Dry-run</SocBadge>}
                        </div>
                        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
                          {formatDateTime(summary.deliveredAt ?? summary.createdAt)}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        채널 <span className="font-mono text-slate-300">{summary.payloadChannel ?? '-'}</span> · 전송 결과{' '}
                        <CodeLabel dict="slackDeliveryStatus" value={summary.zeekadDeliveryStatus} className="text-slate-300" />
                      </div>
                      {summary.payloadTextPreview && (
                        <p className="whitespace-pre-wrap rounded border border-slate-800 bg-[#090f1d] p-3 text-xs text-slate-200">
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
          경보 발송 {formatNumber(row.alerted)} · 판정 {formatNumber(row.resolved)}
        </div>
      </td>
      {quiet ? (
        <td className="soc-td text-xs text-slate-500" colSpan={3}>
          판정 없음
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
