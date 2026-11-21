/**
 * 수집원 상태(T24): 센서 상태 배지(정상·지연·중단·실패·기록 없음)와 캡처 상태 배지(수집 중·지난 날짜·가져온 데이터·실패·기록 없음),
 * 현황판 패널(센서 행 + 가져온 데이터 행)과 운영 현황 표(모든 값).
 */
import { AlertTriangle, CheckCircle2, CircleDashed, Clock, Database, PauseCircle, Radio, XCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { CaptureRow, CaptureState, DashboardOverviewResponse, JobRef, SensorHealth, SensorRow } from '../../types/api';
import { formatDateTime, formatNumber, formatRelativeTo, formatSeconds } from '../../utils/format';
import { captureInfo, shortNameOf } from '../../utils/labels';
import { JobStatusBadge, SocBadge, type BadgeTone } from '../StatusBadge';

export const SENSOR_HEALTH_LABEL: Record<SensorHealth, string> = {
  ok: '정상',
  stale: '지연',
  down: '중단',
  failed: '실패',
  none: '기록 없음',
};

export const CAPTURE_STATE_LABEL: Record<CaptureState, string> = {
  active: '수집 중',
  ended: '지난 날짜',
  imported: '가져온 데이터',
  failed: '실패',
  none: '기록 없음',
};

const HEALTH_TONE: Record<SensorHealth, BadgeTone> = {
  ok: 'positive',
  stale: 'attention',
  down: 'attention',
  failed: 'attention',
  none: 'muted',
};

const HEALTH_ICON: Record<SensorHealth, React.ComponentType<{ className?: string }>> = {
  ok: CheckCircle2,
  stale: Clock,
  down: PauseCircle,
  failed: XCircle,
  none: CircleDashed,
};

/** 센서 상태 뜻(툴팁). 기준값은 응답의 staleAfterSeconds·downAfterSeconds */
export function sensorHealthTooltip(health: SensorHealth, staleSec: number, downSec: number, snapshot: boolean): string {
  const ref = snapshot ? '기준 시각' : '지금';
  const text: Record<SensorHealth, string> = {
    ok: `정상: 마지막 채점이 ${ref}에서 ${formatSeconds(staleSec)} 안입니다`,
    stale: `지연: 마지막 채점이 ${ref}에서 ${formatSeconds(staleSec)}을 넘었고 ${formatSeconds(downSec)} 안입니다`,
    down: `중단: 마지막 채점이 ${ref}에서 ${formatSeconds(downSec)}을 넘었습니다`,
    failed: '실패: 이 센서의 가장 최근 탐지 작업이 실패했습니다',
    none: '기록 없음: 이 센서의 성공한 탐지 작업이 없습니다',
  };
  return `${text[health]}${snapshot ? ' (기준 시각 기준)' : ''}`;
}

export const CAPTURE_STATE_TOOLTIP: Record<CaptureState, string> = {
  active: '수집 중: 이 센서의 가장 최근 채점이 이 캡처(날짜)에 있습니다',
  ended: '지난 날짜: 이 센서가 다음 날짜 캡처로 넘어갔습니다(센서 상태에 영향 없음)',
  imported: '가져온 데이터: 공개 데이터셋을 가져와 채점한 캡처입니다',
  failed: '실패: 이 캡처의 가장 최근 탐지 작업이 실패했습니다',
  none: '기록 없음: 이 캡처의 성공한 탐지 작업이 없습니다',
};

export function SensorHealthBadge({
  health,
  title,
}: {
  health: SensorHealth;
  title?: string;
}) {
  const Icon = HEALTH_ICON[health] ?? CircleDashed;
  return (
    <SocBadge tone={HEALTH_TONE[health] ?? 'muted'} title={title}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      {SENSOR_HEALTH_LABEL[health] ?? health}
    </SocBadge>
  );
}

export function CaptureStateBadge({ state }: { state: CaptureState }) {
  const tone: BadgeTone =
    state === 'failed' ? 'attention' : state === 'active' ? 'info' : state === 'imported' ? 'neutral' : 'muted';
  const Icon = state === 'failed' ? AlertTriangle : state === 'active' ? Radio : state === 'imported' ? Database : CircleDashed;
  return (
    <SocBadge tone={tone} title={CAPTURE_STATE_TOOLTIP[state]}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      {CAPTURE_STATE_LABEL[state] ?? state}
    </SocBadge>
  );
}

/** 상대 시각(기준 시각에서) + 툴팁 절대 시각 */
export function RelativeTime({
  iso,
  anchor,
  label,
  emptyTitle,
}: {
  iso: string | null | undefined;
  anchor: string | null | undefined;
  label: string;
  emptyTitle?: string;
}) {
  if (!iso) {
    return (
      <span className="text-slate-500" title={emptyTitle}>
        -
      </span>
    );
  }
  return (
    <span className="whitespace-nowrap tabular-nums" title={`${label} ${formatDateTime(iso)}`}>
      {formatRelativeTo(iso, anchor)}
    </span>
  );
}

export const NO_ACTIVITY_TITLE = '마지막 채점에 인시던트 없음';

/** 가져온 데이터 캡처 정렬: 실패 → 기록 없음 → 나머지(캡처 ID) */
export function sortImportedCaptures(rows: CaptureRow[]): CaptureRow[] {
  const rank = (r: CaptureRow) => (r.state === 'failed' ? 0 : r.state === 'none' ? 1 : 2);
  return [...rows].sort((a, b) => rank(a) - rank(b) || a.captureId.localeCompare(b.captureId));
}

function jobTitle(job: JobRef | null): string | undefined {
  if (!job) return undefined;
  return `최근 끝난 탐지 작업 ${job.jobId} · ${job.status ?? '-'} · 완료 ${formatDateTime(job.finishedAt)}${job.error ? `\n오류: ${job.error}` : ''}`;
}

/* ───────────────────────── 현황판 패널 ───────────────────────── */

export function SourceStatusList({
  overview,
  shortNames,
  period,
}: {
  overview: DashboardOverviewResponse;
  shortNames: Map<string, string>;
  period: string;
}) {
  const { sensors, captures, anchor, snapshot, staleAfterSeconds, downAfterSeconds } = overview;
  const imported = sortImportedCaptures(captures.filter((c) => c.sensorKey === null));
  if (sensors.length === 0 && imported.length === 0) {
    return <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">조건에 맞는 수집원이 없습니다.</div>;
  }
  return (
    <div className="space-y-3">
      {sensors.length > 0 && (
        <ul className="space-y-2" aria-label="센서">
          {sensors.map((s) => (
            <SensorItem
              key={s.sensorKey}
              sensor={s}
              captures={captures.filter((c) => c.sensorKey === s.sensorKey)}
              anchor={anchor}
              snapshot={snapshot}
              staleSec={staleAfterSeconds}
              downSec={downAfterSeconds}
              shortNames={shortNames}
              period={period}
            />
          ))}
        </ul>
      )}
      {imported.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-medium text-slate-400">가져온 데이터</div>
          <ul className="divide-y divide-slate-800/80" aria-label="가져온 데이터">
            {imported.map((c) => (
              <ImportedItem key={c.captureId} row={c} anchor={anchor} shortNames={shortNames} period={period} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function SensorItem({
  sensor,
  captures,
  anchor,
  snapshot,
  staleSec,
  downSec,
  shortNames,
  period,
}: {
  sensor: SensorRow;
  captures: CaptureRow[];
  anchor: string;
  snapshot: boolean;
  staleSec: number;
  downSec: number;
  shortNames: Map<string, string>;
  period: string;
}) {
  // "지난 날짜"로 접는 것은 ended뿐이다. 수집 중(active)과 실패(failed)·기록 없음(none) 캡처는 펼쳐 둔다
  // (오늘 캡처가 실패하면 서버 상태는 failed라 active로만 고르면 지난 날짜에 묻혔다, T24 review-2 M1).
  const active = captures.filter((c) => c.state !== 'ended');
  const others = captures.filter((c) => c.state === 'ended');
  return (
    <li className="soc-panel p-2.5 text-xs" data-sensor={sensor.sensorKey}>
      <Link
        to={`/incidents?period=${period}&source=live`}
        className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
        aria-label={`${sensor.label} 인시던트 목록`}
      >
        <span className="flex min-w-0 items-center gap-1.5 font-semibold text-slate-100">
          <Radio className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          {sensor.label}
        </span>
        <span title={jobTitle(sensor.latestJob)}>
          <SensorHealthBadge health={sensor.health} title={sensorHealthTooltip(sensor.health, staleSec, downSec, snapshot)} />
        </span>
        <span className="ml-auto whitespace-nowrap tabular-nums text-slate-300">
          인시던트 {formatNumber(sensor.total)} · <span className="text-rose-200">High {formatNumber(sensor.high)}</span>
        </span>
      </Link>
      <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[11px] text-slate-400">
        <dt>마지막 채점</dt>
        <dd className="text-slate-200">
          <RelativeTime iso={sensor.lastScoredAt} anchor={anchor} label="마지막 채점" />
        </dd>
        <dt>마지막 이상 활동</dt>
        <dd className="text-slate-200">
          <RelativeTime iso={sensor.lastActivityAt} anchor={anchor} label="마지막 이상 활동" emptyTitle={NO_ACTIVITY_TITLE} />
        </dd>
      </dl>
      {(active.length > 0 || others.length > 0) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
          {active.map((c) => (
            <CaptureChip key={c.captureId} row={c} shortNames={shortNames} period={period} />
          ))}
          {others.length > 0 && (
            <details className="group" data-ended-captures="">
              <summary className="cursor-pointer list-none text-slate-400 hover:text-slate-200">
                지난 날짜 {formatNumber(others.length)}개
              </summary>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {others.map((c) => (
                  <CaptureChip key={c.captureId} row={c} shortNames={shortNames} period={period} />
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </li>
  );
}

function CaptureChip({ row, shortNames, period }: { row: CaptureRow; shortNames: Map<string, string>; period: string }) {
  const info = captureInfo(row.captureId);
  const flagged = row.state === 'failed' || row.state === 'none';
  return (
    <Link
      to={`/incidents?period=${period}&captureId=${encodeURIComponent(row.captureId)}`}
      title={`${info.text} · 캡처 ID: ${row.captureId}\n${CAPTURE_STATE_TOOLTIP[row.state]}`}
      data-capture-chip={row.state}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-slate-200 ${
        row.state === 'failed' ? 'border-amber-500/60 hover:border-amber-400' : 'border-slate-700 hover:border-slate-500'
      }`}
    >
      <span aria-hidden="true">{shortNameOf(shortNames, row.captureId)}</span>
      {flagged && (
        <span className={row.state === 'failed' ? 'text-amber-200' : 'text-slate-400'} aria-hidden="true">
          {CAPTURE_STATE_LABEL[row.state]}
        </span>
      )}
      <span className="sr-only">{`${info.text} · 캡처 ID: ${row.captureId} · ${CAPTURE_STATE_LABEL[row.state]}`}</span>
      <span className="tabular-nums text-slate-400" aria-hidden="true">
        {formatNumber(row.total)}
      </span>
    </Link>
  );
}

function ImportedItem({
  row,
  anchor,
  shortNames,
  period,
}: {
  row: CaptureRow;
  anchor: string;
  shortNames: Map<string, string>;
  period: string;
}) {
  const info = captureInfo(row.captureId);
  return (
    <li>
      <Link
        to={`/incidents?period=${period}&captureId=${encodeURIComponent(row.captureId)}`}
        className="flex items-center gap-2 rounded px-1 py-1.5 text-xs transition hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
        title={`${info.text} · 캡처 ID: ${row.captureId}${row.latestJob?.error ? `\n오류: ${row.latestJob.error}` : ''}`}
        data-capture={row.captureId}
      >
        <span className="min-w-0 flex-1 truncate text-slate-100" aria-hidden="true">
          {shortNameOf(shortNames, row.captureId)}
        </span>
        <span className="sr-only">{`${info.text} · 캡처 ID: ${row.captureId}`}</span>
        <CaptureStateBadge state={row.state} />
        <span className="hidden w-16 text-right text-[11px] text-slate-400 sm:inline">
          <RelativeTime iso={row.lastScoredAt} anchor={anchor} label="마지막 채점" />
        </span>
        <span className="w-10 text-right tabular-nums text-slate-300" title="기간 안 인시던트">
          {formatNumber(row.total)}
        </span>
      </Link>
    </li>
  );
}

/* ───────────────────────── 운영 현황 표 ───────────────────────── */

export function SourceStatusTable({
  overview,
  shortNames,
}: {
  overview: DashboardOverviewResponse;
  shortNames: Map<string, string>;
}) {
  const { sensors, captures, anchor, snapshot, staleAfterSeconds, downAfterSeconds } = overview;
  const imported = sortImportedCaptures(captures.filter((c) => c.sensorKey === null));
  if (sensors.length === 0 && imported.length === 0) {
    return <div className="soc-panel px-4 py-6 text-center text-xs text-slate-400">조건에 맞는 수집원이 없습니다.</div>;
  }
  return (
    <div className="overflow-x-auto" data-scroll-box="">
      <table className="w-full border-collapse text-left text-xs">
        <thead>
          <tr>
            <th className="soc-th">수집원</th>
            <th className="soc-th">상태</th>
            <th className="soc-th">마지막 채점</th>
            <th className="soc-th">마지막 이상 활동</th>
            <th className="soc-th">최근 끝난 작업</th>
            <th className="soc-th text-right" title="기간 안에 탐지된 인시던트">인시던트</th>
            <th className="soc-th text-right">High</th>
            <th className="soc-th text-right">경보 발송</th>
            <th className="soc-th text-right" title="기간 안 실패한 탐지 작업(완료 시각, 없으면 시작 시각 기준)">실패 작업</th>
            <th className="soc-th">오류</th>
          </tr>
        </thead>
        <tbody>
          {sensors.map((s) => (
            <SensorTableRows
              key={s.sensorKey}
              sensor={s}
              captures={captures
                .filter((c) => c.sensorKey === s.sensorKey)
                .sort((a, b) => b.captureId.localeCompare(a.captureId))}
              anchor={anchor}
              snapshot={snapshot}
              staleSec={staleAfterSeconds}
              downSec={downAfterSeconds}
              shortNames={shortNames}
            />
          ))}
          {imported.map((c) => (
            <CaptureTableRow key={c.captureId} row={c} anchor={anchor} shortNames={shortNames} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JobCell({ job }: { job: JobRef | null }) {
  if (!job) return <span className="text-slate-500">-</span>;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={`완료 ${formatDateTime(job.finishedAt)} · 시작 ${formatDateTime(job.startedAt)}`}>
      {/* T27: 칸 머리가 "최근 끝난 작업"이라 숫자만 쓴다('#'은 인시던트 번호에만) */}
      <span className="tabular-nums text-slate-400" aria-label={`작업 ${job.jobId}`}>{job.jobId}</span>
      <JobStatusBadge status={job.status} />
    </span>
  );
}

function SensorTableRows({
  sensor,
  captures,
  anchor,
  snapshot,
  staleSec,
  downSec,
  shortNames,
}: {
  sensor: SensorRow;
  captures: CaptureRow[];
  anchor: string;
  snapshot: boolean;
  staleSec: number;
  downSec: number;
  shortNames: Map<string, string>;
}) {
  return (
    <>
      <tr className="bg-slate-800/40" data-sensor-row={sensor.sensorKey}>
        <td className="soc-td whitespace-nowrap font-semibold text-slate-100" title={`센서 패턴 ${sensor.sensorKey} · 캡처 ${sensor.captureCount}개`}>
          <span className="inline-flex items-center gap-1.5">
            <Radio className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            {sensor.label}
          </span>
        </td>
        <td className="soc-td">
          <SensorHealthBadge health={sensor.health} title={sensorHealthTooltip(sensor.health, staleSec, downSec, snapshot)} />
        </td>
        <td className="soc-td text-slate-200">
          <RelativeTime iso={sensor.lastScoredAt} anchor={anchor} label="마지막 채점" />
        </td>
        <td className="soc-td text-slate-200">
          <RelativeTime iso={sensor.lastActivityAt} anchor={anchor} label="마지막 이상 활동" emptyTitle={NO_ACTIVITY_TITLE} />
        </td>
        <td className="soc-td">
          <JobCell job={sensor.latestJob} />
        </td>
        <td className="soc-td soc-num">{formatNumber(sensor.total)}</td>
        <td className="soc-td soc-num">{formatNumber(sensor.high)}</td>
        <td className="soc-td soc-num">{formatNumber(sensor.alerted)}</td>
        <td className="soc-td soc-num">{formatNumber(sensor.failedJobs)}</td>
        <ErrorCell error={sensor.latestJob?.error} />
      </tr>
      {captures.map((c) => (
        <CaptureTableRow key={c.captureId} row={c} anchor={anchor} shortNames={shortNames} indent />
      ))}
    </>
  );
}

function CaptureTableRow({
  row,
  anchor,
  shortNames,
  indent = false,
}: {
  row: CaptureRow;
  anchor: string;
  shortNames: Map<string, string>;
  indent?: boolean;
}) {
  const info = captureInfo(row.captureId);
  return (
    <tr className="hover:bg-slate-800/35" data-capture-row={row.captureId}>
      <td className={`soc-td whitespace-nowrap ${indent ? 'pl-7' : ''}`} title={`${info.text} · 캡처 ID: ${row.captureId}`}>
        <span className="text-slate-100" aria-hidden="true">
          {shortNameOf(shortNames, row.captureId)}
        </span>
        <span className="sr-only">{`${info.text} · 캡처 ID: ${row.captureId}`}</span>
      </td>
      <td className="soc-td">
        <CaptureStateBadge state={row.state} />
      </td>
      <td className="soc-td text-slate-200">
        <RelativeTime iso={row.lastScoredAt} anchor={anchor} label="마지막 채점" />
      </td>
      <td className="soc-td text-slate-200">
        <RelativeTime iso={row.lastActivityAt} anchor={anchor} label="마지막 이상 활동" emptyTitle={NO_ACTIVITY_TITLE} />
      </td>
      <td className="soc-td">
        <JobCell job={row.latestJob} />
      </td>
      <td className="soc-td soc-num">{formatNumber(row.total)}</td>
      <td className="soc-td soc-num">{formatNumber(row.high)}</td>
      <td className="soc-td soc-num">{formatNumber(row.alerted)}</td>
      <td className="soc-td soc-num">{formatNumber(row.failedJobs)}</td>
      <ErrorCell error={row.latestJob?.error} />
    </tr>
  );
}

/**
 * 수집원 상태 표의 오류 칸(T25, T24 후속): 한 줄 말줄임, 전체 글은 툴팁. 서버가 VIEWER에게는 IPv4를 가린 글을 주므로
 * 툴팁도 가려진 글이다.
 */
function ErrorCell({ error }: { error: string | null | undefined }) {
  if (!error) {
    return <td className="soc-td text-amber-200">-</td>;
  }
  return (
    <td className="soc-td max-w-xs text-amber-200" title={error} data-error-cell="">
      <span className="block truncate">{error}</span>
    </td>
  );
}
