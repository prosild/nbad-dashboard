/**
 * T29 기간 밖 안내: 고른 기간 밖에 같은 조건의 인시던트가 더 있으면 알리고 한 번에 전체 기간으로 넓힌다.
 * 큐·현황판이 같이 쓴다. 결과가 0건이면 각 화면의 빈 결과 안내가 이 내용을 대신 보인다(겹치지 않게).
 */
import { Info } from 'lucide-react';
import type { QueueSource, UnifiedQueueResponse } from '../types/api';
import { formatCompactDateTime, formatDateTime, formatNumber, formatRelativeTo } from '../utils/format';
import { captureInfo } from '../utils/labels';
import { parseOffsetIso } from '../utils/periodRange';
import { SOURCE_TYPE_LABEL } from './StatusBadge';

/** 기간 밖 수(없거나 기간 전체면 0) */
export function outsideCount(queue: Pick<UnifiedQueueResponse, 'outsidePeriod' | 'period'> | null | undefined): number {
  if (!queue || queue.period === 'all') return 0;
  return typeof queue.outsidePeriod === 'number' && queue.outsidePeriod > 0 ? queue.outsidePeriod : 0;
}

/**
 * 기간 (periodStart, periodEnd] 밖인가(T34: 응답의 실제 경계를 쓴다. 프리셋은 (기준 시각 − P, 기준 시각], 지정 기간은 받은 범위).
 * 탐지 시각이 없거나 경계가 없으면(전체 기간) 판단하지 않는다(false).
 */
export function isOutsidePeriod(
  iso: string | null | undefined,
  periodStart: string | null | undefined,
  periodEnd: string | null | undefined,
): boolean {
  const t = parseOffsetIso(iso);
  const s = parseOffsetIso(periodStart);
  const e = parseOffsetIso(periodEnd);
  if (t === null || s === null || e === null) return false;
  return t <= s || t > e;
}

/** 고른 수집원(캡처 하나 또는 수집원 종류)의 이름과 마지막 탐지 시각. 전체 수집원이면 null */
export function selectedSourceLastDetected(
  sources: QueueSource[],
  selectValue: string,
): { label: string; lastDetectedAt: string | null } | null {
  if (selectValue.startsWith('cap:')) {
    const id = selectValue.slice(4);
    const s = sources.find((x) => x.captureId === id);
    if (!s) return null;
    return { label: captureInfo(id).text, lastDetectedAt: s.lastDetectedAt ?? null };
  }
  if (selectValue.startsWith('src:')) {
    const type = selectValue.slice(4) as keyof typeof SOURCE_TYPE_LABEL;
    const members = sources.filter((x) => x.sourceType === type);
    if (members.length === 0 || !(type in SOURCE_TYPE_LABEL)) return null;
    return { label: SOURCE_TYPE_LABEL[type], lastDetectedAt: maxIso(members.map((m) => m.lastDetectedAt ?? null)) };
  }
  return null;
}

export function maxIso(values: (string | null | undefined)[]): string | null {
  let best: string | null = null;
  let bestT = -Infinity;
  for (const v of values) {
    if (!v) continue;
    const t = new Date(v).getTime();
    if (!Number.isNaN(t) && t > bestT) {
      bestT = t;
      best = v;
    }
  }
  return best;
}

/** "마지막 탐지 11-12 03:10(기준 시각 7일 전)" 같은 짧은 글(수집원 선택 목록·안내가 같이 쓴다) */
export function lastDetectedText(iso: string | null | undefined, anchor: string | null | undefined, snapshot: boolean): string {
  if (!iso) return '탐지 없음';
  const rel = anchor ? formatRelativeTo(iso, anchor) : '-';
  const after = anchor ? new Date(iso).getTime() > new Date(anchor).getTime() : false;
  const relText = after ? '기준 시각 뒤' : rel === '-' ? '' : snapshot ? `기준 시각 ${rel}` : rel;
  return `마지막 탐지 ${formatCompactDateTime(iso, anchor)}${relText ? `(${relText})` : ''}`;
}

/**
 * 결과가 있을 때(total > 0) 기간 밖 인시던트가 더 있으면 보이는 한 줄. 0건이면 빈 결과 안내가 대신한다.
 */
export function OutsidePeriodNotice({
  queue,
  onAllPeriod,
  className = '',
}: {
  queue: UnifiedQueueResponse | null;
  onAllPeriod: () => void;
  className?: string;
}) {
  const n = outsideCount(queue);
  if (!queue || queue.total === 0 || n === 0) return null;
  return (
    <div
      role="status"
      data-testid="outside-period"
      className={`flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-cyan-900/60 bg-cyan-950/30 px-3 py-1.5 text-xs text-slate-200 ${className}`}
    >
      <Info className="h-3.5 w-3.5 shrink-0 text-cyan-300" aria-hidden="true" />
      <span>
        선택한 기간 밖 인시던트 <span className="font-semibold tabular-nums text-slate-50">{formatNumber(n)}</span>건
      </span>
      {queue.newestOutsidePeriod && (
        <span className="text-slate-400" title={formatDateTime(queue.newestOutsidePeriod)}>
          (기간 밖 가장 최근 탐지{' '}
          <span className="tabular-nums text-slate-300">{formatCompactDateTime(queue.newestOutsidePeriod, queue.anchor)}</span>)
        </span>
      )}
      <span aria-hidden="true" className="text-slate-600">
        ·
      </span>
      <button
        type="button"
        onClick={onAllPeriod}
        className="rounded px-1 font-medium text-cyan-300 underline-offset-2 hover:text-cyan-200 hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
      >
        전체 기간 보기
      </button>
    </div>
  );
}

/**
 * 0건 안내에 덧붙일 글: 고른 수집원의 마지막 탐지가 기간 밖이면 그 사실, 아니면 기간 밖 수·가장 최근 탐지.
 * 버튼은 화면의 빈 결과 안내가 하나만 둔다.
 */
export function EmptyPeriodText({ queue, sourceValue }: { queue: UnifiedQueueResponse; sourceValue: string }) {
  const n = outsideCount(queue);
  const src = selectedSourceLastDetected(queue.sources ?? [], sourceValue);
  const srcOutside = src !== null && isOutsidePeriod(src.lastDetectedAt, queue.periodStart, queue.periodEnd);
  return (
    <>
      <p>
        이 기간에 탐지된 인시던트가 없습니다.
        {n > 0 && (
          <>
            {' '}
            선택한 기간 밖 인시던트 <span className="font-semibold tabular-nums text-slate-100">{formatNumber(n)}</span>건
          </>
        )}
        {queue.newestOutsidePeriod && (
          <>
            {n > 0 ? ' · ' : ' '}가장 최근 탐지:{' '}
            <span className="tabular-nums text-slate-100">{formatDateTime(queue.newestOutsidePeriod)}</span>
          </>
        )}
      </p>
      {srcOutside && src && (
        <p className="text-xs text-slate-400" data-testid="source-outside">
          고른 수집원 <span className="text-slate-200">{src.label}</span>의{' '}
          {lastDetectedText(src.lastDetectedAt, queue.anchor, queue.snapshot)}이 선택한 기간 밖입니다.
        </p>
      )}
    </>
  );
}

/** 0건 안내에서 "전체 기간 보기"를 보일까: 기간 밖 수가 있거나 기간 밖 가장 최근 탐지가 있으면 */
export function hasOutsideToShow(queue: UnifiedQueueResponse | null): boolean {
  return Boolean(queue && queue.period !== 'all' && (outsideCount(queue) > 0 || queue.newestOutsidePeriod));
}
