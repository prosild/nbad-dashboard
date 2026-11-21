import { ArrowRight, CheckCircle2, ClipboardCheck, GitPullRequestArrow, AlertTriangle } from 'lucide-react';
import type { AnalystReviewView, StatusHistoryItem } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { reviewReasonText } from '../../utils/labels';
import { CodeLabel, LookupText, ResolutionBadge, ReviewActionBadge } from '../StatusBadge';

export type TimelineEvent =
  | { kind: 'status'; at: string | null; item: StatusHistoryItem }
  | { kind: 'reviewRequested'; at: string | null; reason: string | null }
  | { kind: 'reviewDecided'; at: string | null; action: string | null; analyst: string | null }
  | { kind: 'reviewResumed'; at: string | null }
  | { kind: 'reviewResumeFailed'; at: string | null };

function timeOf(iso: string | null): number {
  if (!iso) return Number.POSITIVE_INFINITY;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? Number.POSITIVE_INFINITY : t;
}

/**
 * 상태 변경 이력과 에스컬레이션 요청·결정·반영을 시간 순서 하나로 합친다(T19 L7). 오래된 것이 위.
 * 시각이 없는 항목은 맨 뒤, 같은 시각은 원래 순서(상태 이력 → 요청 → 결정 → 반영)를 지킨다.
 * 반영 실패는 시각이 없어 결정 시각에 붙인다.
 */
export function buildTimeline(statusHistory: StatusHistoryItem[], review: AnalystReviewView): TimelineEvent[] {
  const events: TimelineEvent[] = statusHistory.map((item) => ({ kind: 'status', at: item.changedAt, item }));
  if (review.present) {
    events.push({ kind: 'reviewRequested', at: review.requestedAt, reason: review.reviewReason });
    if (review.reviewAction) {
      events.push({
        kind: 'reviewDecided',
        at: review.decidedAt,
        action: review.reviewAction,
        analyst: review.analystDisplay,
      });
      if (review.resumedAt) {
        events.push({ kind: 'reviewResumed', at: review.resumedAt });
      } else if (review.resumeFailed) {
        events.push({ kind: 'reviewResumeFailed', at: review.decidedAt });
      }
    }
  }
  return events
    .map((ev, idx) => ({ ev, idx }))
    .sort((a, b) => timeOf(a.ev.at) - timeOf(b.ev.at) || a.idx - b.idx)
    .map(({ ev }) => ev);
}

function EventBody({ ev }: { ev: TimelineEvent }) {
  switch (ev.kind) {
    case 'status':
      return (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-400">
              {ev.item.fromStatus ? <CodeLabel dict="incidentStatus" value={ev.item.fromStatus} /> : '생성'}
            </span>
            <ArrowRight className="h-3 w-3 text-slate-600" aria-hidden="true" />
            <span className="font-semibold text-slate-100">
              <CodeLabel dict="incidentStatus" value={ev.item.toStatus} />
            </span>
            {ev.item.resolution && <ResolutionBadge resolution={ev.item.resolution} />}
          </div>
          <div className="mt-1 text-slate-200">{ev.item.reason || '-'}</div>
          <div className="mt-0.5 text-[11px] text-slate-400">
            마지막 변경자 <span data-raw="">{ev.item.actorDisplay ?? '-'}</span>
          </div>
        </>
      );
    case 'reviewRequested':
      return (
        <>
          <div className="font-semibold text-slate-100">에스컬레이션 요청</div>
          <div className="mt-1 text-slate-300">
            <LookupText label={reviewReasonText(ev.reason)} />
          </div>
        </>
      );
    case 'reviewDecided':
      return (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-semibold text-slate-100">에스컬레이션 결정</span>
          <ReviewActionBadge action={ev.action} pending={false} />
          {ev.analyst && (
            <span className="text-[11px] text-slate-400">
              결정자 <span data-raw="">{ev.analyst}</span>
            </span>
          )}
        </div>
      );
    case 'reviewResumed':
      return <div className="font-semibold text-slate-100">결정이 자동 처리에 반영됨</div>;
    case 'reviewResumeFailed':
      return <div className="font-semibold text-amber-200">결정 반영 실패(관리자 확인 필요)</div>;
    default:
      return null;
  }
}

const ICONS = {
  status: GitPullRequestArrow,
  reviewRequested: ClipboardCheck,
  reviewDecided: CheckCircle2,
  reviewResumed: CheckCircle2,
  reviewResumeFailed: AlertTriangle,
} as const;

export function HistoryTimeline({
  events,
  emptyText,
  label = '이력 타임라인',
}: {
  events: TimelineEvent[];
  emptyText: string;
  label?: string;
}) {
  if (events.length === 0) {
    return <p className="text-xs text-slate-400">{emptyText}</p>;
  }
  return (
    <ol className="space-y-2" aria-label={label}>
      {events.map((ev, idx) => {
        const Icon = ICONS[ev.kind];
        return (
          <li key={`${ev.kind}-${ev.at ?? 'x'}-${idx}`} className="flex gap-2.5 rounded-lg border border-slate-800 bg-[#090f1d] p-2.5 text-xs">
            <Icon
              className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${ev.kind === 'reviewResumeFailed' ? 'text-amber-300' : 'text-slate-400'}`}
              aria-hidden="true"
            />
            <div className="min-w-0 flex-1">
              <div className="mb-0.5 text-[11px] tabular-nums text-slate-500">{formatDateTime(ev.at)}</div>
              <EventBody ev={ev} />
            </div>
          </li>
        );
      })}
    </ol>
  );
}
