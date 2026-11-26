import { ArrowRight, CheckCircle2, ClipboardCheck, GitPullRequestArrow, AlertTriangle, ShieldCheck, UserCheck } from 'lucide-react';
import type { AnalystReviewView, AssignmentHistoryItem, ResponseActionItem, StatusHistoryItem } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { labelText, reviewReasonText } from '../../utils/labels';
import { isReopenTransition, REOPENED_LABEL } from '../../utils/reopen';
import { CodeLabel, LookupText, ResolutionBadge, ReviewActionBadge } from '../StatusBadge';

export type TimelineEvent =
  | { kind: 'status'; at: string | null; item: StatusHistoryItem }
  | { kind: 'reviewRequested'; at: string | null; reason: string | null }
  | { kind: 'reviewDecided'; at: string | null; action: string | null; analyst: string | null }
  | { kind: 'reviewResumed'; at: string | null }
  | { kind: 'reviewResumeFailed'; at: string | null }
  | { kind: 'assignment'; at: string | null; item: AssignmentHistoryItem }
  | { kind: 'response'; at: string | null; item: ResponseActionItem };

/** 담당 변경 종류(T25): 미배정 → 사람 = 지정, 사람 → 미배정 = 해제, 사람 → 사람 = 변경 */
export function assignmentKindLabel(item: AssignmentHistoryItem): string {
  if (!item.from) return '담당 지정';
  if (!item.to) return '담당 해제';
  return '담당 변경';
}

function timeOf(iso: string | null): number {
  if (!iso) return Number.POSITIVE_INFINITY;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? Number.POSITIVE_INFINITY : t;
}

/**
 * 상태 변경 이력과 에스컬레이션 요청·결정·반영을 시간 순서 하나로 합친다(T19). 오래된 것이 위.
 * 시각이 없는 항목은 맨 뒤, 같은 시각은 원래 순서(상태 이력 → 요청 → 결정 → 반영 → 담당 변경 → 대응 조치)를 지킨다.
 * 반영 실패는 시각이 없어 결정 시각에 붙인다. T25: 담당 변경 이력도 같은 줄에 종류 표지로 넣는다.
 * T56: 대응 조치 기록(서버는 시간 역순으로 준다)은 기록한 시각으로 넣는다. 같은 시각의 기록끼리는 먼저 기록한 것이 위다.
 */
export function buildTimeline(
  statusHistory: StatusHistoryItem[],
  review: AnalystReviewView,
  assignmentHistory: AssignmentHistoryItem[] = [],
  responseActions: ResponseActionItem[] = [],
): TimelineEvent[] {
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
  for (const item of assignmentHistory) {
    events.push({ kind: 'assignment', at: item.changedAt, item });
  }
  for (const item of [...responseActions].reverse()) {
    events.push({ kind: 'response', at: item.recordedAt, item });
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
            {/* T53: 종결 → 분석 중은 다시 연 것이다(판정은 비워져 배지가 없다) */}
            {isReopenTransition(ev.item) && (
              <span className="rounded border border-cyan-500/40 px-1.5 text-[11px] text-cyan-200">{REOPENED_LABEL}</span>
            )}
            {ev.item.resolution && <ResolutionBadge resolution={ev.item.resolution} />}
          </div>
          {/* T21: 각 항목은 그 변경의 변경자·사유다. 결정 반영으로 생긴 항목의 사유는 결정 메모다(서버가 VIEWER에게 IPv4를 가린다). */}
          <div className="mt-1 text-slate-200">
            <span className="mr-1.5 text-[11px] text-slate-500">사유</span>
            <span className="whitespace-pre-line break-words">{ev.item.reason || '-'}</span>
          </div>
          <div className="mt-0.5 text-[11px] text-slate-400">
            변경자 <span data-raw="">{ev.item.actorDisplay ?? '-'}</span>
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
      return <div className="font-semibold text-slate-100">결정 반영됨(파이프라인)</div>;
    case 'reviewResumeFailed':
      return <div className="font-semibold text-amber-200">결정 반영 실패(관리자 확인 필요)</div>;
    case 'assignment':
      return (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="rounded border border-slate-700 px-1.5 text-[11px] text-slate-300">{assignmentKindLabel(ev.item)}</span>
            <span className="text-slate-400" data-raw="">
              {ev.item.from ? ev.item.from.displayName : '미배정'}
            </span>
            <ArrowRight className="h-3 w-3 text-slate-600" aria-hidden="true" />
            <span className="font-semibold text-slate-100" data-raw="">
              {ev.item.to ? ev.item.to.displayName : '미배정'}
            </span>
            {ev.item.reason === 'auto_on_start' && (
              <span className="text-[11px] text-slate-400">조사 시작 때 자동 지정</span>
            )}
          </div>
          <div className="mt-0.5 text-[11px] text-slate-400">
            변경자 <span data-raw="">{ev.item.actorDisplay ?? '-'}</span>
          </div>
        </>
      );
    case 'response':
      return (
        <>
          <div className="font-semibold text-slate-100">대응 조치 · {labelText('responseAction', ev.item.action)}</div>
          {/* 메모는 분석가·관리자에게만 온다(조회자 응답에는 없다) */}
          {ev.item.note && (
            <div className="mt-1 text-slate-200">
              <span className="mr-1.5 text-[11px] text-slate-500">메모</span>
              <span className="whitespace-pre-line break-words" data-raw="">
                {ev.item.note}
              </span>
            </div>
          )}
          <div className="mt-0.5 text-[11px] text-slate-400">
            기록자 <span data-raw="">{ev.item.actorDisplay ?? '-'}</span>
          </div>
        </>
      );
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
  assignment: UserCheck,
  response: ShieldCheck,
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
