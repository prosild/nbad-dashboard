import { AlarmClock, UserX } from 'lucide-react';
import type { AssigneeRef } from '../../types/api';
import { formatDateTime, formatElapsed, secondsBetween } from '../../utils/format';
import { isClosedStatus } from '../../utils/triage';
import { SocBadge } from '../StatusBadge';

/** 착수 지연 표지 툴팁(docs/ui-terminology.md "착수 지연") */
export const ACK_OVERDUE_TOOLTIP =
  '실습망 신규 인시던트가 우선순위별 착수 목표(탐지 뒤 High 30분·Medium 4시간·Low 24시간, 기본값)를 넘겼습니다. 조사를 시작하면 풀립니다.';

/** 빨간 "착수 지연" 표지. 색만이 아니라 글자로 보인다(T25). */
export function AckOverdueBadge({ dueAt }: { dueAt?: string | null }) {
  return (
    <SocBadge tone="danger" title={dueAt ? `${ACK_OVERDUE_TOOLTIP}\n착수 목표 ${formatDateTime(dueAt)}` : ACK_OVERDUE_TOOLTIP}>
      <AlarmClock className="h-3 w-3" aria-hidden="true" />
      착수 지연
    </SocBadge>
  );
}

/** 담당자 이름. 없으면 흐린 "미배정", 비활성 계정이면 "비활성" 표지를 붙인다. */
export function AssigneeName({
  assignee,
  className = '',
}: {
  assignee: AssigneeRef | null | undefined;
  className?: string;
}) {
  if (!assignee) {
    return <span className={`text-slate-500 ${className}`}>미배정</span>;
  }
  return (
    <span className={`inline-flex min-w-0 items-center gap-1 ${className}`} title={`${assignee.displayName} (${assignee.username})`}>
      <span className="min-w-0 truncate text-slate-200" data-raw="">
        {assignee.displayName}
      </span>
      {!assignee.enabled && (
        <span className="inline-flex shrink-0 items-center gap-0.5 rounded border border-slate-700 px-1 text-[10px] text-slate-400">
          <UserX className="h-2.5 w-2.5" aria-hidden="true" />
          비활성
        </span>
      )}
    </span>
  );
}

/**
 * 탐지 뒤 경과(미종결) 또는 처리 시간(종결 = 종결 시각 − 탐지 시각, 종결은 끝 상태라 상태 갱신 시각이 종결 시각이다).
 * 기준 시각(anchor)으로 센다(고정 스냅샷이면 그 기준 시각).
 */
export function elapsedText(
  detectedAt: string | null | undefined,
  status: string | null | undefined,
  statusUpdatedAt: string | null | undefined,
  anchor: string | null | undefined,
): { kind: 'elapsed' | 'handled'; text: string } | null {
  if (!detectedAt) return null;
  if (isClosedStatus(status)) {
    const s = secondsBetween(detectedAt, statusUpdatedAt);
    return s === null || s < 0 ? null : { kind: 'handled', text: `처리 ${formatElapsed(s)}` };
  }
  const s = secondsBetween(detectedAt, anchor);
  return s === null || s < 0 ? null : { kind: 'elapsed', text: formatElapsed(s) };
}
