import { useState } from 'react';
import { AlertTriangle, RefreshCw, UserCheck, UserMinus, UserPlus, Users } from 'lucide-react';
import { ApiError } from '../../api/client';
import { incidentsApi } from '../../api/endpoints';
import type { AssigneeCandidate, IncidentAssignment } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { useToast } from '../ToastContext';
import { AssigneeName } from './AssignmentBits';

/**
 * 조치 패널 맨 위의 담당 칸(T25). 현재 담당자를 보이고, 분석가·관리자면 "내가 맡기"·"담당자 변경"·"담당 해제"를 둔다.
 * 종결이면 읽기만 한다(서버 canAssign=false). 요청에는 화면이 본 담당자(expected)를 싣고, 409면 서버 문장을 보인 뒤 상세를 다시 불러온다.
 */
export function AssignmentSection({
  jobId,
  queueRank,
  assignment,
  canAssign,
  closed,
  currentUsername,
  onRefresh,
  blockedReason = null,
}: {
  jobId: number;
  queueRank: number;
  assignment: IncidentAssignment | null | undefined;
  canAssign: boolean;
  closed: boolean;
  currentUsername: string | null;
  onRefresh: () => Promise<void>;
  /** T42: 값이 최신이 아닌 동안 담당 변경을 막는 이유(조치 패널 위에 한 번 보이고 버튼은 툴팁으로) */
  blockedReason?: string | null;
}) {
  const { notify } = useToast();
  const assignee = assignment?.assignee ?? null;
  const mine = Boolean(assignee && currentUsername && assignee.username.toLowerCase() === currentUsername.toLowerCase());
  const [busy, setBusy] = useState(false);
  const blocked = blockedReason !== null;
  const blockedTitle = blockedReason ?? undefined;
  const [error, setError] = useState<string | null>(null);
  const [candidates, setCandidates] = useState<AssigneeCandidate[] | null>(null);
  const [picking, setPicking] = useState(false);
  const [picked, setPicked] = useState('');

  async function submit(target: string | null, successText: string) {
    setError(null);
    setBusy(true);
    try {
      await incidentsApi.assign(jobId, queueRank, { assignee: target, expected: assignee?.username ?? null });
      notify(successText, 'success');
      setPicking(false);
      setPicked('');
      await onRefresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // 다른 사람이 먼저 바꿨거나(충돌)·같은 값·종결: 서버 문장을 보이고 바뀐 값을 다시 불러온다.
        setError(err.message);
        await onRefresh();
      } else {
        setError(err instanceof ApiError ? err.message : '담당자를 바꾸지 못했습니다.');
      }
    } finally {
      setBusy(false);
    }
  }

  async function openPicker() {
    setError(null);
    setPicking(true);
    if (candidates !== null) return;
    try {
      const res = await incidentsApi.assignees(jobId, queueRank);
      setCandidates(res.assignees);
    } catch (err) {
      setPicking(false);
      setError(err instanceof ApiError ? err.message : '담당자 목록을 불러오지 못했습니다.');
    }
  }

  const options = (candidates ?? []).filter((c) => c.username.toLowerCase() !== (assignee?.username ?? "").toLowerCase());

  return (
    <div className="space-y-2" aria-label="담당" role="group">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="soc-subhead flex items-center gap-1.5">
          <UserCheck className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
          담당
        </h3>
        <AssigneeName assignee={assignee} className="text-xs" />
      </div>
      {assignee && assignment?.assignedAt && (
        <div className="text-[11px] text-slate-400">
          지정 <span className="tabular-nums text-slate-300">{formatDateTime(assignment.assignedAt)}</span> · 지정자{' '}
          <span className="text-slate-300" data-raw="">
            {assignment.assignedByDisplay ?? '-'}
          </span>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
        >
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
            {error}
          </span>
          <button type="button" onClick={() => void onRefresh()} className="soc-btn-secondary py-1 text-[11px]">
            <RefreshCw className="h-3 w-3" aria-hidden="true" />
            다시 불러오기
          </button>
        </div>
      )}

      {canAssign ? (
        <>
          <div className="flex flex-wrap gap-1.5">
            {!mine && (
              <button
                type="button"
                disabled={busy || blocked || !currentUsername}
                title={blockedTitle}
                onClick={() => void submit(currentUsername, '내가 담당자가 되었습니다.')}
                className="soc-btn-secondary px-2.5 py-1 text-xs"
              >
                <UserPlus className="h-3.5 w-3.5" aria-hidden="true" />
                내가 맡기
              </button>
            )}
            <button
              type="button"
              disabled={busy || blocked}
              title={blockedTitle}
              onClick={() => void openPicker()}
              aria-expanded={picking}
              className="soc-btn-secondary px-2.5 py-1 text-xs"
            >
              <Users className="h-3.5 w-3.5" aria-hidden="true" />
              담당자 변경
            </button>
            {assignee && (
              <button
                type="button"
                disabled={busy || blocked}
                title={blockedTitle}
                onClick={() => void submit(null, '담당을 해제했습니다.')}
                className="soc-btn-secondary px-2.5 py-1 text-xs"
              >
                <UserMinus className="h-3.5 w-3.5" aria-hidden="true" />
                담당 해제
              </button>
            )}
          </div>
          {picking && (
            <div className="flex flex-wrap items-center gap-1.5">
              <label htmlFor="assignee-select" className="sr-only">
                새 담당자
              </label>
              <select
                id="assignee-select"
                value={picked}
                onChange={(e) => setPicked(e.target.value)}
                disabled={candidates === null || busy}
                className="soc-select min-w-0 flex-1 py-1 text-xs"
              >
                <option value="">{candidates === null ? '불러오는 중...' : '담당자 고르기'}</option>
                {options.map((c) => (
                  <option key={c.username} value={c.username}>
                    {c.displayName} ({c.username})
                  </option>
                ))}
              </select>
              <button
                type="button"
                disabled={!picked || busy || blocked}
                title={blockedTitle}
                onClick={() => void submit(picked, '담당자를 바꿨습니다.')}
                className="soc-btn-primary px-2.5 py-1 text-xs"
              >
                지정
              </button>
              <button type="button" onClick={() => setPicking(false)} className="px-1.5 py-1 text-[11px] text-slate-400 hover:text-slate-100">
                취소
              </button>
              {candidates !== null && options.length === 0 && (
                <p className="w-full text-[11px] text-slate-400">지정할 수 있는 다른 사용자가 없습니다.</p>
              )}
            </div>
          )}
        </>
      ) : (
        closed && <p className="text-[11px] text-slate-400">종결된 인시던트라 담당자를 바꾸지 않습니다.</p>
      )}
    </div>
  );
}
