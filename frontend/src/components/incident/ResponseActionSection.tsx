import { useState } from 'react';
import { AlertTriangle, Info, RefreshCw, ShieldCheck } from 'lucide-react';
import { ApiError } from '../../api/client';
import { incidentsApi } from '../../api/endpoints';
import type { ResponseActionItem } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { FREE_TEXT_MAX } from '../../utils/freeText';
import { RESPONSE_ACTION_NOTE_REQUIRED, RESPONSE_ACTION_VALUES } from '../../utils/responseActions';
import { labelText } from '../../utils/labels';
import { CodeLabel } from '../StatusBadge';
import { useToast } from '../ToastContext';
import { FreeTextCounter } from './FreeTextCounter';

/**
 * 조치 패널의 "대응 조치" 칸(T56). 분석가가 인시던트에 어떤 조치를 했는지(차단, 격리, 계정 잠금, 이관, 조치 없음 등) 기록한다.
 * 이 콘솔은 방화벽·EDR에 명령을 내리지 않는다. 기록만 한다(실행 버튼이 없다).
 * 칸에는 기록 수와 가장 최근 1건만 보인다. 나머지는 이력(패널의 최근 이력, 이력 탭)에 섞여 나온다.
 * 조회자는 종류·기록자·시각만 본다(메모는 서버가 내리지 않는다). 기록을 고치거나 지우는 화면은 없다.
 */
export function ResponseActionSection({
  jobId,
  queueRank,
  actions,
  canRecord,
  notStarted,
  onRefresh,
  blockedReason = null,
}: {
  jobId: number;
  queueRank: number;
  /** 시간 역순(서버 값). 응답에 없으면(옛 응답) 빈 목록으로 보인다 */
  actions: ResponseActionItem[];
  /** 분석가·관리자이고 신규가 아님(서버 값) */
  canRecord: boolean;
  /** 쓰기 권한은 있는데 아직 신규(착수 전)라 기록할 수 없음 */
  notStarted: boolean;
  onRefresh: () => Promise<void>;
  /** T42: 값이 최신이 아닌 동안 기록을 막는 이유 */
  blockedReason?: string | null;
}) {
  const { notify } = useToast();
  const [action, setAction] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const latest = actions.length > 0 ? actions[0] : null;
  const noteRequired = RESPONSE_ACTION_NOTE_REQUIRED.includes(action);
  const blocked = blockedReason !== null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!action) return;
    setError(null);
    setBusy(true);
    try {
      const res = await incidentsApi.recordResponseAction(jobId, queueRank, { action, note: note.trim() || null });
      notify(res.message || '대응 조치를 기록했습니다.', 'success');
      setAction('');
      setNote('');
      await onRefresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '대응 조치를 기록하지 못했습니다.');
      if (err instanceof ApiError && err.status === 409) {
        // 그사이 상태가 바뀌었다(착수 전으로 보임 등): 서버 문장을 보이고 바뀐 값을 다시 불러온다.
        await onRefresh();
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2 border-t border-slate-800 pt-3" aria-label="대응 조치" role="group">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="soc-subhead flex items-center gap-1.5">
          <ShieldCheck className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
          대응 조치
        </h3>
        <span className="text-[11px] tabular-nums text-slate-400">기록 {actions.length}건</span>
      </div>

      {latest ? (
        <div className="space-y-1 rounded-lg border border-slate-800 bg-[#090f1d] p-2.5 text-xs" data-testid="response-latest">
          <div>
            <span className="rounded border border-slate-700 px-1.5 text-[11px] text-slate-300">
              <CodeLabel dict="responseAction" value={latest.action} />
            </span>
          </div>
          {latest.note && (
            <div className="whitespace-pre-line break-words text-slate-200" data-raw="">
              {latest.note}
            </div>
          )}
          <div className="text-[11px] text-slate-400">
            기록자{' '}
            <span className="text-slate-300 [overflow-wrap:anywhere]" data-raw="">
              {latest.actorDisplay ?? '-'}
            </span>{' '}
            · 기록 <span className="tabular-nums text-slate-300">{formatDateTime(latest.recordedAt)}</span>
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-400">기록된 대응 조치가 없습니다.</p>
      )}
      {actions.length > 1 && <p className="text-[11px] text-slate-400">이전 기록 {actions.length - 1}건은 이력 탭에서 볼 수 있습니다.</p>}

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

      {canRecord && (
        <form onSubmit={(e) => void submit(e)} className="space-y-2" aria-label="대응 조치 기록">
          <p className="flex items-start gap-1.5 text-[11px] text-slate-400">
            <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
            실제 차단·격리는 해당 장비에서 하고 여기에는 한 일을 기록합니다.
          </p>
          <div>
            <label htmlFor="response-action-type" className="mb-1 block text-xs font-medium text-slate-300">
              조치 종류 (필수)
            </label>
            <select
              id="response-action-type"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="soc-select w-full text-xs"
            >
              <option value="">조치 종류 고르기</option>
              {RESPONSE_ACTION_VALUES.map((value) => (
                <option key={value} value={value}>
                  {labelText('responseAction', value)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="response-action-note" className="mb-1 block text-xs font-medium text-slate-300">
              메모 ({noteRequired ? '필수' : '선택'})
            </label>
            <textarea
              id="response-action-note"
              rows={2}
              required={noteRequired}
              maxLength={FREE_TEXT_MAX}
              aria-describedby="response-action-note-count"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={
                action === 'none' ? '조치하지 않은 이유를 적어 두세요.' : '대상과 요청한 곳을 적어 두세요(예: 방화벽 담당에 차단 요청).'
              }
              className="soc-input text-xs"
            />
            <FreeTextCounter id="response-action-note-count" value={note} />
          </div>
          <button
            type="submit"
            disabled={busy || !action || (noteRequired && !note.trim()) || blocked}
            title={blockedReason ?? undefined}
            className="soc-btn-secondary w-full py-1.5 text-xs"
          >
            {busy ? '저장 중...' : '조치 기록'}
          </button>
        </form>
      )}
      {!canRecord && notStarted && <p className="text-[11px] text-slate-400">착수한 뒤(분석 중) 기록할 수 있습니다.</p>}
    </div>
  );
}
