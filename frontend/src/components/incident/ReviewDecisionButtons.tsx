import { useState } from 'react';
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import { labelText } from '../../utils/labels';

/** 오탐 종결 메모 필수 안내(화면 검증. API의 메모는 선택값 그대로다) */
export const DISMISS_NOTE_REQUIRED = '오탐 종결에는 검토 메모가 필요합니다.';
/** 오탐 종결 확인 문구 */
export const DISMISS_CONFIRM_TEXT = '오탐 종결로 결정할까요? 결정은 되돌릴 수 없고, 인시던트 상태는 바뀌지 않습니다.';

/**
 * 에스컬레이션 결정 버튼(승인 · 오탐 종결). 오탐 종결은 메모가 있어야 하고 확인 단계를 한 번 더 거친다(T19 H7·M4).
 * 상세 조치 패널과 에스컬레이션 목록이 같은 컴포넌트를 써서 같은 안전 수준을 지킨다.
 */
export function ReviewDecisionButtons({
  note,
  noteInputId,
  submitting,
  onDecide,
  compact = false,
  idPrefix,
}: {
  note: string;
  /** 메모가 비었을 때 포커스를 옮길 입력 칸 id */
  noteInputId: string;
  submitting: boolean;
  onDecide: (action: 'confirm' | 'dismiss') => void;
  compact?: boolean;
  /** 같은 화면에 여러 개 있을 때 접근성 이름을 구분하는 말(에스컬레이션 목록의 인시던트) */
  idPrefix?: string;
}) {
  const [confirming, setConfirming] = useState(false);
  const [noteError, setNoteError] = useState(false);
  const hasNote = note.trim().length > 0;
  const size = compact ? 'px-2 py-1 text-xs' : 'py-2 text-xs';
  const icon = compact ? 'h-3.5 w-3.5' : 'h-4 w-4';

  function askDismiss() {
    if (!hasNote) {
      setNoteError(true);
      setConfirming(false);
      document.getElementById(noteInputId)?.focus();
      return;
    }
    setNoteError(false);
    setConfirming(true);
  }

  if (confirming) {
    return (
      <div
        role="group"
        aria-label={idPrefix ? `${idPrefix} 오탐 종결 확인` : '오탐 종결 확인'}
        className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-100"
      >
        <p className="flex items-start gap-1.5">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" aria-hidden="true" />
          <span>{DISMISS_CONFIRM_TEXT}</span>
        </p>
        {!hasNote && (
          <p role="alert" className="text-amber-200">
            {DISMISS_NOTE_REQUIRED}
          </p>
        )}
        <div className="flex gap-1.5">
          <button
            type="button"
            disabled={submitting || !hasNote}
            onClick={() => {
              onDecide('dismiss');
              setConfirming(false);
            }}
            className={`soc-btn-caution flex-1 ${size}`}
          >
            <XCircle className={icon} aria-hidden="true" />
            오탐 종결 확정
          </button>
          <button
            type="button"
            disabled={submitting}
            onClick={() => setConfirming(false)}
            className={`soc-btn-secondary flex-1 ${size}`}
          >
            취소
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {noteError && !hasNote && (
        <p role="alert" className="text-xs text-amber-200">
          {DISMISS_NOTE_REQUIRED}
        </p>
      )}
      <div className={compact ? 'flex gap-1.5' : 'grid grid-cols-2 gap-2'}>
        <button
          type="button"
          disabled={submitting}
          onClick={() => onDecide('confirm')}
          className={`soc-btn-emerald flex-1 ${size}`}
        >
          <CheckCircle2 className={icon} aria-hidden="true" />
          {labelText('reviewAction', 'confirm')}
        </button>
        <button
          type="button"
          disabled={submitting}
          onClick={askDismiss}
          className={`soc-btn-secondary flex-1 ${size}`}
        >
          <XCircle className={icon} aria-hidden="true" />
          {labelText('reviewAction', 'dismiss')}
        </button>
      </div>
    </div>
  );
}
