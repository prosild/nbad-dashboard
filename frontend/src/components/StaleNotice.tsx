import { AlertTriangle, RefreshCw } from 'lucide-react';
import type { ErrorNotice } from '../api/client';
import { formatDateTime } from '../utils/format';

/**
 * T41(현황판) → T42(공통): 다시 불러오기에 실패해 화면 값이 최신이 아니라는 한 줄 표시.
 * 같은 조건으로 성공한 값을 남긴 채 실패했을 때만 쓴다. 실패 이유, 마지막 성공 시각, 다시 시도.
 * "N초마다 다시 시도" 말은 자동 갱신이 이어질 때만 붙인다(autoRetrySeconds).
 */
export function StaleNotice({
  notice,
  loadedAt,
  autoRetrySeconds = null,
  loading,
  onRetry,
}: {
  notice: ErrorNotice;
  loadedAt: string | null;
  autoRetrySeconds?: number | null;
  loading: boolean;
  onRetry: () => void;
}) {
  return (
    <div
      role="status"
      data-testid="stale-notice"
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-amber-500/40 bg-amber-950/30 px-3 py-2 text-xs text-amber-100"
    >
      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
      <span className="font-semibold text-amber-200">최신 값이 아닙니다</span>
      <span className="min-w-0 break-words">{notice.message}</span>
      <span className="text-amber-100/80">
        마지막 성공 <span className="tabular-nums">{formatDateTime(loadedAt)}</span>
      </span>
      {autoRetrySeconds !== null && (
        <span className="text-amber-100/80" data-testid="stale-auto-retry">
          {autoRetrySeconds}초마다 다시 시도합니다
        </span>
      )}
      <button type="button" onClick={onRetry} disabled={loading} className="soc-btn-secondary ml-auto py-1 text-xs">
        <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
        다시 시도
      </button>
    </div>
  );
}

/** 최신 값이 아닌 동안 조치 버튼을 막을 때 붙이는 이유(T42). */
export const STALE_ACTION_BLOCKED = '최신 값을 불러온 뒤 결정할 수 있습니다';

/** 상세 조치 패널(담당·상태 변경·에스컬레이션 결정)을 막을 때의 이유(T42). */
export const STALE_ACTION_BLOCKED_DETAIL = '최신 값을 불러온 뒤 조치할 수 있습니다';
