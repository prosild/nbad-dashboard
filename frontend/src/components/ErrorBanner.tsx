import { AlertTriangle, RefreshCw } from 'lucide-react';

/**
 * 요청 실패 안내. 사람이 다시 시도하거나 관리자에게 알려야 하므로 주의(주황) 색을 쓴다.
 * T41: 요청 제한(429)이면 제목을 바꾸고 "관리자에게 알려 주세요" 줄을 뺀다(장애가 아니다).
 */
export function ErrorAlert({
  title,
  message,
  rateLimited = false,
  onRetry,
}: {
  title?: string;
  message: string;
  rateLimited?: boolean;
  onRetry?: () => void;
}) {
  const heading = title ?? (rateLimited ? '요청이 잠시 제한됐습니다' : '요청을 처리하지 못했습니다');
  return (
    <div
      role="alert"
      className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-amber-500/40 bg-amber-950/30 px-4 py-3.5 text-sm text-amber-100"
    >
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
        <div>
          <div className="font-semibold text-amber-200">{heading}</div>
          <div className="mt-0.5 text-amber-100/90">{message}</div>
          {!rateLimited && (
            <div className="mt-1 text-xs text-amber-100/70">잠시 후 다시 시도하세요. 계속되면 관리자에게 알려 주세요.</div>
          )}
        </div>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="soc-btn-secondary py-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          다시 시도
        </button>
      )}
    </div>
  );
}

export function LoadingPanel({ label = '불러오는 중...' }: { label?: string }) {
  return (
    <div className="soc-card flex items-center justify-center gap-3 p-10 text-sm text-slate-400">
      <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
      <span>{label}</span>
    </div>
  );
}
