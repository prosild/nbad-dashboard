import { AlertTriangle, RefreshCw } from 'lucide-react';

export function ErrorAlert({
  title = '요청 처리 중 오류가 발생했습니다',
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-rose-500/40 bg-rose-950/35 px-4 py-3.5 text-sm text-rose-100"
    >
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
        <div>
          <div className="font-semibold text-rose-200">{title}</div>
          <div className="mt-0.5 text-rose-100/90">{message}</div>
        </div>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="soc-btn-secondary py-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          새로고침
        </button>
      )}
    </div>
  );
}

export function LoadingPanel({ label = '데이터를 불러오는 중...' }: { label?: string }) {
  return (
    <div className="soc-card flex items-center justify-center gap-3 p-10 text-sm text-slate-400">
      <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
      <span>{label}</span>
    </div>
  );
}
