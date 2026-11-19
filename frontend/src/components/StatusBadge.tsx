import { resolutionLabel, statusLabel } from '../utils/format';

type BadgeTone = 'cyan' | 'emerald' | 'amber' | 'rose' | 'purple' | 'slate';

const TONE_CLASS: Record<BadgeTone, string> = {
  cyan: 'border-cyan-500/35 bg-cyan-500/15 text-cyan-200',
  emerald: 'border-emerald-500/35 bg-emerald-500/15 text-emerald-200',
  amber: 'border-amber-500/35 bg-amber-500/15 text-amber-200',
  rose: 'border-rose-500/35 bg-rose-500/15 text-rose-200',
  purple: 'border-purple-500/35 bg-purple-500/15 text-purple-200',
  slate: 'border-slate-700 bg-slate-800/80 text-slate-300',
};

export function SocBadge({
  tone = 'slate',
  children,
}: {
  tone?: BadgeTone;
  children: React.ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium leading-tight ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status: string | null | undefined }) {
  const norm = (status ?? 'open').toLowerCase();
  const tone: BadgeTone =
    norm === 'open' ? 'rose' : norm === 'investigating' ? 'amber' : norm === 'closed' ? 'emerald' : 'slate';
  return <SocBadge tone={tone}>{statusLabel(norm)}</SocBadge>;
}

export function ResolutionBadge({ resolution }: { resolution: string | null | undefined }) {
  if (!resolution) {
    return null;
  }
  const norm = resolution.toLowerCase();
  const tone: BadgeTone =
    norm === 'true_positive' ? 'rose' : norm === 'false_positive' ? 'amber' : 'cyan';
  return <SocBadge tone={tone}>{resolutionLabel(norm)}</SocBadge>;
}

export function ReviewActionBadge({
  action,
  pending,
}: {
  action: string | null | undefined;
  pending?: boolean;
}) {
  if (pending || !action) {
    return pending ? <SocBadge tone="amber">승인 대기</SocBadge> : <SocBadge tone="slate">-</SocBadge>;
  }
  const norm = action.toLowerCase();
  return norm === 'confirm' ? (
    <SocBadge tone="emerald">confirm (조사 진행)</SocBadge>
  ) : (
    <SocBadge tone="amber">dismiss (오탐 종료)</SocBadge>
  );
}
