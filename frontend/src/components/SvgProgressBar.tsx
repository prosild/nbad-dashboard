interface SvgProgressBarProps {
  value: number;
  max: number;
  tone?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'purple' | 'slate';
  label?: string;
}

const TONE_FILL: Record<NonNullable<SvgProgressBarProps['tone']>, string> = {
  cyan: '#22d3ee',
  emerald: '#34d399',
  amber: '#fbbf24',
  rose: '#fb7185',
  purple: '#a78bfa',
  slate: '#94a3b8',
};

export function SvgProgressBar({
  value,
  max,
  tone = 'cyan',
  label,
}: SvgProgressBarProps) {
  const safeMax = Number.isFinite(max) && max > 0 ? max : 1;
  const safeVal = Number.isFinite(value) && value > 0 ? value : 0;
  const percent = Math.min(100, Math.max(0, (safeVal / safeMax) * 100));
  const fillColor = TONE_FILL[tone];

  return (
    <svg
      viewBox="0 0 100 8"
      preserveAspectRatio="none"
      className="h-2 w-full overflow-hidden rounded-full bg-slate-900"
      role="img"
      aria-label={label ?? `${percent.toFixed(1)}%`}
    >
      <rect x={0} y={0} width={100} height={8} rx={4} fill="#0f172a" />
      {percent > 0 && (
        <rect x={0} y={0} width={Number(percent.toFixed(2))} height={8} rx={4} fill={fillColor} />
      )}
    </svg>
  );
}
