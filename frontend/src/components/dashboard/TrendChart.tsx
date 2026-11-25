/**
 * 탐지 추이(T24): 우선순위별 쌓은 막대. 순수 SVG(새 의존성 없음)이고 인라인 style을 쓰지 않는다(엄격한 CSP).
 * 막대 높이·위치는 SVG 속성으로 준다. 폭은 상자 폭을 재서 viewBox를 맞추므로 글자가 늘어나지 않고 막대만 줄어든다.
 * 색은 우선순위 배지와 같은 체계(High 빨강, Medium 밝은 회색, Low 흐린 회색, 종결 더 흐린 색)다.
 */
import { useContainerWidth } from '../../hooks/useContainerWidth';
import type { DashboardTrend, TrendBucket, TrendBucketUnit } from '../../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatCompactDateTime, formatDateTime, formatNumber } from '../../utils/format';
import { earlierIso, laterIso, parseOffsetIso, type PeriodRange } from '../../utils/periodRange';

export const TREND_COLORS = {
  high: '#f43f5e',
  medium: '#cbd5e1',
  low: '#64748b',
  none: '#334155',
} as const;

const SERIES: { key: 'high' | 'medium' | 'low' | 'none'; label: string }[] = [
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
  { key: 'none', label: '종결' },
];

const HEIGHT = 150;
const TOP = 14;
const BOTTOM = 20;
const LEFT = 30;
const RIGHT = 4;

/** 구간 눈금 글: 5분·1시간은 시각, 6시간은 월-일 시, 일·주는 월-일(KST) */
export function bucketTickLabel(iso: string, unit: TrendBucketUnit): string {
  const full = formatDateTime(iso);
  if (full.length !== 19) return full;
  if (unit === '5m' || unit === '1h') return full.slice(11, 16);
  if (unit === '6h') return `${full.slice(5, 10)} ${full.slice(11, 13)}시`;
  return full.slice(5, 10);
}

/** 구간 범위 글(KST): 같은 날이면 끝은 시각만 */
export function bucketRangeText(b: TrendBucket): string {
  const s = formatDateTime(b.start);
  const e = formatDateTime(b.end);
  if (s.length !== 19 || e.length !== 19) return `${s} ~ ${e}`;
  const endText = s.slice(0, 10) === e.slice(0, 10) ? e.slice(11, 16) : e.slice(5, 16);
  return `${s.slice(5, 16)} ~ ${endText} ${DISPLAY_TIME_ZONE_LABEL}`;
}

export function bucketTitle(b: TrendBucket): string {
  const parts = SERIES.map((s) => `${s.label} ${formatNumber(b[s.key])}`).join(' · ');
  return `${bucketRangeText(b)}\n합계 ${formatNumber(b.total)}건 (${parts})${b.partial ? '\n일부 구간: 구간 일부만 기간 안입니다' : ''}`;
}

/**
 * T34 막대에서 들어갈 큐 범위: 구간을 기간 경계(periodStart)와 min(기간 끝, 기준 시각)으로 자른다. 0건 막대는 null.
 * 문자열은 받은 값을 그대로 쓴다(서버 값의 마이크로초를 잃지 않게).
 */
export function bucketQueueRange(
  b: TrendBucket,
  periodStart: string | null | undefined,
  periodEnd: string | null | undefined,
  anchor: string | null | undefined,
): PeriodRange | null {
  if (b.total <= 0) return null;
  const start = laterIso(b.start, periodStart);
  const end = earlierIso(earlierIso(b.end, periodEnd), anchor);
  const s = parseOffsetIso(start);
  const e = parseOffsetIso(end);
  if (s === null || e === null || s >= e) return null;
  return { start, end };
}

/** 막대 링크의 접근성 이름: "11-19 09:00–10:00 인시던트 12건 보기"(KST, 같은 날이면 끝은 시각만) */
export function bucketLinkLabel(range: PeriodRange, total: number, anchor?: string | null): string {
  const s = formatCompactDateTime(range.start, anchor ?? range.end);
  const e = formatCompactDateTime(range.end, anchor ?? range.end);
  const sameDay = s.length === e.length && s.slice(0, -6) === e.slice(0, -6);
  return `${s}–${sameDay ? e.slice(-5) : e} 인시던트 ${formatNumber(total)}건 보기`;
}

export function TrendChart({
  trend,
  bucketHref,
  onNavigate,
  anchor = null,
  periodStart = null,
  periodEnd = null,
}: {
  trend: DashboardTrend;
  /** T34: 구간 범위 → 큐 주소. 없으면 막대를 누를 수 없다 */
  bucketHref?: (range: PeriodRange) => string;
  onNavigate?: (href: string) => void;
  anchor?: string | null;
  periodStart?: string | null;
  periodEnd?: string | null;
}) {
  const [ref, width] = useContainerWidth<HTMLDivElement>();
  const buckets = trend.buckets;
  const n = buckets.length;
  const max = buckets.reduce((m, b) => Math.max(m, b.total), 0);
  const plotW = Math.max(40, width - LEFT - RIGHT);
  const plotH = HEIGHT - TOP - BOTTOM;
  const slot = n > 0 ? plotW / n : plotW;
  const gap = slot > 6 ? Math.min(3, slot * 0.2) : 0.5;
  const barW = Math.max(1, slot - gap);
  const scale = (v: number) => (max > 0 ? (v / max) * plotH : 0);
  // 눈금 글은 폭에 맞춰 몇 개만(글 하나에 약 64px)
  const maxTicks = Math.max(2, Math.floor(plotW / 64));
  const tickEvery = Math.max(1, Math.ceil(n / maxTicks));
  const r = (v: number) => Number(v.toFixed(2));

  return (
    <div ref={ref} className="w-full min-w-0" data-trend-chart="">
      <svg
        width={width}
        height={HEIGHT}
        viewBox={`0 0 ${width} ${HEIGHT}`}
        className="block max-w-full"
        role={bucketHref ? 'group' : 'img'}
        aria-label={`탐지 추이: 구간 ${formatNumber(n)}개, 구간 최대 ${formatNumber(max)}건${bucketHref ? '. 막대를 누르면 그 구간의 인시던트 목록으로 갑니다' : ''}`}
      >
        {/* 세로축: 최대값과 0 */}
        <line x1={LEFT} x2={LEFT + plotW} y1={TOP + plotH} y2={TOP + plotH} stroke="#334155" strokeWidth={1} />
        <line x1={LEFT} x2={LEFT + plotW} y1={TOP} y2={TOP} stroke="#1e293b" strokeWidth={1} strokeDasharray="3 3" />
        <text x={LEFT - 4} y={TOP + 4} textAnchor="end" fontSize={10} fill="#94a3b8" data-axis-max="">
          {formatNumber(max)}
        </text>
        <text x={LEFT - 4} y={TOP + plotH} textAnchor="end" fontSize={10} fill="#64748b">
          0
        </text>
        {buckets.map((b, i) => {
          const x = LEFT + i * slot + gap / 2;
          let y = TOP + plotH;
          const range = bucketHref ? bucketQueueRange(b, periodStart, periodEnd, anchor) : null;
          const href = range && bucketHref ? bucketHref(range) : null;
          const bars = (
            <>
              <title>{bucketTitle(b)}</title>
              {/* 툴팁을 띄우기 쉬운 투명 영역(링크면 누르는 영역) */}
              <rect x={r(LEFT + i * slot)} y={TOP} width={r(slot)} height={plotH} fill="transparent" />
              {SERIES.map((s) => {
                const h = scale(b[s.key]);
                if (h <= 0) return null;
                y -= h;
                return (
                  <rect
                    key={s.key}
                    x={r(x)}
                    y={r(y)}
                    width={r(barW)}
                    height={r(h)}
                    fill={TREND_COLORS[s.key]}
                    fillOpacity={b.partial ? 0.45 : 1}
                    data-series={s.key}
                  />
                );
              })}
            </>
          );
          return (
            <g key={b.start} data-bucket="" data-partial={b.partial ? 'true' : undefined}>
              {href && range ? (
                <a
                  href={href}
                  aria-label={bucketLinkLabel(range, b.total, anchor)}
                  data-bucket-link=""
                  className="cursor-pointer focus:outline-none"
                  onClick={(e) => {
                    if (!onNavigate || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
                    e.preventDefault();
                    onNavigate(href);
                  }}
                >
                  {bars}
                </a>
              ) : (
                bars
              )}
              {i % tickEvery === 0 && (
                <text
                  x={r(LEFT + i * slot + slot / 2)}
                  y={HEIGHT - 5}
                  textAnchor="middle"
                  fontSize={10}
                  fill="#94a3b8"
                  data-tick=""
                >
                  {bucketTickLabel(b.start, trend.bucket)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-slate-400" aria-hidden="true">
        {SERIES.map((s) => (
          <li key={s.key} className="flex items-center gap-1">
            <svg width={10} height={10} viewBox="0 0 10 10">
              <rect width={10} height={10} rx={2} fill={TREND_COLORS[s.key]} />
            </svg>
            {s.label}
          </li>
        ))}
        <li className="flex items-center gap-1">
          <svg width={10} height={10} viewBox="0 0 10 10">
            <rect width={10} height={10} rx={2} fill={TREND_COLORS.low} fillOpacity={0.45} />
          </svg>
          흐린 막대: 일부 구간
        </li>
      </ul>
      {/* 표에 sr-only를 바로 주면 표는 내용 폭(휴대폰에서 ~460px)보다 좁아지지 않아 페이지가 가로로 넘친다(T24 휴대폰 측정).
          1px·overflow hidden 상자로 감싸 넘침을 가둔다. */}
      <div className="sr-only" data-trend-table>
      <table>
        <caption>탐지 추이 구간별 인시던트 수</caption>
        <thead>
          <tr>
            <th scope="col">구간</th>
            {SERIES.map((s) => (
              <th key={s.key} scope="col">
                {s.label}
              </th>
            ))}
            <th scope="col">합계</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b) => (
            <tr key={b.start}>
              <th scope="row">
                {bucketRangeText(b)}
                {b.partial ? ' (일부 구간)' : ''}
              </th>
              {SERIES.map((s) => (
                <td key={s.key}>{b[s.key]}</td>
              ))}
              <td>{b.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </div>
  );
}
