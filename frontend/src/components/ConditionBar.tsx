/**
 * 공통 조건 줄(T24): 기간 버튼과 수집원 선택. 인시던트 큐·현황판·운영 현황이 같이 쓴다.
 * URL 쿼리(period·source·captureId)가 상태의 원본이며, 화면마다 기본 기간이 다르다(큐·현황판 24시간, 운영 현황 7일).
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { CalendarRange } from 'lucide-react';
import type { SourceType } from '../types/api';
import { captureInfo } from '../utils/labels';
import {
  formatRangeLong,
  formatRangeShort,
  initialRangeInputs,
  rangeFromInputs,
  type PeriodRange,
} from '../utils/periodRange';
import { PERIODS, type Period, type PresetPeriod } from '../utils/triage';
import { lastDetectedText, maxIso } from './OutsidePeriodNotice';
import { SOURCE_TYPE_LABEL } from './StatusBadge';

/** 수집원 선택 목록에 쓰는 최소 정보(큐 sources·overview captures) */
export interface SourceOption {
  captureId: string;
  sourceType: SourceType;
  /** T29 큐 sources만 준다(운영 현황 목록에는 없다). 있으면 목록에 마지막 탐지를 붙인다 */
  lastDetectedAt?: string | null;
}

/** URL의 source·captureId → 선택 값('' = 전체, 'src:live|imported', 'cap:<id>') */
export function sourceSelectValue(source: string | null | undefined, captureId: string | null | undefined): string {
  if (captureId) return `cap:${captureId}`;
  if (source) return `src:${source}`;
  return '';
}

/** 선택 값 → URL 변경(수집원 종류와 캡처 하나는 함께 쓰지 않는다) */
export function sourceSelectChanges(value: string): { source: string | null; captureId: string | null } {
  if (value.startsWith('cap:')) return { source: null, captureId: value.slice(4) };
  if (value.startsWith('src:')) return { source: value.slice(4), captureId: null };
  return { source: null, captureId: null };
}

/**
 * 기간 버튼(프리셋)과 T34 "기간 지정"(시작·끝, KST 분 단위). 지정 중에는 "기간 지정" 버튼이 눌린 상태로 범위를 짧게 보인다.
 * 창 처음 값은 지금 보이는 기간(current: 응답의 periodStart·periodEnd), 전체면 기준 시각 − 24시간 ~ 기준 시각이다.
 */
export function PeriodButtons({
  value,
  onChange,
  range = null,
  onApplyRange,
  current = null,
}: {
  value: Period;
  onChange: (value: PresetPeriod) => void;
  /** 지정 중인 범위(value가 custom일 때) */
  range?: PeriodRange | null;
  /** 없으면 "기간 지정" 버튼을 보이지 않는다 */
  onApplyRange?: (range: PeriodRange) => void;
  /** 창 처음 값을 정할 지금 기간 경계와 기준 시각 */
  current?: { periodStart?: string | null; periodEnd?: string | null; anchor?: string | null } | null;
}) {
  const [open, setOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const custom = value === 'custom' && range !== null;
  return (
    <div className="relative flex flex-wrap items-center gap-x-2 gap-y-1.5" role="group" aria-label="기간">
      <span className="shrink-0 text-xs font-medium text-slate-400" aria-hidden="true">
        기간
      </span>
      <div className="flex overflow-hidden rounded-md border border-slate-700">
        {PERIODS.map((p) => {
          const active = p.value === value;
          return (
            <button
              key={p.value}
              type="button"
              aria-pressed={active}
              onClick={() => onChange(p.value)}
              title={p.value === 'all' ? '탐지 시각 조건 없이 전체' : `기준 시각에서 최근 ${p.label} 안에 탐지된 인시던트`}
              className={`border-l border-slate-700 px-2 py-1 text-xs tabular-nums first:border-l-0 ${
                active ? 'bg-cyan-500/15 font-semibold text-cyan-200' : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              {p.label}
            </button>
          );
        })}
      </div>
      {onApplyRange && (
        <button
          ref={toggleRef}
          type="button"
          aria-pressed={custom}
          aria-expanded={open}
          aria-controls={open ? 'period-range-dialog' : undefined}
          aria-haspopup="dialog"
          onClick={() => setOpen((v) => !v)}
          title={custom && range ? `기간 지정: ${formatRangeLong(range)}` : '시작·끝 시각을 KST로 지정합니다'}
          data-testid="period-custom"
          className={`inline-flex min-w-0 max-w-full items-center gap-1 rounded-md border px-2 py-1 text-xs tabular-nums ${
            custom
              ? 'border-cyan-500/60 bg-cyan-500/15 font-semibold text-cyan-200'
              : 'border-slate-700 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <CalendarRange className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          {custom && range && <span className="sr-only">기간 지정 </span>}
          <span className="truncate">{custom && range ? formatRangeShort(range, current?.anchor) : '기간 지정'}</span>
        </button>
      )}
      {open && onApplyRange && (
        <RangeDialog
          range={custom ? range : null}
          current={current}
          onCancel={() => {
            setOpen(false);
            toggleRef.current?.focus();
          }}
          onApply={(r) => {
            setOpen(false);
            onApplyRange(r);
            toggleRef.current?.focus();
          }}
        />
      )}
    </div>
  );
}

/** 기간 지정 창: 시작·끝(KST, 분 단위), 적용·취소. Esc로 닫고 포커스는 "기간 지정" 버튼으로 돌아간다 */
function RangeDialog({
  range,
  current,
  onCancel,
  onApply,
}: {
  range: PeriodRange | null;
  current: { periodStart?: string | null; periodEnd?: string | null; anchor?: string | null } | null;
  onCancel: () => void;
  onApply: (range: PeriodRange) => void;
}) {
  const initial = useMemo(
    () =>
      range
        ? initialRangeInputs(range.start, range.end, current?.anchor)
        : initialRangeInputs(current?.periodStart, current?.periodEnd, current?.anchor),
    // 창을 열 때 한 번만 정한다(창은 열 때마다 새로 만든다)
    [],
  );
  const [start, setStart] = useState(initial.start);
  const [end, setEnd] = useState(initial.end);
  const [error, setError] = useState<string | null>(null);
  const startRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    startRef.current?.focus();
  }, []);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const result = rangeFromInputs(start, end);
    if ('error' in result) {
      setError(result.error);
      return;
    }
    onApply(result.range);
  }

  return (
    <div
      id="period-range-dialog"
      role="dialog"
      aria-label="기간 지정"
      className="absolute left-0 top-full z-30 mt-1 w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-slate-700 bg-slate-900 p-3 shadow-xl"
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation();
          onCancel();
        }
      }}
    >
      <form onSubmit={submit} className="space-y-2" noValidate>
        <p className="text-[11px] text-slate-400">탐지 시각 기준, 시작 초과 ~ 끝 이하 (KST)</p>
        <label className="block text-xs text-slate-300" htmlFor="period-range-start">
          시작 <span className="text-slate-500">KST</span>
        </label>
        <input
          ref={startRef}
          id="period-range-start"
          type="datetime-local"
          step={60}
          value={start}
          onChange={(e) => setStart(e.target.value)}
          aria-label="시작 시각(KST)"
          aria-invalid={error !== null}
          aria-describedby={error ? 'period-range-error' : undefined}
          className="soc-input w-full py-1 text-xs tabular-nums"
        />
        <label className="block text-xs text-slate-300" htmlFor="period-range-end">
          끝 <span className="text-slate-500">KST</span>
        </label>
        <input
          id="period-range-end"
          type="datetime-local"
          step={60}
          value={end}
          onChange={(e) => setEnd(e.target.value)}
          aria-label="끝 시각(KST)"
          aria-invalid={error !== null}
          aria-describedby={error ? 'period-range-error' : undefined}
          className="soc-input w-full py-1 text-xs tabular-nums"
        />
        {error && (
          <p id="period-range-error" role="alert" className="text-xs text-rose-300">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={onCancel} className="soc-btn-secondary px-3 py-1 text-xs">
            취소
          </button>
          <button type="submit" className="soc-btn-primary px-3 py-1 text-xs">
            적용
          </button>
        </div>
      </form>
    </div>
  );
}

/** T29 목록 글 뒤에 붙일 마지막 탐지(큐 sources에서 온 것만) */
function lastDetectedSuffix(
  members: SourceOption[],
  anchor: string | null | undefined,
  snapshot: boolean,
): string {
  if (members.length === 0 || members.some((m) => m.lastDetectedAt === undefined)) return '';
  return ` · ${lastDetectedText(maxIso(members.map((m) => m.lastDetectedAt)), anchor, snapshot)}`;
}

export function SourceSelect({
  id = 'filter-source',
  sources,
  value,
  onChange,
  anchor = null,
  snapshot = false,
}: {
  id?: string;
  sources: SourceOption[];
  value: string;
  onChange: (value: string) => void;
  /** T29 마지막 탐지와 견줄 기준 시각(고정 스냅샷이면 "기준 시각 N일 전") */
  anchor?: string | null;
  snapshot?: boolean;
}) {
  const groups: SourceType[] = ['live', 'imported'];
  const known = new Set(sources.map((s) => `cap:${s.captureId}`));
  const selectedCapture = value.startsWith('cap:') ? value.slice(4) : null;
  return (
    <select
      id={id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="soc-select w-full py-1.5 text-xs sm:w-72"
      title={selectedCapture ? captureInfo(selectedCapture).tooltip || undefined : undefined}
    >
      <option value="">전체 수집원</option>
      {groups.map((g) => {
        const members = sources.filter((s) => s.sourceType === g);
        return [
          <option key={`src-${g}`} value={`src:${g}`}>
            {`${SOURCE_TYPE_LABEL[g]} 전체${lastDetectedSuffix(members, anchor, snapshot)}`}
          </option>,
          members.length > 0 ? (
            <optgroup key={`grp-${g}`} label={SOURCE_TYPE_LABEL[g]}>
              {members.map((s) => {
                const info = captureInfo(s.captureId);
                return (
                  <option key={s.captureId} value={`cap:${s.captureId}`} title={info.tooltip}>
                    {`${info.text}${lastDetectedSuffix([s], anchor, snapshot)}`}
                  </option>
                );
              })}
            </optgroup>
          ) : null,
        ];
      })}
      {/* 옛 링크의 captureId가 목록에 없으면(허용 밖 등) 그대로 보여 준다. 서버가 403으로 답한다. */}
      {selectedCapture && !known.has(value) && <option value={value}>{captureInfo(selectedCapture).text}</option>}
    </select>
  );
}

/** 수집원 라벨 + 선택 상자 묶음 */
export function SourceField({
  id = 'filter-source',
  sources,
  value,
  onChange,
  anchor = null,
  snapshot = false,
}: {
  id?: string;
  sources: SourceOption[];
  value: string;
  onChange: (value: string) => void;
  anchor?: string | null;
  snapshot?: boolean;
}) {
  return (
    <div className="flex min-w-0 flex-1 basis-full items-center gap-2 sm:basis-auto sm:flex-none">
      <label htmlFor={id} className="shrink-0 text-xs font-medium text-slate-400">
        수집원
      </label>
      <SourceSelect id={id} sources={sources} value={value} onChange={onChange} anchor={anchor} snapshot={snapshot} />
    </div>
  );
}
