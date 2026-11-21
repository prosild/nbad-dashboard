/**
 * 공통 조건 줄(T24): 기간 버튼과 수집원 선택. 인시던트 큐·현황판·운영 현황이 같이 쓴다.
 * URL 쿼리(period·source·captureId)가 상태의 원본이며, 화면마다 기본 기간이 다르다(큐·현황판 24시간, 운영 현황 7일).
 */
import type { SourceType } from '../types/api';
import { captureInfo } from '../utils/labels';
import { PERIODS, type Period } from '../utils/triage';
import { SOURCE_TYPE_LABEL } from './StatusBadge';

/** 수집원 선택 목록에 쓰는 최소 정보(큐 sources·overview captures) */
export interface SourceOption {
  captureId: string;
  sourceType: SourceType;
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

export function PeriodButtons({ value, onChange }: { value: Period; onChange: (value: Period) => void }) {
  return (
    <div className="flex items-center gap-2" role="group" aria-label="기간">
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
    </div>
  );
}

export function SourceSelect({
  id = 'filter-source',
  sources,
  value,
  onChange,
}: {
  id?: string;
  sources: SourceOption[];
  value: string;
  onChange: (value: string) => void;
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
            {SOURCE_TYPE_LABEL[g]} 전체
          </option>,
          members.length > 0 ? (
            <optgroup key={`grp-${g}`} label={SOURCE_TYPE_LABEL[g]}>
              {members.map((s) => {
                const info = captureInfo(s.captureId);
                return (
                  <option key={s.captureId} value={`cap:${s.captureId}`} title={info.tooltip}>
                    {info.text}
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
}: {
  id?: string;
  sources: SourceOption[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex min-w-0 flex-1 basis-full items-center gap-2 sm:basis-auto sm:flex-none">
      <label htmlFor={id} className="shrink-0 text-xs font-medium text-slate-400">
        수집원
      </label>
      <SourceSelect id={id} sources={sources} value={value} onChange={onChange} />
    </div>
  );
}
