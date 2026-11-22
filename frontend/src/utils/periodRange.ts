/**
 * T34 사용자 지정 기간: 시작·끝 절대 범위(탐지 시각 기준, (시작, 끝]).
 * URL과 API는 UTC `Z` 형식(`2026-11-19T00:00:00Z`)을 쓴다. 쿼리 문자열에서 `+`가 공백으로 읽히는 문제를 피하려는 것이다.
 * 화면 입력은 브라우저 시간대와 상관없이 KST(UTC+9, 일광 절약 없음)로 읽고 쓴다. 이 파일은 `Date`의 지역 시간 메서드를 쓰지 않는다.
 * 범위 검사(시작 < 끝, 366일, 2000년 하한)는 서버(IncidentQueueService.resolveCustomRange)와 같다.
 * 시각 형식은 서버가 받는 것(ISO_OFFSET_DATE_TIME: 소문자 t·z, ±hh:mm:ss 오프셋도 받음)보다 좁아서 대문자 T·Z와 ±hh:mm만 받는다.
 */
import { formatCompactDateTime, formatDateTime } from './format';

export interface PeriodRange {
  /** 시작(불포함), UTC ISO-8601 */
  start: string;
  /** 끝(포함), UTC ISO-8601 */
  end: string;
}

const MINUTE_MS = 60_000;
const KST_OFFSET_MS = 9 * 3_600_000;
/** 지정 기간 길이 상한(366일) */
export const CUSTOM_MAX_MS = 366 * 86_400_000;
/** 지정 기간 시작 하한: 2000-01-01 00:00 KST(포함) */
export const CUSTOM_MIN_START_MS = Date.UTC(2000, 0, 1) - KST_OFFSET_MS;

const ISO_OFFSET_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})$/;
const KST_INPUT_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;

/** 날짜 부분이 실제 달력 값인가(2026-02-30 같은 값 거부) */
function validParts(y: number, mo: number, d: number, h: number, mi: number, s: number): boolean {
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return false;
  const check = new Date(Date.UTC(y, mo - 1, d));
  return check.getUTCFullYear() === y && check.getUTCMonth() === mo - 1 && check.getUTCDate() === d;
}

/** 오프셋(Z 또는 ±hh:mm)이 반드시 있는 ISO-8601 → 밀리초. 형식이 틀리면 null */
export function parseOffsetIso(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const m = ISO_OFFSET_RE.exec(raw.trim());
  if (!m) return null;
  const [y, mo, d, h, mi] = [m[1], m[2], m[3], m[4], m[5]].map(Number);
  const s = m[6] ? Number(m[6]) : 0;
  if (!validParts(y, mo, d, h, mi, s)) return null;
  const ms = m[7] ? Number(m[7].padEnd(3, '0').slice(0, 3)) : 0;
  let offset = 0;
  if (m[8] !== 'Z') {
    const sign = m[8][0] === '-' ? -1 : 1;
    const oh = Number(m[8].slice(1, 3));
    const om = Number(m[8].slice(4, 6));
    if (oh > 18 || om > 59) return null;
    offset = sign * (oh * 60 + om) * MINUTE_MS;
  }
  return Date.UTC(y, mo - 1, d, h, mi, s, ms) - offset;
}

/** 밀리초 → UTC `Z` 형식(밀리초가 0이면 뺀다): `2026-11-19T00:00:00Z` */
export function toUtcIso(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z');
}

/** 서버와 같은 검사. 맞으면 null, 틀리면 한국어 문장 */
export function rangeError(startMs: number | null, endMs: number | null): string | null {
  if (startMs === null || endMs === null) return '시작과 끝을 모두 입력하세요.';
  if (startMs >= endMs) return '시작은 끝보다 앞이어야 합니다.';
  if (endMs - startMs > CUSTOM_MAX_MS) return '기간은 366일을 넘을 수 없습니다.';
  if (startMs < CUSTOM_MIN_START_MS) return '시작은 2000-01-01 00:00 KST 이후여야 합니다.';
  return null;
}

/** URL의 start·end를 읽는다. 형식·검사가 틀리면 null */
export function parseRangeParams(start: string | null | undefined, end: string | null | undefined): PeriodRange | null {
  const s = parseOffsetIso(start);
  const e = parseOffsetIso(end);
  if (rangeError(s, e) !== null) return null;
  return { start: (start ?? '').trim(), end: (end ?? '').trim() };
}

/** 입력 칸 값(`YYYY-MM-DDTHH:mm`, KST) → 밀리초. 비었거나 틀리면 null */
export function kstInputToMs(value: string | null | undefined): number | null {
  const m = KST_INPUT_RE.exec((value ?? '').trim());
  if (!m) return null;
  const [y, mo, d, h, mi] = [m[1], m[2], m[3], m[4], m[5]].map(Number);
  if (!validParts(y, mo, d, h, mi, 0)) return null;
  return Date.UTC(y, mo - 1, d, h, mi) - KST_OFFSET_MS;
}

/** 밀리초 → 입력 칸 값(KST, 분 단위). floor는 분 내림, ceil은 분 올림 */
export function msToKstInput(ms: number, mode: 'floor' | 'ceil' = 'floor'): string {
  const minutes = mode === 'ceil' ? Math.ceil(ms / MINUTE_MS) : Math.floor(ms / MINUTE_MS);
  // KST 벽시계 값을 UTC 필드로 읽는다(지역 시간 메서드를 쓰지 않는다)
  const iso = new Date(minutes * MINUTE_MS + KST_OFFSET_MS).toISOString();
  return iso.slice(0, 16);
}

/**
 * 기간 지정 창의 처음 값: 지금 보이는 기간(응답의 periodStart·periodEnd), 전체면 기준 시각 − 24시간 ~ 기준 시각.
 * 시작은 분 내림, 끝은 분 올림이다(값을 바꾸지 않고 적용하면 범위가 1분 안쪽으로 조금 넓어진다).
 */
export function initialRangeInputs(
  periodStart: string | null | undefined,
  periodEnd: string | null | undefined,
  anchor: string | null | undefined,
  nowMs: number = Date.now(),
): { start: string; end: string } {
  let s = parseOffsetIso(periodStart);
  let e = parseOffsetIso(periodEnd);
  if (s === null || e === null) {
    e = parseOffsetIso(anchor) ?? nowMs;
    s = e - 86_400_000;
  }
  return { start: msToKstInput(s, 'floor'), end: msToKstInput(e, 'ceil') };
}

/** 입력 칸 두 값 → 범위 또는 오류 문장 */
export function rangeFromInputs(start: string, end: string): { range: PeriodRange } | { error: string } {
  const s = kstInputToMs(start);
  const e = kstInputToMs(end);
  if (s === null || e === null) return { error: '시작과 끝을 날짜와 시각(분)까지 입력하세요.' };
  const err = rangeError(s, e);
  if (err) return { error: err };
  return { range: { start: toUtcIso(s), end: toUtcIso(e) } };
}

/** 짧은 범위 글(KST): `11-19 09:00 – 11-19 12:00`. 기준 시각과 해가 다르면 연도를 붙인다 */
export function formatRangeShort(range: PeriodRange, anchor?: string | null): string {
  const ref = anchor ?? range.end;
  return `${formatCompactDateTime(range.start, ref)} – ${formatCompactDateTime(range.end, ref)}`;
}

/** 긴 범위 글(KST, 초 포함): 툴팁용 */
export function formatRangeLong(range: PeriodRange): string {
  return `${formatDateTime(range.start)} 초과 ~ ${formatDateTime(range.end)} 이하 KST`;
}

/** 두 ISO 중 늦은 것(원래 문자열을 돌려준다) */
export function laterIso(a: string, b: string | null | undefined): string {
  if (!b) return a;
  const ta = parseOffsetIso(a);
  const tb = parseOffsetIso(b);
  if (ta === null || tb === null) return a;
  return tb > ta ? b : a;
}

/** 두 ISO 중 이른 것(원래 문자열을 돌려준다) */
export function earlierIso(a: string, b: string | null | undefined): string {
  if (!b) return a;
  const ta = parseOffsetIso(a);
  const tb = parseOffsetIso(b);
  if (ta === null || tb === null) return a;
  return tb < ta ? b : a;
}
