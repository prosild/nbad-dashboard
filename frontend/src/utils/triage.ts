import type { QueuePriority, SourceType } from '../types/api';
import { formatRangeShort, parseRangeParams, type PeriodRange } from './periodRange';

/**
 * 인시던트 큐(T23 통합 큐)의 URL 쿼리 해석과 API 파라미터 만들기.
 * 우선순위 계산·정렬·쪽 나눔·요약은 서버(GET /api/incidents/queue)가 한다. 화면은 서버 값을 그대로 보인다.
 * 우선순위 규칙은 2026-11-21 결정 "자동 분류 우선순위 규칙 수정"(docs/design-decisions.md)이며 서버 SQL(ZeekadReadMapper.xml unifiedQueueBase)에 한 번만 있다.
 */

export type Priority = QueuePriority;

export const PRIORITY_VALUES: readonly Priority[] = ['high', 'medium', 'low'];

/** 상태 정규화: 소문자로 비교하고 null·빈 문자열은 신규(open)로 본다. 등록되지 않은 값은 소문자 원문 그대로 둔다. */
export function normalizeStatus(status: string | null | undefined): string {
  const norm = (status ?? '').trim().toLowerCase();
  return norm === '' ? 'open' : norm;
}

/** 종료(closed)만 종료로 본다. 등록되지 않은 상태 값은 종료가 아닌 것으로 본다. */
export function isClosedStatus(status: string | null | undefined): boolean {
  return normalizeStatus(status) === 'closed';
}

/* ───────────── 정렬·쪽 ───────────── */

export type SortKey = 'priority' | 'detected' | 'start' | 'connections' | 'status';
export type SortDir = 'asc' | 'desc';

export const SORT_KEYS: readonly SortKey[] = ['priority', 'detected', 'start', 'connections', 'status'];

/** 처음 누를 때 방향: 우선순위·상태는 오름(High·신규 먼저), 시각·세션 수는 내림(최근·많은 것 먼저). 서버 기본과 같다. */
export const DEFAULT_SORT_DIR: Record<SortKey, SortDir> = {
  priority: 'asc',
  detected: 'desc',
  start: 'desc',
  connections: 'desc',
  status: 'asc',
};

/** 기본 정렬: 우선순위 오름 → (같으면) 탐지 시각 최근(서버 2차 정렬) */
export const DEFAULT_SORT: { key: SortKey; dir: SortDir } = { key: 'priority', dir: 'asc' };

export function parseSortKey(raw: string | null | undefined): SortKey | null {
  return SORT_KEYS.includes(raw as SortKey) ? (raw as SortKey) : null;
}

export function parseSortDir(raw: string | null | undefined): SortDir | null {
  return raw === 'asc' || raw === 'desc' ? raw : null;
}

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 50;

/** 허용 밖 size는 50으로 고친다. */
export function parsePageSize(raw: string | null | undefined): number {
  const n = Number(raw);
  return (PAGE_SIZES as readonly number[]).includes(n) ? n : DEFAULT_PAGE_SIZE;
}

/** 쪽 번호: 숫자가 아니거나 1보다 작으면 1. 범위 밖은 서버가 마지막 쪽으로 고쳐 돌려준다. */
export function parsePage(raw: string | null | undefined): number {
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 ? n : 1;
}

/* ───────────── 기간·수집원 ───────────── */

/** 기간 프리셋(버튼) */
export type PresetPeriod = '1h' | '24h' | '7d' | '30d' | 'all';
/** T34: 프리셋 또는 사용자 지정 기간(custom, 시작·끝은 URL start·end) */
export type Period = PresetPeriod | 'custom';

export const PERIODS: readonly { value: PresetPeriod; label: string }[] = [
  { value: '1h', label: '1시간' },
  { value: '24h', label: '24시간' },
  { value: '7d', label: '7일' },
  { value: '30d', label: '30일' },
  { value: 'all', label: '전체' },
];

export const DEFAULT_PERIOD: PresetPeriod = '24h';

/** 프리셋만 읽는다(custom·허용 밖 값은 기본 기간 24시간) */
export function parsePeriod(raw: string | null | undefined): PresetPeriod {
  return PERIODS.some((p) => p.value === raw) ? (raw as PresetPeriod) : DEFAULT_PERIOD;
}

export function periodLabel(period: Period): string {
  if (period === 'custom') return '기간 지정';
  return PERIODS.find((p) => p.value === period)?.label ?? period;
}

/** T34 기간 선택: custom이면 range가 있다(그 밖에는 null) */
export interface PeriodSelection {
  period: Period;
  range: PeriodRange | null;
}

/**
 * URL의 period·start·end를 읽는다. period=custom이면 start·end를 서버와 같은 규칙으로 검사하고 틀리면 그 화면의 기본 기간이다.
 * 프리셋·전체에 섞여 온 start·end는 버린다(API에도 보내지 않는다). period가 없으면 화면 기본 기간, 허용 밖이면 24시간(지금과 같다).
 */
export function parsePeriodSelection(params: URLSearchParams, screenDefault: PresetPeriod): PeriodSelection {
  const raw = params.get('period');
  if (!raw) return { period: screenDefault, range: null };
  if (raw === 'custom') {
    const range = parseRangeParams(params.get('start'), params.get('end'));
    return range ? { period: 'custom', range } : { period: screenDefault, range: null };
  }
  return { period: parsePeriod(raw), range: null };
}

/** API 파라미터: period와 (custom이면) start·end */
export function periodApiParams(sel: PeriodSelection): { period: string; start?: string; end?: string } {
  if (sel.period === 'custom' && sel.range) return { period: 'custom', start: sel.range.start, end: sel.range.end };
  return { period: sel.period };
}

/** URL 변경: 프리셋·전체를 고르면 start·end를 지운다. 화면 기본 기간이면 period도 지운다 */
export function presetUrlChanges(period: PresetPeriod, screenDefault: PresetPeriod): Record<string, string | null> {
  return { period: period === screenDefault ? null : period, start: null, end: null };
}

/** URL 변경: 지정 기간 */
export function customUrlChanges(range: PeriodRange): Record<string, string | null> {
  return { period: 'custom', start: range.start, end: range.end };
}

/** 링크 쿼리에 기간을 쓴다(period와 custom이면 start·end) */
export function setPeriodParams(q: URLSearchParams, sel: PeriodSelection): URLSearchParams {
  q.set('period', sel.period);
  if (sel.period === 'custom' && sel.range) {
    q.set('start', sel.range.start);
    q.set('end', sel.range.end);
  } else {
    q.delete('start');
    q.delete('end');
  }
  return q;
}

/** 기간 범위 글: "최근 24시간" / "전체 기간" / "11-19 09:00 – 11-19 12:00" */
export function periodScopeText(sel: PeriodSelection, anchor?: string | null): string {
  if (sel.period === 'custom' && sel.range) return formatRangeShort(sel.range, anchor);
  if (sel.period === 'all') return '전체 기간';
  return `최근 ${periodLabel(sel.period)}`;
}

export function parseSource(raw: string | null | undefined): SourceType | null {
  return raw === 'live' || raw === 'imported' ? raw : null;
}

/* ───────────── 목록 쿼리 ───────────── */

/** 필터 패널의 거르기(칩으로 보인다) */
export const PANEL_FILTER_KEYS = ['pickedBy', 'role', 'status', 'hasReport', 'wouldSend', 'asset'] as const;
/** 요약 띠의 거르기(띠를 눌러 켜고 끈다). overdue = 착수 지연(T25) */
export const STRIP_FILTER_KEYS = ['priority', 'reviewPending', 'alerted', 'overdue'] as const;

/** 담당 조건(T25): 전체(null) · 내 담당 · 미배정 */
export type AssigneeFilter = 'me' | 'none';

export function parseAssignee(raw: string | null | undefined): AssigneeFilter | null {
  return raw === 'me' || raw === 'none' ? raw : null;
}

export interface QueueQuery {
  period: Period;
  /** T34 지정 기간(period=custom일 때만) */
  range: PeriodRange | null;
  source: SourceType | null;
  captureId: string | null;
  priority: Priority | null;
  reviewPending: boolean;
  alerted: boolean;
  /** T25 착수 지연만 */
  overdue: boolean;
  /** T25 담당 조건 */
  assignee: AssigneeFilter | null;
  pickedBy: string;
  role: string;
  status: string;
  hasReport: string;
  wouldSend: string;
  asset: string;
  sortKey: SortKey;
  sortDir: SortDir;
  page: number;
  size: number;
}

/** 목록 URL 쿼리를 읽는다(목록 화면과 상세의 이전·다음이 같은 규칙을 쓴다). 허용 밖 값은 기본값으로 읽는다. */
export function parseQueueQuery(params: URLSearchParams): QueueQuery {
  const priorityRaw = params.get('priority');
  const parsedKey = parseSortKey(params.get('sort'));
  const sortKey: SortKey = parsedKey ?? DEFAULT_SORT.key;
  const sortDir: SortDir = parseSortDir(params.get('dir')) ?? (parsedKey ? DEFAULT_SORT_DIR[sortKey] : DEFAULT_SORT.dir);
  const captureId = (params.get('captureId') ?? '').trim();
  const sel = parsePeriodSelection(params, DEFAULT_PERIOD);
  return {
    period: sel.period,
    range: sel.range,
    source: parseSource(params.get('source')),
    captureId: captureId === '' ? null : captureId,
    priority: PRIORITY_VALUES.includes(priorityRaw as Priority) ? (priorityRaw as Priority) : null,
    reviewPending: params.get('reviewPending') === 'true',
    alerted: params.get('alerted') === 'true',
    overdue: params.get('overdue') === 'true',
    assignee: parseAssignee(params.get('assignee')),
    pickedBy: params.get('pickedBy') ?? '',
    role: params.get('role') ?? '',
    status: params.get('status') ?? '',
    hasReport: params.get('hasReport') ?? '',
    wouldSend: params.get('wouldSend') ?? '',
    asset: params.get('asset') ?? '',
    sortKey,
    sortDir,
    page: parsePage(params.get('page')),
    size: parsePageSize(params.get('size')),
  };
}

/** 서버 API 파라미터. paging=false면 쪽 번호·크기를 빼고(이전·다음), sort=false면 정렬도 뺀다(새 인시던트 수). */
export function queueApiParams(
  q: QueueQuery,
  opts: { paging?: boolean; sort?: boolean; period?: boolean } = {},
): Record<string, string | undefined> {
  const { paging = true, sort = true, period = true } = opts;
  const custom = period && q.period === 'custom' && q.range;
  const out: Record<string, string | undefined> = {
    period: period ? q.period : undefined,
    start: custom ? q.range?.start : undefined,
    end: custom ? q.range?.end : undefined,
    source: q.source ?? undefined,
    captureId: q.captureId ?? undefined,
    priority: q.priority ?? undefined,
    reviewPending: q.reviewPending ? 'true' : undefined,
    alerted: q.alerted ? 'true' : undefined,
    overdue: q.overdue ? 'true' : undefined,
    assignee: q.assignee ?? undefined,
    pickedBy: q.pickedBy || undefined,
    role: q.role || undefined,
    status: q.status || undefined,
    hasReport: q.hasReport || undefined,
    wouldSend: q.wouldSend || undefined,
    asset: q.asset || undefined,
  };
  if (sort) {
    out.sort = q.sortKey;
    out.dir = q.sortDir;
  }
  if (paging) {
    out.page = String(q.page);
    out.size = String(q.size);
  }
  return out;
}

/** 옛 주소 안내(T23): 탐지 작업 선택이 없어졌다 */
export const LEGACY_JOB_NOTICE = '이전 주소의 탐지 작업 선택은 더 쓰지 않습니다. 최신 결과를 보여 줍니다.';

/**
 * 옛 쿼리 정리(T23): jobId는 지우고(안내를 한 번 보인다), sort=rank(캡처 안 순위)는 기본 정렬로 바꾼다.
 * captureId는 그대로 두어 수집원 안의 캡처 선택으로 읽는다.
 */
export function migrateLegacyQueueParams(params: URLSearchParams): {
  next: URLSearchParams;
  changed: boolean;
  droppedJob: boolean;
} {
  const next = new URLSearchParams(params);
  let changed = false;
  let droppedJob = false;
  if (next.has('jobId')) {
    next.delete('jobId');
    changed = true;
    droppedJob = true;
  }
  if (next.get('sort') === 'rank') {
    next.delete('sort');
    next.delete('dir');
    changed = true;
  }
  return { next, changed, droppedJob };
}
