import type { QueuePriority, SourceType } from '../types/api';

/**
 * 인시던트 큐(T23 통합 큐)의 URL 쿼리 해석과 API 파라미터 만들기.
 * 우선순위 계산·정렬·쪽 나눔·요약은 서버(GET /api/incidents/queue)가 한다. 화면은 서버 값을 그대로 보인다.
 * 우선순위 규칙은 SPEC.md 결정 2026-11-21 "자동 분류 우선순위 규칙 수정"이며 서버 SQL(ZeekadReadMapper.xml unifiedQueueBase)에 한 번만 있다.
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

export type Period = '1h' | '24h' | '7d' | '30d' | 'all';

export const PERIODS: readonly { value: Period; label: string }[] = [
  { value: '1h', label: '1시간' },
  { value: '24h', label: '24시간' },
  { value: '7d', label: '7일' },
  { value: '30d', label: '30일' },
  { value: 'all', label: '전체' },
];

export const DEFAULT_PERIOD: Period = '24h';

export function parsePeriod(raw: string | null | undefined): Period {
  return PERIODS.some((p) => p.value === raw) ? (raw as Period) : DEFAULT_PERIOD;
}

export function periodLabel(period: Period): string {
  return PERIODS.find((p) => p.value === period)?.label ?? period;
}

export function parseSource(raw: string | null | undefined): SourceType | null {
  return raw === 'live' || raw === 'imported' ? raw : null;
}

/* ───────────── 목록 쿼리 ───────────── */

/** 필터 패널의 거르기(칩으로 보인다) */
export const PANEL_FILTER_KEYS = ['pickedBy', 'role', 'status', 'hasReport', 'wouldSend', 'asset'] as const;
/** 요약 띠의 거르기(띠를 눌러 켜고 끈다) */
export const STRIP_FILTER_KEYS = ['priority', 'reviewPending', 'alerted'] as const;

export interface QueueQuery {
  period: Period;
  source: SourceType | null;
  captureId: string | null;
  priority: Priority | null;
  reviewPending: boolean;
  alerted: boolean;
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
  return {
    period: parsePeriod(params.get('period')),
    source: parseSource(params.get('source')),
    captureId: captureId === '' ? null : captureId,
    priority: PRIORITY_VALUES.includes(priorityRaw as Priority) ? (priorityRaw as Priority) : null,
    reviewPending: params.get('reviewPending') === 'true',
    alerted: params.get('alerted') === 'true',
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
  const out: Record<string, string | undefined> = {
    period: period ? q.period : undefined,
    source: q.source ?? undefined,
    captureId: q.captureId ?? undefined,
    priority: q.priority ?? undefined,
    reviewPending: q.reviewPending ? 'true' : undefined,
    alerted: q.alerted ? 'true' : undefined,
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
