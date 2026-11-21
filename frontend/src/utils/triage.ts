import type { IncidentQueueItem } from '../types/api';

/**
 * 인시던트 화면의 자동 분류(우선순위)·정렬·페이지 나눔 순수 함수.
 * 규칙은 SPEC.md 결정 2026-11-21 "자동 분류 우선순위 규칙 수정"과 docs/ui-terminology.md '자동 분류 기준' 절을 따른다.
 * 우선순위는 파이프라인 결과로 화면이 계산하는 값이며 분석가 판정이 아니다.
 */

export type Priority = 'high' | 'medium' | 'low';

export const PRIORITY_VALUES: readonly Priority[] = ['high', 'medium', 'low'];

export type TriageInput = Pick<
  IncidentQueueItem,
  'zeekadStatus' | 'zeekadWouldSend' | 'zeekadReviewPending' | 'zeekadAlsoFlaggedBy' | 'hasReport'
>;

/** 상태 정규화: 소문자로 비교하고 null·빈 문자열은 신규(open)로 본다. 등록되지 않은 값은 소문자 원문 그대로 둔다. */
export function normalizeStatus(status: string | null | undefined): string {
  const norm = (status ?? '').trim().toLowerCase();
  return norm === '' ? 'open' : norm;
}

/** 종료(closed)만 종료로 본다. 등록되지 않은 상태 값은 종료가 아닌 것으로 본다. */
export function isClosedStatus(status: string | null | undefined): boolean {
  return normalizeStatus(status) === 'closed';
}

/**
 * 자동 분류 우선순위. 종결된 인시던트는 null(우선순위 없음).
 * - High: 경보 발송(zeekadWouldSend) 또는 에스컬레이션 대기(zeekadReviewPending)
 * - Medium: 교차 탐지 모델이 1개 이상(2개 이상 모델 동시 탐지) 또는 AI 분석 리포트 있음(hasReport)
 * - Low: 그 밖
 */
export function computePriority(item: TriageInput): Priority | null {
  if (isClosedStatus(item.zeekadStatus)) {
    return null;
  }
  if (item.zeekadWouldSend === true || item.zeekadReviewPending === true) {
    return 'high';
  }
  if ((item.zeekadAlsoFlaggedBy ?? []).length >= 1 || item.hasReport === true) {
    return 'medium';
  }
  return 'low';
}

export type SortKey = 'priority' | 'rank' | 'start' | 'connections' | 'status';
export type SortDir = 'asc' | 'desc';

export const SORT_KEYS: readonly SortKey[] = ['priority', 'rank', 'start', 'connections', 'status'];

/** 처음 누를 때 방향: 우선순위·상태·순위는 오름(High·신규·1위 먼저), 시각·세션 수는 내림(최근·많은 것 먼저). */
export const DEFAULT_SORT_DIR: Record<SortKey, SortDir> = {
  priority: 'asc',
  rank: 'asc',
  start: 'desc',
  connections: 'desc',
  status: 'asc',
};

export const DEFAULT_SORT: { key: SortKey; dir: SortDir } = { key: 'priority', dir: 'asc' };

export function parseSortKey(raw: string | null | undefined): SortKey | null {
  return SORT_KEYS.includes(raw as SortKey) ? (raw as SortKey) : null;
}

export function parseSortDir(raw: string | null | undefined): SortDir | null {
  return raw === 'asc' || raw === 'desc' ? raw : null;
}

const PRIORITY_ORDER: Record<Priority, number> = { high: 0, medium: 1, low: 2 };

/** 상태 순서: 신규 → 분석 중 → 종결. 등록되지 않은 값은 분석 중과 종결 사이에 둔다. */
function statusOrder(status: string | null | undefined): number {
  const norm = normalizeStatus(status);
  if (norm === 'open') return 0;
  if (norm === 'investigating') return 1;
  if (norm === 'closed') return 3;
  return 2;
}

function timeValue(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : t;
}

/** 정렬 값. null은 방향과 상관없이 맨 뒤로 보낸다(종결 인시던트의 우선순위, 세션 수·시각 없음). */
function sortValue(item: IncidentQueueItem, key: SortKey): number | null {
  switch (key) {
    case 'priority': {
      const p = computePriority(item);
      return p === null ? null : PRIORITY_ORDER[p];
    }
    case 'rank':
      return item.queueRank;
    case 'start':
      return timeValue(item.eventStart);
    case 'connections':
      return item.connectionCount ?? null;
    case 'status':
      return statusOrder(item.zeekadStatus);
    default:
      return null;
  }
}

/** 정렬한 새 배열을 돌려준다. 같은 값이면 2차 키는 queueRank 오름차순이다. */
export function sortIncidents(items: readonly IncidentQueueItem[], key: SortKey, dir: SortDir): IncidentQueueItem[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    const va = sortValue(a, key);
    const vb = sortValue(b, key);
    if (va === null && vb !== null) return 1;
    if (va !== null && vb === null) return -1;
    if (va !== null && vb !== null && va !== vb) {
      return (va - vb) * sign;
    }
    return a.queueRank - b.queueRank;
  });
}

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 50;

/** 허용 밖 size는 50으로 고친다. */
export function parsePageSize(raw: string | null | undefined): number {
  const n = Number(raw);
  return (PAGE_SIZES as readonly number[]).includes(n) ? n : DEFAULT_PAGE_SIZE;
}

export interface PageWindow {
  page: number;
  pageCount: number;
  /** 1부터 세는 첫 항목 번호(항목이 없으면 0) */
  from: number;
  /** 마지막 항목 번호(항목이 없으면 0) */
  to: number;
  startIndex: number;
  endIndex: number;
}

/** 쪽 번호를 고친다: 숫자가 아니거나 1보다 작으면 1쪽, 범위 밖이면 마지막 쪽. */
export function pageWindow(total: number, rawPage: string | null | undefined, size: number): PageWindow {
  const pageCount = Math.max(1, Math.ceil(total / size));
  const parsed = Number(rawPage);
  let page = Number.isInteger(parsed) && parsed >= 1 ? parsed : 1;
  if (page > pageCount) {
    page = pageCount;
  }
  const startIndex = (page - 1) * size;
  const endIndex = Math.min(total, startIndex + size);
  return {
    page,
    pageCount,
    from: total === 0 ? 0 : startIndex + 1,
    to: endIndex,
    startIndex,
    endIndex,
  };
}

/* ───────────── 목록 보기(화면 필터·정렬)와 상세 이전·다음(T19) ───────────── */

/** 서버로 보내는 필터(API 파라미터). 응답 incidents는 서버가 이미 거른 집합이다. */
export const SERVER_FILTER_KEYS = ['pickedBy', 'role', 'status', 'hasReport', 'wouldSend', 'asset'] as const;
/** 응답 집합 위에서 화면이 거르는 필터 */
export const CLIENT_FILTER_KEYS = ['priority', 'reviewPending', 'alerted'] as const;

export interface ClientFilters {
  priority: Priority | null;
  reviewPending: boolean;
  alerted: boolean;
}

export interface QueueView extends ClientFilters {
  sortKey: SortKey;
  sortDir: SortDir;
}

/** 목록 URL 쿼리에서 화면 필터와 정렬을 읽는다(목록 화면과 상세의 이전·다음이 같은 규칙을 쓴다). */
export function parseQueueView(params: URLSearchParams): QueueView {
  const priorityRaw = params.get('priority');
  const priority = PRIORITY_VALUES.includes(priorityRaw as Priority) ? (priorityRaw as Priority) : null;
  const parsedKey = parseSortKey(params.get('sort'));
  const sortKey: SortKey = parsedKey ?? DEFAULT_SORT.key;
  const sortDir: SortDir = parseSortDir(params.get('dir')) ?? (parsedKey ? DEFAULT_SORT_DIR[sortKey] : DEFAULT_SORT.dir);
  return {
    priority,
    reviewPending: params.get('reviewPending') === 'true',
    alerted: params.get('alerted') === 'true',
    sortKey,
    sortDir,
  };
}

/** 화면 필터(우선순위·에스컬레이션 대기·경보 발송)를 적용한다. */
export function applyClientFilters(items: readonly IncidentQueueItem[], filters: ClientFilters): IncidentQueueItem[] {
  return items.filter((item) => {
    if (filters.priority && computePriority(item) !== filters.priority) return false;
    if (filters.reviewPending && !item.zeekadReviewPending) return false;
    if (filters.alerted && !item.zeekadWouldSend) return false;
    return true;
  });
}

/** 목록 화면과 같은 순서: 화면 필터 → 정렬. */
export function orderQueue(items: readonly IncidentQueueItem[], view: QueueView): IncidentQueueItem[] {
  return sortIncidents(applyClientFilters(items, view), view.sortKey, view.sortDir);
}

export interface NeighborResult {
  /** 0부터 센 현재 위치. 목록에 없으면 -1 */
  index: number;
  total: number;
  prev: IncidentQueueItem | null;
  next: IncidentQueueItem | null;
}

/** 정렬된 목록에서 현재 인시던트(탐지 작업 + 순위)의 앞뒤를 찾는다. */
export function findNeighbors(ordered: readonly IncidentQueueItem[], jobId: number, queueRank: number): NeighborResult {
  const index = ordered.findIndex((it) => it.jobId === jobId && it.queueRank === queueRank);
  return {
    index,
    total: ordered.length,
    prev: index > 0 ? ordered[index - 1] : null,
    next: index >= 0 && index < ordered.length - 1 ? ordered[index + 1] : null,
  };
}
