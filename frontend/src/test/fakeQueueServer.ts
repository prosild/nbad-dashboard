import type {
  IncidentQueueItem,
  QueueNeighborsResponse,
  QueueNewCountResponse,
  UnifiedQueueItem,
  UnifiedQueueResponse,
} from '../types/api';

/**
 * T23 시험용 가짜 통합 큐 서버. 실제 거르기·정렬·쪽 나눔·요약은 서버(SQL)가 하므로 화면 시험은 이 가짜가 돌려준 값을
 * 화면이 그대로 그리는지와 화면이 보낸 파라미터를 본다. 정렬 규칙은 서버와 같게 둔다(값 없음 맨 뒤 → 탐지 시각 최근 → 캡처 → 순위).
 * 우선순위는 시험 데이터가 정한 값(priority)을 쓴다(계산하지 않는다).
 */

export interface FakeQueueOptions {
  items: UnifiedQueueItem[];
  anchor?: string;
  snapshot?: boolean;
  /** 기간 결과가 0건일 때 돌려줄 기간 밖 최근 탐지 시각(시험이 정한다) */
  newestOutsidePeriod?: string | null;
  /** T29: 결과가 있어도 newestOutsidePeriod를 돌려준다(서버 T29 동작) */
  newestOutsideAlways?: boolean;
  /** T29: 수집원별 마지막 탐지(없으면 sources에 lastDetectedAt을 넣지 않는다) */
  lastDetected?: Record<string, string | null>;
  /** 기간별로 보일 항목을 바꾸고 싶으면 넣는다(없으면 기간과 상관없이 모두) */
  periodFilter?: (item: UnifiedQueueItem, period: string) => boolean;
  availableModels?: string[];
  availableRoles?: string[];
  maskedView?: boolean;
  /** T25: assignee=me가 가리킬 로그인 사용자 이름(기본 analyst1) */
  me?: string;
}

export function unified(
  base: IncidentQueueItem,
  extra: Partial<
    Pick<UnifiedQueueItem, 'detectedAt' | 'sourceType' | 'priority' | 'ongoing' | 'assignee' | 'ackDueAt' | 'ackOverdue'>
  > = {},
): UnifiedQueueItem {
  return {
    ...base,
    detectedAt: extra.detectedAt ?? '2026-11-20T00:00:00Z',
    sourceType: extra.sourceType ?? (base.captureId.startsWith('lab-') ? 'live' : 'imported'),
    priority: extra.priority === undefined ? 'low' : extra.priority,
    ongoing: extra.ongoing ?? false,
    assignee: extra.assignee ?? null,
    ackDueAt: extra.ackDueAt ?? null,
    ackOverdue: extra.ackOverdue ?? false,
  };
}

const PRIORITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

function statusOrder(s: string | null): number {
  const n = (s ?? '').trim().toLowerCase();
  if (n === '' || n === 'open') return 0;
  if (n === 'investigating') return 1;
  if (n === 'closed') return 3;
  return 2;
}

function time(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : t;
}

function sortValue(it: UnifiedQueueItem, key: string): number | null {
  switch (key) {
    case 'detected':
      return time(it.detectedAt);
    case 'start':
      return time(it.eventStart);
    case 'connections':
      return it.connectionCount;
    case 'status':
      return statusOrder(it.zeekadStatus);
    default:
      return it.priority === null ? null : PRIORITY_ORDER[it.priority];
  }
}

export function sortLikeServer(items: UnifiedQueueItem[], key: string, dir: string): UnifiedQueueItem[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    const va = sortValue(a, key);
    const vb = sortValue(b, key);
    if (va === null && vb !== null) return 1;
    if (va !== null && vb === null) return -1;
    if (va !== null && vb !== null && va !== vb) return (va - vb) * sign;
    if (key !== 'detected') {
      const da = time(a.detectedAt);
      const db = time(b.detectedAt);
      if (da === null && db !== null) return 1;
      if (da !== null && db === null) return -1;
      if (da !== null && db !== null && da !== db) return db - da;
    }
    if (a.captureId !== b.captureId) return a.captureId < b.captureId ? -1 : 1;
    return a.queueRank - b.queueRank;
  });
}

const DEFAULT_DIR: Record<string, string> = {
  priority: 'asc',
  detected: 'desc',
  start: 'desc',
  connections: 'desc',
  status: 'asc',
};

function filterBase(items: UnifiedQueueItem[], p: URLSearchParams, opts: FakeQueueOptions): UnifiedQueueItem[] {
  const period = p.get('period') ?? '24h';
  return items.filter((it) => {
    if (opts.periodFilter && !opts.periodFilter(it, period)) return false;
    if (p.get('source') && it.sourceType !== p.get('source')) return false;
    if (p.get('captureId') && it.captureId !== p.get('captureId')) return false;
    if (p.get('pickedBy') && it.zeekadPickedBy !== p.get('pickedBy')) return false;
    if (p.get('role') && it.zeekadRole !== p.get('role')) return false;
    if (p.get('status') && (it.zeekadStatus ?? 'open').toLowerCase() !== p.get('status')) return false;
    if (p.get('hasReport') === 'true' && !it.hasReport) return false;
    if (p.get('hasReport') === 'false' && it.hasReport) return false;
    if (p.get('wouldSend') === 'true' && !it.zeekadWouldSend) return false;
    if (p.get('wouldSend') === 'false' && it.zeekadWouldSend) return false;
    // T25 담당 조건(일반 조건)
    if (p.get('assignee') === 'me' && it.assignee?.username !== (opts.me ?? 'analyst1')) return false;
    if (p.get('assignee') === 'none' && it.assignee) return false;
    const asset = (p.get('asset') ?? '').toLowerCase();
    if (asset && !it.hostIp.toLowerCase().includes(asset) && !it.hostName.some((h) => h.toLowerCase().includes(asset)))
      return false;
    return true;
  });
}

function filterStrip(items: UnifiedQueueItem[], p: URLSearchParams): UnifiedQueueItem[] {
  return items.filter((it) => {
    if (p.get('priority') && it.priority !== p.get('priority')) return false;
    if (p.get('reviewPending') === 'true' && !it.zeekadReviewPending) return false;
    if (p.get('alerted') === 'true' && !it.alerted) return false;
    if (p.get('overdue') === 'true' && !it.ackOverdue) return false;
    return true;
  });
}

export function fakeQueue(url: string, opts: FakeQueueOptions): UnifiedQueueResponse {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const base = filterBase(opts.items, p, opts);
  const filtered = filterStrip(base, p);
  const key = p.get('sort') ?? 'priority';
  const dir = p.get('dir') ?? DEFAULT_DIR[key] ?? 'asc';
  const sorted = sortLikeServer(filtered, key, dir);
  const sizeRaw = Number(p.get('size'));
  const size = [25, 50, 100].includes(sizeRaw) ? sizeRaw : 50;
  const pageCount = Math.max(1, Math.ceil(sorted.length / size));
  const pageRaw = Number(p.get('page'));
  const page = Math.min(Number.isInteger(pageRaw) && pageRaw >= 1 ? pageRaw : 1, pageCount);
  const byStatus: Record<string, number> = { open: 0, investigating: 0, closed: 0, other: 0 };
  for (const it of base) {
    const o = statusOrder(it.zeekadStatus);
    byStatus[o === 0 ? 'open' : o === 1 ? 'investigating' : o === 3 ? 'closed' : 'other'] += 1;
  }
  const latest = sorted
    .map((it) => it.detectedAt)
    .filter((d): d is string => Boolean(d))
    .sort()
    .pop();
  return {
    items: sorted.slice((page - 1) * size, page * size),
    total: sorted.length,
    page,
    size,
    pageCount,
    summary: {
      total: base.length,
      high: base.filter((i) => i.priority === 'high').length,
      medium: base.filter((i) => i.priority === 'medium').length,
      low: base.filter((i) => i.priority === 'low').length,
      reviewPending: base.filter((i) => i.zeekadReviewPending).length,
      alerted: base.filter((i) => i.alerted).length,
      byStatus,
      overdue: base.filter((i) => i.ackOverdue).length,
    },
    anchor: opts.anchor ?? '2026-11-21T00:00:00Z',
    anchorMode: opts.snapshot ? 'latest-data' : 'now',
    snapshot: Boolean(opts.snapshot),
    period: p.get('period') ?? '24h',
    // T34 실제 기간 경계(서버와 같다): 프리셋은 (기준 시각 − P, 기준 시각], 전체는 null, 지정 기간은 받은 값
    ...periodBounds(p, opts.anchor ?? '2026-11-21T00:00:00Z'),
    latestDetectedAt: latest ?? null,
    newestOutsidePeriod:
      sorted.length === 0 || opts.newestOutsideAlways ? (opts.newestOutsidePeriod ?? null) : null,
    // T29 기간 밖 수 = 같은 조건 기간 전체 수 − 지금 수
    outsidePeriod:
      (p.get('period') ?? '24h') === 'all'
        ? 0
        : filterStrip(filterBase(opts.items, p, { ...opts, periodFilter: undefined }), p).length - sorted.length,
    sources: [...new Set(opts.items.map((i) => i.captureId))].sort().map((captureId) => ({
      captureId,
      sourceType: captureId.startsWith('lab-') ? ('live' as const) : ('imported' as const),
      latestJobId: opts.items.find((i) => i.captureId === captureId)?.jobId ?? null,
      ...(opts.lastDetected ? { lastDetectedAt: opts.lastDetected[captureId] ?? null } : {}),
    })),
    maskedView: Boolean(opts.maskedView),
    availableModels: opts.availableModels ?? [...new Set(opts.items.map((i) => i.zeekadPickedBy ?? ''))].filter(Boolean),
    availableRoles: opts.availableRoles ?? ['originator', 'responder'],
  };
}

export function fakeNewCount(url: string, opts: FakeQueueOptions): QueueNewCountResponse {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const since = p.get('since') ?? '';
  const sinceT = new Date(since).getTime();
  const all = filterStrip(filterBase(opts.items, new URLSearchParams([...p.entries(), ['period', 'all']]), { ...opts, periodFilter: undefined }), p);
  const newer = all.filter((i) => i.detectedAt && new Date(i.detectedAt).getTime() > sinceT);
  const latest = newer.map((i) => i.detectedAt as string).sort().pop() ?? null;
  return { count: newer.length, latestDetectedAt: latest, since };
}

export function fakeNeighbors(url: string, opts: FakeQueueOptions): QueueNeighborsResponse {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const jobId = Number(p.get('jobId'));
  const rank = Number(p.get('queueRank'));
  const viewed = opts.items.find((i) => i.jobId === jobId && i.queueRank === rank);
  const ordered = sortLikeServer(
    filterStrip(filterBase(opts.items, p, opts), p),
    p.get('sort') ?? 'priority',
    p.get('dir') ?? DEFAULT_DIR[p.get('sort') ?? 'priority'] ?? 'asc',
  );
  const key = (i: UnifiedQueueItem) => ({ jobId: i.jobId, queueRank: i.queueRank, hostIp: i.hostIp });
  if (!viewed) return { current: null, position: null, total: ordered.length, prev: null, next: null };
  const idx = ordered.findIndex((i) => i.jobId === jobId && i.queueRank === rank);
  if (idx < 0) return { current: key(viewed), position: null, total: ordered.length, prev: null, next: null };
  return {
    current: key(viewed),
    position: idx + 1,
    total: ordered.length,
    prev: idx > 0 ? key(ordered[idx - 1]) : null,
    next: idx < ordered.length - 1 ? key(ordered[idx + 1]) : null,
  };
}

/** T34 서버와 같은 기간 경계(UTC). 프리셋은 (기준 시각 − P, 기준 시각], 전체는 null, 지정 기간은 받은 start·end */
const PRESET_MS: Record<string, number> = { '1h': 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000, '30d': 30 * 86_400_000 };
export function periodBounds(p: URLSearchParams, anchor: string): { periodStart: string | null; periodEnd: string | null } {
  const period = p.get('period') ?? '24h';
  if (period === 'custom') return { periodStart: p.get('start'), periodEnd: p.get('end') };
  const len = PRESET_MS[period];
  if (len === undefined) return { periodStart: null, periodEnd: null };
  const a = new Date(anchor).getTime();
  return { periodStart: new Date(a - len).toISOString(), periodEnd: new Date(a).toISOString() };
}
