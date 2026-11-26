import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { DetailHeader } from '../components/incident/DetailHeader';
import { RelatedHostIncidents } from '../components/incident/RelatedHostIncidents';
import { PRIORITY_COLUMN_TOOLTIP, PRIORITY_TOOLTIP } from '../components/StatusBadge';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentQueueItem, IncidentQueueMeta, UnifiedQueueItem } from '../types/api';
import type { HostRiskItem, RelatedHostIncident } from '../types/hosts';
import { incidentMarkdown, QUEUE_CSV_HEADERS, queueCsv } from '../utils/incidentExport';
import { labelText } from '../utils/labels';
import { baseDetail, DEFAULT_META } from './detailFixture';
import { fakeQueue, unified } from './fakeQueueServer';

/**
 * T52 중요 자산 화면: 우선순위 배지 옆 표지와 툴팁(올림·이미 High·종결·조회자 대역), 보이는 글(상세 "중요 자산 · Medium → High"),
 * 큐 표·휴대폰 카드·상세 머리줄·같은 호스트 인시던트·호스트 위험도, 조회자에게 이름이 보이지 않음, "자동 분류 기준" 안내,
 * CSV·마크다운의 "중요 자산" 칸(예/아니요, 이름 없음), 관리자 화면(목록·추가·검증 오류·지우기 확인), 메뉴는 관리자만.
 */

const NAME = '결제 서버';
const RAISED = '중요 자산으로 등록된 호스트라 자동 분류 우선순위를 한 단계 올렸습니다(Medium → High)';
const RAISED_LOW = '중요 자산으로 등록된 호스트라 자동 분류 우선순위를 한 단계 올렸습니다(Low → Medium)';
const ALREADY_HIGH = '중요 자산으로 등록된 호스트입니다. 이미 High라 우선순위는 그대로입니다';
const PLAIN = '중요 자산으로 등록된 호스트입니다';
const BAND = '이 대역에 중요 자산으로 등록된 호스트가 있습니다';
const withName = (text: string) => `${text}\n중요 자산: ${NAME}`;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

type Role = 'ANALYST' | 'ADMIN' | 'VIEWER';
const userOf = (role: Role) => ({
  username: role.toLowerCase(),
  displayName: role,
  role,
  maskedView: role === 'VIEWER',
  totpEnabled: role === 'ADMIN',
  totpVerified: true,
  totpRequired: role === 'ADMIN',
  allowedCapturePatterns: ['*'],
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** 표지(배지)를 찾는다: data-critical-asset 속성이 있는 요소 */
function badgesIn(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>('[data-critical-asset]'));
}

/** 화면 읽기 글(.sr-only)을 뺀 보이는 글 */
function visibleText(el: HTMLElement): string {
  const copy = el.cloneNode(true) as HTMLElement;
  copy.querySelectorAll('.sr-only').forEach((n) => n.remove());
  return (copy.textContent ?? '').trim();
}

/* ───────────── 자료 ───────────── */

function base(i: number, host: string, masked = false): IncidentQueueItem {
  return {
    jobId: 50,
    captureId: 'lab-20261119',
    bundleId: 'zeekad-fusion/3',
    queueRank: i,
    incidentId: masked ? `lab-20261119|10.52.*.*|originator|${i}` : `lab-20261119|${host}|originator|${i}`,
    hostIp: masked ? '10.52.*.*' : host,
    zeekadRole: 'originator',
    eventStart: '2026-11-20T00:00:00Z',
    eventEnd: '2026-11-20T00:30:00Z',
    zeekadPickedBy: 'ae_v2',
    zeekadAlsoFlaggedBy: [],
    connectionCount: 10 * i,
    hostName: [],
    zeekadStatus: i === 3 ? 'closed' : 'open',
    zeekadResolution: i === 3 ? 'benign' : null,
    statusUpdatedAt: null,
    zeekadReportJobId: null,
    hasReport: false,
    zeekadReportKind: null,
    zeekadVerificationPassed: null,
    zeekadWouldSend: false,
    zeekadReviewAction: null,
    zeekadReviewPending: false,
    alerted: false,
  };
}

type Crit = Pick<UnifiedQueueItem, 'priority'> & {
  priorityBase: 'high' | 'medium' | 'low' | null;
  assetCritical: boolean;
  criticalAssetName: string | null;
};

function row(i: number, host: string, crit: Crit, masked = false): UnifiedQueueItem {
  return {
    ...unified(base(i, host, masked), { priority: crit.priority, detectedAt: `2026-11-20T00:0${i}:00Z` }),
    priorityBase: crit.priorityBase,
    assetCritical: crit.assetCritical,
    criticalAssetName: crit.criticalAssetName,
  } as UnifiedQueueItem;
}

/** 1: medium → high(올림), 2: 이미 high, 3: 종결, 4: 중요 자산 아님, 5: low → medium */
function queueRows(masked: boolean, leakName = false): UnifiedQueueItem[] {
  const name = masked && !leakName ? null : NAME;
  return [
    row(1, '10.52.7.7', { priority: 'high', priorityBase: 'medium', assetCritical: true, criticalAssetName: name }, masked),
    row(2, '10.52.7.7', { priority: 'high', priorityBase: 'high', assetCritical: true, criticalAssetName: name }, masked),
    row(3, '10.52.7.7', { priority: null, priorityBase: null, assetCritical: true, criticalAssetName: name }, masked),
    row(4, '10.52.7.8', { priority: 'medium', priorityBase: 'medium', assetCritical: false, criticalAssetName: null }, masked),
    row(5, '10.52.7.7', { priority: 'medium', priorityBase: 'low', assetCritical: true, criticalAssetName: name }, masked),
  ];
}

function renderApp(path: string, role: Role, handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  document.cookie = 'XSRF-TOKEN=t52-token; path=/';
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    return handler(url, init);
  });
  vi.stubGlobal('fetch', fetchMock);
  render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return fetchMock;
}

function renderQueue(role: Role, items: UnifiedQueueItem[]) {
  return renderApp('/incidents', role, (url) => {
    if (url.startsWith('/api/incidents/queue/new-count')) return json({ count: 0, latestDetectedAt: null, since: null });
    if (url.startsWith('/api/incidents/queue')) {
      return json({
        ...fakeQueue(url, { items, anchor: '2026-11-21T00:00:00Z', maskedView: role === 'VIEWER' }),
        maskedView: role === 'VIEWER',
      });
    }
    return json({ status: 404, code: 'NOT_FOUND', message: '없음' }, 404);
  });
}

/* ───────────── 문구 ───────────── */

describe('T52 우선순위 배지 툴팁', () => {
  it('자동 분류 우선순위는 파이프라인 결과와 중요 자산 등록으로 서버가 계산한 값이라고 적는다', () => {
    expect(PRIORITY_TOOLTIP).toBe(
      '자동 분류 우선순위: 파이프라인 결과와 중요 자산 등록으로 서버가 계산한 값이며 분석가 판정이 아닙니다',
    );
  });
});

/* ───────────── 큐 ───────────── */

describe('T52 큐의 중요 자산 표지', () => {
  it('분석가: 표와 휴대폰 카드에서 우선순위 배지 옆에 표지가 있고 툴팁·화면 읽기 글이 올림과 이름을 알린다', async () => {
    renderQueue('ANALYST', queueRows(false));
    const table = await screen.findByRole('table');
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(5));
    const rowOf = (rank: number) =>
      within(table).getAllByRole('row').find((r) => r.querySelector(`a[href^="/incidents/50/rank/${rank}?"]`)) as HTMLElement;

    const expectBadge = (r: HTMLElement, title: string) => {
      const badges = badgesIn(r);
      expect(badges).toHaveLength(1);
      expect(badges[0]).toHaveAttribute('title', title);
      // T62: 데스크톱 표에서는 왕관 아이콘만 보인다(보이는 글 "중요 자산"이 우선순위 칸을 넓혀 1280px 표가 넘쳤다)
      expect(badges[0]).toHaveAttribute('data-critical-asset', 'icon');
      expect(badges[0].querySelector('svg')).not.toBeNull();
      expect(visibleText(badges[0])).toBe('');
      // 배지 꼴로 옆에 두어도 칸이 34px 넓어져 1536px에서 넘쳤다. 우선순위 배지 모서리에 겹쳐 둔다(칸 폭을 늘리지 않는다)
      expect(badges[0].parentElement?.className).toContain('absolute');
      // 툴팁만으로는 휴대폰·키보드 사용자가 볼 수 없어 화면 읽기 글로도 둔다
      expect(badges[0].querySelector('.sr-only')?.textContent).toBe(title.replace('\n', '. '));
      // 우선순위 배지 바로 옆(같은 칸)
      expect(badges[0].closest('td')).toBe(within(r).getAllByRole('cell')[1]);
    };
    expectBadge(rowOf(1), withName(RAISED));
    expectBadge(rowOf(2), withName(ALREADY_HIGH));
    expectBadge(rowOf(3), withName(PLAIN));
    expectBadge(rowOf(5), withName(RAISED_LOW));
    expect(badgesIn(rowOf(4))).toHaveLength(0);

    const cards = screen.getByRole('list', { name: '인시던트 목록' });
    const cardBadges = badgesIn(cards);
    expect(cardBadges).toHaveLength(4);
    expect(cardBadges.map((b) => b.getAttribute('title'))).toContain(withName(RAISED));
    // 휴대폰 카드는 글 표지 그대로다(T62는 데스크톱 표만 아이콘으로 바꿨다)
    for (const b of cardBadges) {
      expect(b).toHaveAttribute('data-critical-asset', '');
      expect(visibleText(b)).toBe('중요 자산');
    }
  });

  it('T62: 데스크톱 표의 우선순위 열 머리 툴팁이 왕관 아이콘의 뜻을 알린다', async () => {
    renderQueue('ANALYST', queueRows(false));
    const table = await screen.findByRole('table');
    const th = within(table).getByRole('button', { name: /우선순위 기준 정렬/ }).closest('th') as HTMLElement;
    expect(th).toHaveAttribute('title', PRIORITY_COLUMN_TOOLTIP);
    expect(PRIORITY_COLUMN_TOOLTIP.startsWith(`${PRIORITY_TOOLTIP}.\n`)).toBe(true);
    expect(PRIORITY_COLUMN_TOOLTIP).toContain('왕관 아이콘: 중요 자산으로 등록된 호스트입니다');
  });

  it('조회자: 표지는 보이고 이름은 어디에도 보이지 않는다(응답에 잘못 실려 와도)', async () => {
    renderQueue('VIEWER', queueRows(true, true));
    const table = await screen.findByRole('table');
    await waitFor(() => expect(badgesIn(table)).toHaveLength(4));
    const titles = badgesIn(table).map((b) => b.getAttribute('title'));
    expect(titles).toContain(RAISED);
    expect(titles).toContain(ALREADY_HIGH);
    expect(titles).toContain(PLAIN);
    expect(document.body.textContent).not.toContain(NAME);
    for (const el of Array.from(document.querySelectorAll('[title]'))) {
      expect(el.getAttribute('title')).not.toContain(NAME);
    }
  });

  it('"자동 분류 기준" 안내에 중요 자산 규칙 두 줄이 있다', async () => {
    renderQueue('ANALYST', queueRows(false));
    const summary = await screen.findByText('자동 분류 기준');
    const box = summary.closest('details') as HTMLElement;
    expect(within(box).getByText('중요 자산으로 등록된 호스트의 인시던트는 한 단계 올립니다(Low → Medium, Medium → High).'))
      .toBeInTheDocument();
    expect(within(box).getByText('같은 우선순위 안에서는 중요 자산이 먼저 옵니다.')).toBeInTheDocument();
    expect(within(box).getByText(/분석가 판정이 아닙니다/)).toBeInTheDocument();
  });
});

/* ───────────── 상세 머리줄 ───────────── */

function renderHeader(meta: IncidentQueueMeta) {
  return render(
    <MemoryRouter initialEntries={['/detail']}>
      <ToastProvider>
        <Routes>
          <Route path="/detail" element={<DetailHeader detail={baseDetail()} meta={meta} incidentNo={7} />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('T52 상세 머리줄', () => {
  it('올렸으면 "중요 자산 · Medium → High"를 보이는 글로 두고 툴팁에 이름을 둔다', () => {
    const { container } = renderHeader({
      ...DEFAULT_META,
      priority: 'high',
      priorityBase: 'medium',
      assetCritical: true,
      criticalAssetName: NAME,
    } as IncidentQueueMeta);
    const badges = badgesIn(container);
    expect(badges).toHaveLength(1);
    expect(screen.getByText('중요 자산 · Medium → High')).toBeInTheDocument();
    expect(badges[0]).toHaveAttribute('title', withName(RAISED));
    expect(container.querySelector('[style]')).toBeNull();
  });

  it('이미 High면 화살표 없이 "중요 자산"이고, 조회자(이름 null)는 이름이 없다', () => {
    const { container } = renderHeader({
      ...DEFAULT_META,
      priority: 'high',
      priorityBase: 'high',
      assetCritical: true,
      criticalAssetName: null,
    } as IncidentQueueMeta);
    const badges = badgesIn(container);
    expect(badges).toHaveLength(1);
    expect(badges[0]).toHaveAttribute('title', ALREADY_HIGH);
    expect(container.textContent).not.toContain('→');
  });

  it('중요 자산이 아니거나 메타가 옛 꼴이면 표지가 없다', () => {
    const { container } = renderHeader(DEFAULT_META);
    expect(badgesIn(container)).toHaveLength(0);
  });
});

/* ───────────── 같은 호스트 인시던트 ───────────── */

function related(overrides: Partial<RelatedHostIncident> & Record<string, unknown>): RelatedHostIncident {
  return {
    incidentNo: 11,
    jobId: 50,
    queueRank: 2,
    captureId: 'lab-20261119',
    hostIp: '10.52.7.7',
    zeekadRole: 'originator',
    eventStart: '2026-11-20T00:10:00Z',
    detectedAt: '2026-11-20T00:20:00Z',
    priority: 'high',
    zeekadStatus: 'open',
    zeekadResolution: null,
    zeekadPickedBy: 'ae_v2',
    connectionCount: 5,
    ...overrides,
  } as RelatedHostIncident;
}

describe('T52 같은 호스트 인시던트', () => {
  it('항목마다 우선순위 배지 옆에 표지와 툴팁이 있고 조회자는 이름이 없다', async () => {
    for (const masked of [false, true]) {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () =>
          json({
            hostIp: masked ? '10.52.*.*' : '10.52.7.7',
            total: 2,
            maskedView: masked,
            items: [
              related({ priorityBase: 'medium', assetCritical: true, criticalAssetName: masked ? null : NAME }),
              related({ queueRank: 3, incidentNo: 12, priority: 'low', priorityBase: 'low', assetCritical: false, criticalAssetName: null }),
            ],
          }),
        ),
      );
      const { container, unmount } = render(
        <MemoryRouter>
          <RelatedHostIncidents jobId={50} queueRank={1} hostIp="10.52.7.7" eventStart={null} maskedView={masked} reloadKey={null} />
        </MemoryRouter>,
      );
      await waitFor(() => expect(badgesIn(container)).toHaveLength(1));
      expect(badgesIn(container)[0]).toHaveAttribute('title', masked ? RAISED : withName(RAISED));
      if (masked) expect(container.textContent).not.toContain(NAME);
      unmount();
      vi.unstubAllGlobals();
    }
  });
});

/* ───────────── 호스트 위험도 ───────────── */

function hostRow(overrides: Partial<HostRiskItem> & Record<string, unknown>): HostRiskItem {
  return {
    hostIp: '10.52.7.7',
    hostNames: [],
    hostNameCount: 0,
    accounts: [],
    accountCount: 0,
    high: 1,
    medium: 1,
    low: 0,
    incidents: 3,
    connections: 30,
    models: ['ae_v2'],
    lastDetectedAt: '2026-11-20T23:00:00Z',
    roleTransition: false,
    ...overrides,
  } as HostRiskItem;
}

function hostsHandler(items: HostRiskItem[], masked: boolean) {
  return (url: string) => {
    if (url.startsWith('/api/hosts')) {
      return json({
        items,
        total: items.length,
        page: 1,
        size: 50,
        pageCount: 1,
        anchor: '2026-11-21T00:00:00Z',
        anchorMode: 'now',
        snapshot: false,
        period: '7d',
        periodStart: null,
        periodEnd: null,
        sources: [],
        maskedView: masked,
      });
    }
    return json({ status: 404, code: 'NOT_FOUND', message: '없음' }, 404);
  };
}

describe('T52 호스트 위험도', () => {
  it('분석가: 중요 자산 호스트 줄에 표지와 이름 툴팁, 다른 줄은 없다', async () => {
    renderApp('/hosts', 'ANALYST', hostsHandler([
      hostRow({ assetCritical: true, criticalAssetName: NAME }),
      hostRow({ hostIp: '10.52.7.8', high: 0, assetCritical: false, criticalAssetName: null }),
    ], false));
    const table = await screen.findByRole('table');
    await waitFor(() => expect(badgesIn(table)).toHaveLength(1));
    expect(badgesIn(table)[0]).toHaveAttribute('title', withName(PLAIN));
    const cards = screen.getByRole('list', { name: '호스트 위험도 목록' });
    expect(badgesIn(cards)).toHaveLength(1);
  });

  it('조회자: 대역 줄은 "이 대역에 …" 툴팁이고 이름이 없다', async () => {
    renderApp('/hosts', 'VIEWER', hostsHandler([
      hostRow({ hostIp: '10.52.*.*', assetCritical: true, criticalAssetName: null }),
    ], true));
    const table = await screen.findByRole('table');
    await waitFor(() => expect(badgesIn(table)).toHaveLength(1));
    expect(badgesIn(table)[0]).toHaveAttribute('title', BAND);
    expect(document.body.textContent).not.toContain(NAME);
  });
});

/* ───────────── CSV·마크다운 ───────────── */

describe('T52 CSV·마크다운의 중요 자산 칸', () => {
  it('CSV는 맨 뒤에 "중요 자산" 칸(예/아니요)을 두고 이름은 넣지 않는다(조회자도 같다). 앞 칸 번호는 그대로다', () => {
    expect(QUEUE_CSV_HEADERS.indexOf('중요 자산')).toBe(QUEUE_CSV_HEADERS.length - 1);
    expect(QUEUE_CSV_HEADERS.indexOf('탐지 시각(KST)')).toBe(2);
    const rows = queueRows(false);
    const lines = queueCsv(rows).slice(1).split('\r\n');
    const col = QUEUE_CSV_HEADERS.indexOf('중요 자산');
    const cells = lines.slice(1, 1 + rows.length).map((line) => line.split('","')[col].replace(/"/g, ''));
    expect(cells).toEqual(['예', '예', '예', '아니요', '예']);
    expect(queueCsv(rows)).not.toContain(NAME);
    const viewerCsv = queueCsv(queueRows(true, true));
    expect(viewerCsv).not.toContain(NAME);
    expect(viewerCsv).toContain('"예"');
  });

  it('마크다운 요약은 우선순위 다음 줄에 "중요 자산: 예/아니요"를 두고 이름·설명은 넣지 않는다', () => {
    const critical = {
      ...DEFAULT_META,
      priority: 'high',
      priorityBase: 'medium',
      assetCritical: true,
      criticalAssetName: NAME,
    } as IncidentQueueMeta;
    const md = incidentMarkdown(baseDetail(), critical, 7);
    const lines = md.split('\n');
    expect(lines[lines.indexOf('- 우선순위: High') + 1]).toBe('- 중요 자산: 예');
    expect(md).not.toContain(NAME);
    expect(incidentMarkdown(baseDetail(), DEFAULT_META, 7)).toContain('- 우선순위: High\n- 중요 자산: 아니요\n');
    expect(incidentMarkdown(baseDetail(), null, null)).toContain('- 우선순위: -\n- 중요 자산: -\n');
  });
});

/* ───────────── 관리자 화면 ───────────── */

interface AssetRow {
  id: number;
  hostIp: string;
  name: string;
  description: string | null;
  createdBy: string;
  createdAt: string;
  updatedBy: string;
  updatedAt: string;
}

function assetRow(id: number, hostIp: string, name: string, description: string | null): AssetRow {
  return {
    id,
    hostIp,
    name,
    description,
    createdBy: 'admin',
    createdAt: '2026-11-20T00:00:00Z',
    updatedBy: 'admin2',
    updatedAt: '2026-11-20T01:00:00Z',
  };
}

function adminHandler(state: { items: AssetRow[]; calls: Array<{ url: string; method: string; body: unknown }> }) {
  return async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    if (url.startsWith('/api/admin/critical-assets')) {
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      state.calls.push({ url, method, body });
      if (method === 'GET') return json({ items: state.items, limit: 200 });
      if (method === 'POST' && url === '/api/admin/critical-assets') {
        if (body.hostIp === '10.0.0.0/24') {
          return json({ status: 400, code: 'INVALID_REQUEST', message: '주소는 IPv4 한 주소(예: 192.0.2.10)만 받습니다.' }, 400);
        }
        const created = assetRow(9, body.hostIp, body.name, body.description ?? null);
        state.items = [...state.items, created];
        return json({ message: '중요 자산을 등록했습니다.', item: created }, 201);
      }
      const del = url.match(/\/api\/admin\/critical-assets\/(\d+)\/delete$/);
      if (method === 'POST' && del) {
        const id = Number(del[1]);
        const removed = state.items.find((a) => a.id === id);
        state.items = state.items.filter((a) => a.id !== id);
        return json({ message: '중요 자산을 지웠습니다.', item: removed });
      }
      const upd = url.match(/\/api\/admin\/critical-assets\/(\d+)$/);
      if (method === 'PUT' && upd) {
        const id = Number(upd[1]);
        state.items = state.items.map((a) => (a.id === id ? { ...a, name: body.name, description: body.description } : a));
        return json({ message: '중요 자산을 고쳤습니다.', item: state.items.find((a) => a.id === id) });
      }
    }
    return json({ status: 404, code: 'NOT_FOUND', message: '없음' }, 404);
  };
}

describe('T52 관리자 화면 /admin/critical-assets', () => {
  it('메뉴 "중요 자산"은 관리자에게 보인다', async () => {
    renderApp('/admin/critical-assets', 'ADMIN', adminHandler({ items: [], calls: [] }));
    expect(await screen.findByRole('link', { name: '중요 자산' })).toHaveAttribute('href', '/admin/critical-assets');
  });

  it('분석가에게는 메뉴 "중요 자산"이 없다', async () => {
    renderApp('/', 'ANALYST', () => json({ status: 404, code: 'NOT_FOUND', message: '없음' }, 404));
    await screen.findByRole('link', { name: '현황판' });
    expect(screen.queryByRole('link', { name: '중요 자산' })).toBeNull();
    expect(screen.queryByRole('link', { name: '사용자 관리' })).toBeNull();
  });

  it('목록(주소·이름·설명·고친 사람·시각), 규칙 한 줄, 추가와 서버 검증 오류', async () => {
    const user = userEvent.setup();
    const state = { items: [assetRow(1, '10.10.0.20', '실습망 대상 서버', 'SSH·HTTP·파일 공유')], calls: [] as Array<{ url: string; method: string; body: unknown }> };
    renderApp('/admin/critical-assets', 'ADMIN', adminHandler(state));
    const h1 = await screen.findByRole('heading', { level: 1, name: '중요 자산' });
    // 화면 제목 아래 설명 문장을 두지 않는다(T48)
    expect((h1.parentElement as HTMLElement).textContent).toBe('중요 자산');
    expect(screen.getByText(/등록한 주소가 호스트인 미종결 인시던트는 자동 분류 우선순위를 한 단계 올립니다/)).toBeInTheDocument();
    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent?.trim())).toEqual([
      '주소',
      '이름',
      '설명',
      '고친 사람 · 시각',
      '관리',
    ]);
    expect(within(table).getByText('10.10.0.20')).toBeInTheDocument();
    expect(within(table).getByText('실습망 대상 서버')).toBeInTheDocument();
    expect(within(table).getByText('SSH·HTTP·파일 공유')).toBeInTheDocument();
    expect(within(table).getByText(/admin2/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '중요 자산 추가' }));
    await user.type(screen.getByLabelText('주소'), '10.0.0.0/24');
    await user.type(screen.getByLabelText('이름'), '대역');
    await user.click(screen.getByRole('button', { name: '등록' }));
    expect(await screen.findByText('주소는 IPv4 한 주소(예: 192.0.2.10)만 받습니다.')).toBeInTheDocument();
    expect(state.items).toHaveLength(1);

    await user.clear(screen.getByLabelText('주소'));
    await user.type(screen.getByLabelText('주소'), '192.168.10.3');
    await user.clear(screen.getByLabelText('이름'));
    await user.type(screen.getByLabelText('이름'), '도메인 서버');
    await user.type(screen.getByLabelText('설명'), 'DNS·Kerberos');
    await user.click(screen.getByRole('button', { name: '등록' }));
    expect(await within(table).findByText('도메인 서버')).toBeInTheDocument();
    const post = state.calls.filter((c) => c.method === 'POST' && c.url === '/api/admin/critical-assets');
    expect(post[post.length - 1].body).toEqual({ hostIp: '192.168.10.3', name: '도메인 서버', description: 'DNS·Kerberos' });
    expect(document.querySelector('[style]')).toBeNull();
  });

  it('지우기는 확인을 한 번 더 받고 POST …/{id}/delete로 보낸다(DELETE 메서드를 쓰지 않는다)', async () => {
    const user = userEvent.setup();
    const state = { items: [assetRow(1, '10.10.0.20', '실습망 대상 서버', null)], calls: [] as Array<{ url: string; method: string; body: unknown }> };
    renderApp('/admin/critical-assets', 'ADMIN', adminHandler(state));
    const table = await screen.findByRole('table');
    await within(table).findByText('10.10.0.20');
    await user.click(within(table).getByRole('button', { name: '10.10.0.20 지우기' }));
    // 확인 전에는 보내지 않는다
    expect(state.calls.some((c) => c.method !== 'GET')).toBe(false);
    const confirm = screen.getByRole('group', { name: '10.10.0.20 지우기 확인' });
    expect(confirm).toHaveTextContent('되돌릴 수 없습니다');
    await user.click(within(confirm).getByRole('button', { name: '취소' }));
    expect(screen.queryByRole('group', { name: '10.10.0.20 지우기 확인' })).toBeNull();

    await user.click(within(table).getByRole('button', { name: '10.10.0.20 지우기' }));
    await user.click(within(screen.getByRole('group', { name: '10.10.0.20 지우기 확인' })).getByRole('button', { name: '지우기 확정' }));
    await waitFor(() => expect(state.items).toHaveLength(0));
    const writes = state.calls.filter((c) => c.method !== 'GET');
    expect(writes).toEqual([{ url: '/api/admin/critical-assets/1/delete', method: 'POST', body: null }]);
    expect(await screen.findByText('등록한 중요 자산이 없습니다.')).toBeInTheDocument();
  });

  it('고치기는 이름·설명만 보내고 주소는 바꿀 수 없다', async () => {
    const user = userEvent.setup();
    const state = { items: [assetRow(1, '10.10.0.20', '실습망 대상 서버', null)], calls: [] as Array<{ url: string; method: string; body: unknown }> };
    renderApp('/admin/critical-assets', 'ADMIN', adminHandler(state));
    const table = await screen.findByRole('table');
    await user.click(await within(table).findByRole('button', { name: '10.10.0.20 고치기' }));
    const form = screen.getByRole('form', { name: '중요 자산 고치기' });
    expect(within(form).queryByLabelText('주소')).toBeNull();
    expect(within(form).getByText('10.10.0.20')).toBeInTheDocument();
    await user.clear(within(form).getByLabelText('이름'));
    await user.type(within(form).getByLabelText('이름'), '대상 서버');
    await user.click(within(form).getByRole('button', { name: '저장' }));
    await waitFor(() => expect(state.items[0].name).toBe('대상 서버'));
    const put = state.calls.find((c) => c.method === 'PUT');
    expect(put).toEqual({ url: '/api/admin/critical-assets/1', method: 'PUT', body: { name: '대상 서버', description: null } });
  });
});

describe('T52 감사 유형 라벨', () => {
  it('CRITICAL_ASSET_CHANGE는 "중요 자산 변경"이다', () => {
    expect(labelText('auditAction', 'CRITICAL_ASSET_CHANGE')).toBe('중요 자산 변경');
  });
});
