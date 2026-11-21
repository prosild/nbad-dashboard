import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentNoLocation, QueueNeighborsResponse, UnifiedQueueItem } from '../types/api';
import { incidentPath, incidentShareUrl, parseIncidentNo } from '../utils/incidentLink';
import { safeReturnPath } from '../utils/returnTo';
import { baseDetail, DEFAULT_META, queueItem } from './detailFixture';
import { fakeNewCount, fakeQueue, unified } from './fakeQueueServer';

/**
 * T27 인시던트 번호·고정 주소·로그인 뒤 원래 주소·작업 번호 표기·줄인 "지연" 표지.
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

type Role = 'VIEWER' | 'ANALYST' | 'ADMIN';
const userOf = (role: Role, totpVerified = true) => ({
  username: role === 'VIEWER' ? 'demo' : role === 'ADMIN' ? 'admin' : 'analyst1',
  displayName: role,
  role,
  maskedView: role === 'VIEWER',
  totpEnabled: role === 'ADMIN',
  totpVerified,
  totpRequired: role === 'ADMIN',
  allowedCapturePatterns: ['*'],
});

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}
const loc = () => screen.getByTestId('loc').textContent ?? '';

interface Setup {
  role?: Role;
  /** 로그인 안 된 상태로 시작 */
  anonymous?: boolean;
  /** 번호 API 응답들(차례로, 마지막 값을 계속 쓴다). null이면 403 */
  locations?: (IncidentNoLocation | null)[];
  /** 상세 응답의 incidentNo(작업·순위 → 번호). 없으면 null */
  numberOf?: (jobId: number, rank: number) => number | null;
  neighbors?: QueueNeighborsResponse;
  queueItems?: UnifiedQueueItem[];
  reviews?: unknown[];
  /** 상세 API가 이 횟수까지 401(SESSION_EXPIRED)을 준다 */
  detailExpiredTimes?: number;
}

function renderApp(path: string | { pathname: string; state?: unknown }, setup: Setup = {}) {
  document.cookie = 'XSRF-TOKEN=t27-token; path=/';
  const role = setup.role ?? 'ANALYST';
  let authed = !setup.anonymous;
  let totpDone = role !== 'ADMIN';
  let locateCalls = 0;
  let detailCalls = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') {
      return json(authed ? { authenticated: true, user: userOf(role, totpDone) } : { authenticated: false, user: null });
    }
    if (url === '/api/auth/login-notice') return json({ notice: '' });
    if (url === '/api/auth/login' && init?.method === 'POST') {
      authed = true;
      return json({
        authenticated: true,
        user: userOf(role, totpDone),
        nextRoute: role === 'ADMIN' ? '/login/totp' : '/',
      });
    }
    if (url === '/api/auth/totp/verify' && init?.method === 'POST') {
      totpDone = true;
      return json({ succeeded: true, code: 'OK', message: '인증 완료', user: userOf(role, true) });
    }
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    const no = url.match(/^\/api\/incidents\/no\/(\d+)$/);
    if (no) {
      const list = setup.locations ?? [{ incidentNo: Number(no[1]), jobId: 44, queueRank: 3, latest: true }];
      const l = list[Math.min(locateCalls, list.length - 1)];
      locateCalls += 1;
      if (l === null) return json({ status: 403, code: 'FORBIDDEN', message: '요청하신 기능을 수행할 권한이 없습니다.' }, 403);
      return json(l);
    }
    const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
    if (m) {
      detailCalls += 1;
      if (detailCalls <= (setup.detailExpiredTimes ?? 0)) {
        authed = false;
        return json({ status: 401, code: 'SESSION_EXPIRED', message: '세션이 만료되었습니다.' }, 401);
      }
      const d = baseDetail();
      const jobId = Number(m[1]);
      const rank = Number(m[2]);
      return json({
        maskedView: role === 'VIEWER',
        canDecideReview: role !== 'VIEWER',
        detail: { ...d, incident: { ...d.incident, jobId, queueRank: rank } },
        queueMeta: DEFAULT_META,
        assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
        assignmentHistory: [],
        canAssign: false,
        incidentNo: setup.numberOf ? setup.numberOf(jobId, rank) : null,
      });
    }
    if (url.startsWith('/api/incidents/queue/neighbors')) {
      return json(setup.neighbors ?? { current: null, position: null, total: 0, prev: null, next: null });
    }
    if (url.startsWith('/api/incidents/queue/new-count')) {
      return json(fakeNewCount(url, { items: setup.queueItems ?? [] }));
    }
    if (url.startsWith('/api/incidents/queue')) {
      return json(fakeQueue(url, { items: setup.queueItems ?? [], anchor: '2026-11-21T00:00:00Z' }));
    }
    if (url.startsWith('/api/reviews')) {
      return json({
        maskedView: false,
        canDecideReview: false,
        allowedCaptures: ['cic17-wed'],
        selectedCaptureId: null,
        pendingOnly: false,
        reviews: setup.reviews ?? [],
      });
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  const entry = typeof path === 'string' ? path : path;
  const utils = render(
    <MemoryRouter initialEntries={[entry]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
          <LocationProbe />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  const calls = (re: RegExp) => fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => re.test(u));
  return { ...utils, fetchMock, calls };
}

const header = () => screen.getByRole('region', { name: '인시던트 요약' });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T27 번호 주소', () => {
  it('번호 주소 → 번호 API 위치 → 그 작업·순위로 상세를 부르고 머리에 #번호를 보인다(주소는 그대로)', async () => {
    const { calls } = renderApp('/incidents/1042?tab=history', { numberOf: () => 1042 });
    const no = await within(await screen.findByRole('region', { name: '인시던트 요약' })).findByLabelText('인시던트 번호 1042');
    expect(no).toHaveTextContent('#1042');
    expect(calls(/^\/api\/incidents\/no\/1042$/)).toHaveLength(1);
    expect(calls(/^\/api\/incidents\/44\/rank\/3$/).length).toBeGreaterThanOrEqual(1);
    expect(loc()).toBe('/incidents/1042?tab=history');
    // 조치 API 열쇠도 그 위치다(이웃 API가 위치로 불린다)
    expect(calls(/neighbors\?jobId=44&queueRank=3/).length).toBeGreaterThanOrEqual(1);
  });

  it('번호 API 403이면 기존 오류 안내를 보이고 상세를 부르지 않는다', async () => {
    const { calls } = renderApp('/incidents/77', { locations: [null] });
    expect(await screen.findByText('요청하신 기능을 수행할 권한이 없습니다.')).toBeInTheDocument();
    expect(calls(/\/rank\//)).toHaveLength(0);
  });

  it('옛 주소는 상세 응답의 번호로 같은 쿼리를 붙인 번호 주소로 바뀐다(replace)', async () => {
    renderApp('/incidents/42/rank/1?from=status%3Dopen&tab=evidence', { numberOf: () => 1042 });
    await waitFor(() => expect(loc()).toBe('/incidents/1042?from=status%3Dopen&tab=evidence'));
    expect(await within(await screen.findByRole('region', { name: '인시던트 요약' })).findByText('#1042')).toBeInTheDocument();
  });

  it('옛 주소에서 번호가 null이면 그대로 보인다(번호·링크 복사 없음)', async () => {
    renderApp('/incidents/42/rank/1', { numberOf: () => null });
    await screen.findByRole('region', { name: '인시던트 요약' });
    await new Promise((r) => setTimeout(r, 30));
    expect(loc()).toBe('/incidents/42/rank/1');
    expect(within(header()).queryByRole('button', { name: '링크 복사' })).toBeNull();
    expect(within(header()).queryByLabelText(/인시던트 번호/)).toBeNull();
    expect(within(header()).getByRole('button', { name: '인시던트 ID 복사' })).toBeInTheDocument();
  });

  it('latest=false면 마지막 탐지 결과 안내를 보인다', async () => {
    renderApp('/incidents/7', { locations: [{ incidentNo: 7, jobId: 30, queueRank: 2, latest: false }], numberOf: () => 7 });
    expect(
      await screen.findByText('최신 탐지 결과에는 이 인시던트가 없습니다. 마지막으로 나온 탐지 결과를 보여 줍니다.'),
    ).toBeInTheDocument();
  });

  it('열어 둔 사이 새 작업이 끝나면 새 결과 띠의 "새로 고침"이 번호 위치를 다시 받는다(주소 그대로)', async () => {
    const user = userEvent.setup();
    const { calls } = renderApp('/incidents/1042', {
      locations: [
        { incidentNo: 1042, jobId: 44, queueRank: 3, latest: true },
        { incidentNo: 1042, jobId: 45, queueRank: 1, latest: true },
      ],
      numberOf: () => 1042,
      neighbors: { current: { jobId: 45, queueRank: 1, hostIp: '192.168.10.5', incidentNo: 1042 }, position: 1, total: 1, prev: null, next: null },
    });
    const refresh = await screen.findByRole('button', { name: '새로 고침' });
    expect(screen.queryByRole('link', { name: '최신 보기' })).toBeNull();
    await user.click(refresh);
    await waitFor(() => expect(calls(/^\/api\/incidents\/45\/rank\/1$/).length).toBeGreaterThanOrEqual(1));
    expect(calls(/^\/api\/incidents\/no\/1042$/)).toHaveLength(2);
    expect(loc()).toBe('/incidents/1042');
  });

  it('상세 이전·다음 링크는 번호 주소다(번호가 없으면 옛 주소)', async () => {
    renderApp('/incidents/1042?from=sort%3Ddetected', {
      numberOf: () => 1042,
      neighbors: {
        current: { jobId: 44, queueRank: 3, hostIp: '192.168.10.5', incidentNo: 1042 },
        position: 2,
        total: 3,
        prev: { jobId: 44, queueRank: 2, hostIp: '10.0.0.2', incidentNo: 1041 },
        next: { jobId: 44, queueRank: 4, hostIp: '10.0.0.4', incidentNo: null },
      },
    });
    // 이웃을 받기 전에는 비활성 자리표시(href 없음)다
    await waitFor(() =>
      expect(screen.getByRole('link', { name: '이전 인시던트' })).toHaveAttribute('href', '/incidents/1041?from=sort%3Ddetected'),
    );
    expect(screen.getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('href', '/incidents/44/rank/4?from=sort%3Ddetected');
  });

  it('머리의 "링크 복사"는 {origin}/incidents/{번호}(쿼리 없음)를 복사한다', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    renderApp('/incidents/1042?from=x%3D1&tab=report', { numberOf: () => 1042 });
    const btn = await within(await screen.findByRole('region', { name: '인시던트 요약' })).findByRole('button', { name: '링크 복사' });
    await user.click(btn);
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/incidents/1042`);
    expect(await screen.findByText('인시던트 링크를 복사했습니다.')).toBeInTheDocument();
  });

  it('작업 번호는 "작업 44"로 쓰고 "#"은 인시던트 번호에만 쓴다(상세 머리 툴팁)', async () => {
    renderApp('/incidents/1042', { numberOf: () => 1042 });
    const h = await screen.findByRole('region', { name: '인시던트 요약' });
    const occurred = await within(h).findByTitle(/탐지 작업/);
    const title = occurred.getAttribute('title') ?? '';
    expect(title).toContain('작업 44');
    expect(title).not.toMatch(/#\d/);
  });
});

describe('T27 큐·에스컬레이션 링크와 번호 칸', () => {
  const rows = (): UnifiedQueueItem[] => [
    { ...unified(queueItem({ jobId: 44, queueRank: 3, hostIp: '10.0.0.3', incidentId: 'a' }), { priority: 'high' }), incidentNo: 1042 },
    { ...unified(queueItem({ jobId: 44, queueRank: 4, hostIp: '10.0.0.4', incidentId: 'b' }), { priority: 'low' }), incidentNo: null },
  ];

  it('큐 행·휴대폰 카드 링크는 번호 주소(없으면 옛 주소), 번호 칸은 2xl부터, 행 링크 이름에 번호', async () => {
    renderApp('/incidents', { queueItems: rows() });
    const table = await screen.findByRole('table');
    const head = within(table).getAllByRole('columnheader')[0];
    expect(head).toHaveTextContent('번호');
    expect(head.className.split(/\s+/)).toEqual(expect.arrayContaining(['hidden', '2xl:table-cell']));
    const link = within(table).getByRole('link', { name: /인시던트 번호 1042, 인시던트 상세: 10\.0\.0\.3/ });
    expect(link.getAttribute('href')).toMatch(/^\/incidents\/1042\?from=/);
    const cell = table.querySelector('[data-col="incident-no"]') as HTMLElement;
    expect(cell).toHaveTextContent('#1042');
    const other = within(table).getByRole('link', { name: /^인시던트 상세: 10\.0\.0\.4/ });
    expect(other.getAttribute('href')).toMatch(/^\/incidents\/44\/rank\/4\?from=/);
    // 휴대폰 카드
    const cards = screen.getByRole('list', { name: '인시던트 목록' });
    expect(within(cards).getByLabelText('인시던트 번호 1042')).toHaveTextContent('#1042');
    const cardLinks = within(cards).getAllByRole('link');
    expect(cardLinks[0].getAttribute('href')).toMatch(/^\/incidents\/1042\?from=/);
  });

  it('에스컬레이션 목록: queueRank가 없어도 번호가 있으면 번호 주소로 링크하고, 둘 다 없으면 숨긴다', async () => {
    const reviewRow = (over: Record<string, unknown>) => ({
      jobId: 99,
      reviewJobId: 99,
      captureId: 'cic17-wed',
      incidentId: 'cic17-wed|1.2.3.4|originator|1',
      queueRank: null,
      hostIp: '1.2.3.4',
      zeekadRole: 'originator',
      zeekadReviewReason: '검토',
      requestedAt: '2026-11-20T00:00:00Z',
      zeekadReviewAction: null,
      analyst: null,
      analystDisplay: null,
      decidedAt: null,
      zeekadReviewResumedAt: null,
      zeekadReviewResumeFailed: null,
      incidentNo: null,
      ...over,
    });
    renderApp('/reviews', {
      reviews: [
        reviewRow({ incidentNo: 501, incidentId: 'r1' }),
        reviewRow({ incidentNo: null, incidentId: 'r2', hostIp: '5.6.7.8' }),
      ],
    });
    const links = await screen.findAllByRole('link', { name: /인시던트 상세/ });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute('href', '/incidents/501');
  });
});

describe('T27 로그인 뒤 원래 주소', () => {
  it('ANALYST: 셸로 들어온 비로그인 번호 주소 → 로그인 → 원래 주소', async () => {
    const user = userEvent.setup();
    renderApp('/incidents/1042?tab=history', { anonymous: true, numberOf: () => 1042 });
    await user.type(await screen.findByLabelText('아이디'), 'analyst1');
    await user.type(screen.getByLabelText('비밀번호'), 'Pass!1234');
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    await waitFor(() => expect(loc()).toBe('/incidents/1042?tab=history'));
    expect(await screen.findByLabelText('인시던트 번호 1042')).toBeInTheDocument();
  });

  it('ADMIN: 로그인 → OTP → 원래 주소', async () => {
    const user = userEvent.setup();
    renderApp('/incidents/1042', { role: 'ADMIN', anonymous: true, numberOf: () => 1042 });
    await user.type(await screen.findByLabelText('아이디'), 'admin');
    await user.type(screen.getByLabelText('비밀번호'), 'Pass!1234');
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    await waitFor(() => expect(loc()).toBe('/login/totp'));
    await user.type(await screen.findByLabelText('6자리 TOTP 인증 코드'), '123456');
    await user.click(screen.getByRole('button', { name: /인증/ }));
    await waitFor(() => expect(loc()).toBe('/incidents/1042'));
  });

  it('ADMIN OTP 미완료 상태로 셸에 들어와도 OTP 뒤 원래 주소로 간다', async () => {
    const user = userEvent.setup();
    // 로그인은 됐고 OTP만 남은 세션(서버가 셸을 줌)
    const setup: Setup = { role: 'ADMIN', numberOf: () => 1042 };
    renderApp('/incidents/1042?from=a%3D1', setup);
    await waitFor(() => expect(loc()).toBe('/login/totp'));
    await user.type(await screen.findByLabelText('6자리 TOTP 인증 코드'), '123456');
    await user.click(screen.getByRole('button', { name: /인증/ }));
    await waitFor(() => expect(loc()).toBe('/incidents/1042?from=a%3D1'));
  });

  it('열어 둔 화면에서 세션이 끝나 API 401을 받으면 다시 로그인한 뒤 그 주소로 간다(만료 안내)', async () => {
    const user = userEvent.setup();
    renderApp('/incidents/1042?tab=evidence', { numberOf: () => 1042, detailExpiredTimes: 1 });
    expect(await screen.findByText('세션이 만료되었습니다. 다시 로그인해 주세요.')).toBeInTheDocument();
    expect(loc()).toBe('/login?expired');
    await user.type(screen.getByLabelText('아이디'), 'analyst1');
    await user.type(screen.getByLabelText('비밀번호'), 'Pass!1234');
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    await waitFor(() => expect(loc()).toBe('/incidents/1042?tab=evidence'));
  });

  it.each([
    ['//evil.example/x'],
    ['/\\evil.example'],
    ['/login/totp'],
    ['/loginx'],
    ['https://evil.example/incidents/1'],
    ['incidents/1'],
  ])('앱 밖·로그인 경로 %s는 받지 않고 nextRoute(/)로 간다', async (from) => {
    const user = userEvent.setup();
    renderApp({ pathname: '/login', state: { from } } as unknown as string, { anonymous: true });
    await user.type(await screen.findByLabelText('아이디'), 'analyst1');
    await user.type(screen.getByLabelText('비밀번호'), 'Pass!1234');
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    await waitFor(() => expect(loc()).toBe('/'));
  });

  it('safeReturnPath: 앱 안 경로만(쿼리 포함 허용)', () => {
    expect(safeReturnPath('/incidents/1042?tab=history')).toBe('/incidents/1042?tab=history');
    expect(safeReturnPath('/')).toBe('/');
    for (const bad of ['//x', '/\\x', '/login', '/login?expired', 'https://x', '', null, 5, '/a\nb']) {
      expect(safeReturnPath(bad)).toBeNull();
    }
  });
});

describe('T27 도우미·표지', () => {
  it('incidentPath·incidentShareUrl·parseIncidentNo', () => {
    expect(incidentPath({ incidentNo: 5, jobId: 1, queueRank: 2 }, 'from=a')).toBe('/incidents/5?from=a');
    expect(incidentPath({ incidentNo: null, jobId: 1, queueRank: 2 })).toBe('/incidents/1/rank/2');
    expect(incidentPath({ incidentNo: null, jobId: 1, queueRank: null })).toBeNull();
    expect(incidentShareUrl(9, 'https://soc.example')).toBe('https://soc.example/incidents/9');
    expect(parseIncidentNo('12')).toBe(12);
    for (const bad of ['0', '-1', 'abc', '1.5', undefined]) {
      expect(parseIncidentNo(bad)).toBeNull();
    }
  });

  it('번호 주소가 숫자가 아니면 잘못된 경로 안내(번호 API를 부르지 않음)', async () => {
    const { calls } = renderApp('/incidents/abc');
    expect(await screen.findByText('잘못된 인시던트 경로입니다.')).toBeInTheDocument();
    expect(calls(/\/api\/incidents\/no\//)).toHaveLength(0);
  });

  it('큐의 줄인 "지연" 표지: 보이는 글 "지연", 판독기 이름은 "착수 지연"과 목표 시간, 툴팁도 같다', async () => {
    const overdue: UnifiedQueueItem = {
      ...unified(queueItem({ jobId: 44, queueRank: 3, incidentId: 'o' }), {
        priority: 'high',
        detectedAt: '2026-11-20T22:00:00Z',
        ackDueAt: '2026-11-20T22:30:00Z',
        ackOverdue: true,
      }),
      incidentNo: 3,
    };
    renderApp('/incidents', { queueItems: [overdue] });
    const table = await screen.findByRole('table');
    const short = table.querySelector('[data-ack-short]') as HTMLElement;
    expect(short).toHaveTextContent('지연');
    expect(short.className.split(/\s+/)).toContain('2xl:hidden');
    const badge = short.parentElement as HTMLElement;
    expect(within(badge).getByText('착수 지연, 목표 탐지 뒤 30분')).toHaveClass('sr-only');
    expect(badge.getAttribute('title')).toContain('이 우선순위의 착수 목표: 탐지 뒤 30분');
    await act(async () => undefined);
  });
});
