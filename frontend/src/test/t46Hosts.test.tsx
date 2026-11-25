import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { RELATED_LOAD_FAILED_TEXT } from '../components/incident/RelatedHostIncidents';
import { MASKED_RANGE_NOTICE, ROLE_TRANSITION_LABEL, ROLE_TRANSITION_TOOLTIP } from '../pages/HostsPage';
import type { HostRiskItem, HostRiskResponse, RelatedHostIncident, RelatedHostIncidentsResponse } from '../types/hosts';
import {
  hostAllIncidentsPath,
  hostIncidentsPath,
  isHostIpFilterValue,
  parseHostSortDir,
  parseHostSortKey,
  relativeGapText,
} from '../utils/hosts';
import { baseDetail, DEFAULT_META } from './detailFixture';
import { expectAllTablesInScrollBox } from './tableScrollBox';

/**
 * T46: 호스트 위험도 화면(/hosts)과 상세 요약 탭의 같은 호스트 인시던트 구역.
 * 조건 줄과 URL(기본 기간 7일), 정렬, 쪽 나눔, 줄 링크(조건 유지 + hostIp=, 기간을 늘 적음), 전환 표지,
 * 조회자 화면(대역 안내, 전환 없음, roleTransitionOnly를 보내지 않음), 실패·최신 아님·빈 목록(T42 규칙).
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const serverError = () => json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500);

interface Deferred {
  promise: Promise<Response>;
  resolve: (r: Response) => void;
}
function deferred(): Deferred {
  let resolve!: (r: Response) => void;
  const promise = new Promise<Response>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

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

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}
const loc = () => screen.getByTestId('loc').textContent ?? '';
const urlParams = () => new URLSearchParams(loc().split('?')[1] ?? '');

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

function renderApp(path: string, handler: Handler, role: Role = 'ANALYST') {
  document.cookie = 'XSRF-TOKEN=t46-token; path=/';
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    return handler(url, init);
  });
  vi.stubGlobal('fetch', fetchMock);
  const utils = render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
          <LocationProbe />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { ...utils, fetchMock };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ───────────────────────── 가짜 서버 ───────────────────────── */

function hostRow(overrides: Partial<HostRiskItem> = {}): HostRiskItem {
  return {
    hostIp: '10.46.1.10',
    hostNames: ['fin-alias', 'ws-fin-01', 'ws-fin-01.corp.local'],
    hostNameCount: 3,
    accounts: ['BOB_NT', 'FINPC-07$', 'alice.kim', 'bob.lee'],
    accountCount: 4,
    high: 1,
    medium: 1,
    low: 1,
    incidents: 3,
    connections: 157,
    models: ['tail_rarity_v2', 'tgn_recon'],
    lastDetectedAt: '2026-11-20T11:00:00Z',
    roleTransition: true,
    ...overrides,
  };
}

const ANALYST_ROWS: HostRiskItem[] = [
  hostRow(),
  hostRow({
    hostIp: '10.46.1.20',
    hostNames: [],
    hostNameCount: 0,
    accounts: ['adam.cho'],
    accountCount: 1,
    high: 0,
    medium: 0,
    low: 1,
    incidents: 2,
    connections: 30,
    models: ['transformer_v2'],
    lastDetectedAt: '2026-11-20T10:00:00Z',
    roleTransition: false,
  }),
  hostRow({
    hostIp: '172.20.5.80',
    hostNames: ['h1.imp.local', 'h2.imp.local', 'h3.imp.local', 'h4.imp.local', 'h5.imp.local'],
    hostNameCount: 7,
    accounts: ['u1.one', 'u2.two', 'u3.three', 'u4.four', 'u5.five'],
    accountCount: 6,
    high: 0,
    medium: 0,
    low: 1,
    incidents: 1,
    connections: 999,
    models: ['transformer_v2'],
    lastDetectedAt: null,
    roleTransition: false,
  }),
  // 호스트 조건으로 쓸 수 없는 주소(IPv6): 링크 없이 글로 둔다
  hostRow({
    hostIp: 'fe80::1ff:fe23:4567:890a',
    hostNames: [],
    hostNameCount: 0,
    accounts: [],
    accountCount: 0,
    high: 0,
    medium: 0,
    low: 1,
    incidents: 1,
    connections: 4,
    models: [],
    lastDetectedAt: '2026-11-20T09:00:00Z',
    roleTransition: false,
  }),
];

const VIEWER_ROWS: HostRiskItem[] = [
  hostRow({
    hostIp: '10.46.*.*',
    hostNames: ['dev-box-20', 'fin-alias'],
    hostNameCount: 4,
    accounts: ['B***', 'F***', 'a***', 'b***'],
    accountCount: 4,
    incidents: 7,
    low: 4,
    roleTransition: false,
  }),
];

const SOURCES = [
  { captureId: 'lab-20261119', sourceType: 'live', latestJobId: null, lastDetectedAt: null },
  { captureId: 'cic17-wed', sourceType: 'imported', latestJobId: null, lastDetectedAt: null },
];

function hostsResponse(url: string, rows: HostRiskItem[], over: Partial<HostRiskResponse> = {}): HostRiskResponse {
  const p = new URL(url, 'http://x').searchParams;
  const size = Number(p.get('size') ?? '50');
  const total = over.total ?? rows.length;
  const pageCount = Math.max(1, Math.ceil(total / size));
  return {
    items: rows,
    total,
    page: Math.min(Number(p.get('page') ?? '1'), pageCount),
    size,
    pageCount,
    anchor: '2026-11-21T00:00:00Z',
    anchorMode: 'now',
    snapshot: false,
    period: p.get('period') ?? '24h',
    periodStart: null,
    periodEnd: null,
    sources: SOURCES as HostRiskResponse['sources'],
    maskedView: false,
    ...over,
  };
}

/** /api/hosts 요청 URL을 모으는 가짜 서버 */
function hostsServer(respond: (url: string, call: number) => Response | Promise<Response>) {
  const calls: string[] = [];
  const handler: Handler = (url) => {
    if (url.startsWith('/api/hosts')) {
      calls.push(url);
      return respond(url, calls.length);
    }
    return json({}, 404);
  };
  const last = () => new URL(calls[calls.length - 1], 'http://x').searchParams;
  return { handler, calls, last };
}

const tableRows = () => within(document.querySelector('[data-hosts-table-wrap]') as HTMLElement).getAllByRole('row').slice(1);

/* ───────────────────────── 유틸 ───────────────────────── */

describe('T46 호스트 유틸', () => {
  it('호스트 조건으로 쓸 수 있는 값은 온전한 IPv4와 가려진 대역뿐이다', () => {
    for (const ok of ['10.46.1.10', '0.0.0.0', '255.255.255.255', '10.46.*.*']) expect(isHostIpFilterValue(ok), ok).toBe(true);
    for (const bad of ['', ' 10.46.1.10', '10.46.1', '10.46.1.*', '10.*.*.*', '256.1.1.1', '10.46.1.10:445', 'fe80::1', 'host-01', null, undefined]) {
      expect(isHostIpFilterValue(bad), String(bad)).toBe(false);
    }
  });

  it('줄 링크는 지금 조건을 유지하고 기간을 늘 적는다(화면 기본 기간이어도)', () => {
    const preset = { sel: { period: '7d' as const, range: null }, source: null, captureId: null };
    expect(hostIncidentsPath('10.46.1.10', preset)).toBe('/incidents?period=7d&hostIp=10.46.1.10');
    expect(hostIncidentsPath('10.46.*.*', { ...preset, source: 'live' })).toBe(
      '/incidents?period=7d&source=live&hostIp=10.46.*.*',
    );
    // 캡처 하나를 골랐으면 수집원 종류 대신 캡처를 적는다
    expect(hostIncidentsPath('10.46.1.10', { ...preset, source: 'live', captureId: 'lab-20261119' })).toBe(
      '/incidents?period=7d&captureId=lab-20261119&hostIp=10.46.1.10',
    );
    const custom = {
      sel: { period: 'custom' as const, range: { start: '2026-11-19T00:00:00Z', end: '2026-11-20T00:00:00Z' } },
      source: null,
      captureId: null,
    };
    const q = new URLSearchParams((hostIncidentsPath('10.46.1.10', custom) ?? '').split('?')[1]);
    expect(Object.fromEntries(q)).toEqual({
      period: 'custom',
      start: '2026-11-19T00:00:00Z',
      end: '2026-11-20T00:00:00Z',
      hostIp: '10.46.1.10',
    });
    expect(hostIncidentsPath('fe80::1', preset)).toBeNull();
    expect(hostAllIncidentsPath('10.50.0.1')).toBe('/incidents?period=all&hostIp=10.50.0.1');
    expect(hostAllIncidentsPath('10.50.*.*')).toBe('/incidents?period=all&hostIp=10.50.*.*');
    expect(hostAllIncidentsPath('fe80::1')).toBeNull();
  });

  it('간격 글: 이 인시던트보다 앞이면 "전", 뒤면 "뒤"', () => {
    const self = '2026-11-20T06:00:00Z';
    expect(relativeGapText('2026-11-20T03:00:00Z', self)).toBe('3시간 전');
    expect(relativeGapText('2026-11-22T06:00:00Z', self)).toBe('2일 뒤');
    expect(relativeGapText('2026-11-20T05:50:00Z', self)).toBe('10분 전');
    expect(relativeGapText('2026-11-20T06:59:59Z', self)).toBe('59분 뒤');
    expect(relativeGapText('2026-11-20T06:00:30Z', self)).toBe('같은 시각');
    expect(relativeGapText('2026-11-20T15:00:00+09:00', self)).toBe('같은 시각');
    expect(relativeGapText(null, self)).toBeNull();
    expect(relativeGapText(self, null)).toBeNull();
    expect(relativeGapText('깨진 값', self)).toBeNull();
  });

  it('정렬 값: 모르는 값은 기본(위험도), 방향 기본은 주소만 오름', () => {
    expect(parseHostSortKey(null)).toBe('risk');
    expect(parseHostSortKey('priority')).toBe('risk');
    expect(parseHostSortKey('lastDetected')).toBe('lastDetected');
    expect(parseHostSortDir(null, 'hostIp')).toBe('asc');
    expect(parseHostSortDir(null, 'risk')).toBe('desc');
    expect(parseHostSortDir('up', 'incidents')).toBe('desc');
    expect(parseHostSortDir('asc', 'incidents')).toBe('asc');
  });
});

/* ───────────────────────── /hosts 화면 ───────────────────────── */

describe('T46 호스트 위험도 화면', () => {
  it('메뉴에서 인시던트 다음에 있고, 기본 기간 7일로 부르며 URL에는 기간을 적지 않는다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    renderApp('/hosts', server.handler);
    expect(await screen.findByRole('heading', { name: '호스트 위험도' })).toBeInTheDocument();
    const nav = screen.getAllByRole('link').map((a) => a.textContent?.trim());
    const at = nav.indexOf('인시던트');
    expect(nav[0]).toBe('현황판');
    expect(nav[at + 1]).toBe('호스트 위험도');

    await waitFor(() => expect(tableRows()).toHaveLength(4));
    expect(server.calls).toHaveLength(1);
    expect(Object.fromEntries(server.last())).toEqual({ period: '7d', sort: 'risk', dir: 'desc', page: '1', size: '50' });
    expect(loc()).toBe('/hosts');
    expect(screen.getByRole('button', { name: '7일' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('최근 7일 호스트 4개');
    // 조회자 안내는 분석가에게 보이지 않는다
    expect(screen.queryByTestId('hosts-range-notice')).toBeNull();
    expectAllTablesInScrollBox(document.querySelector('.soc-card.overflow-hidden') as HTMLElement);
  });

  it('줄의 값과 링크: 조건 유지 + hostIp, 기본 기간에도 period가 적히고, 주소 꼴이 아니면 링크가 없다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    renderApp('/hosts', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));
    const [h1, h2, h8, v6] = tableRows();

    const link = within(h1).getByRole('link');
    expect(link).toHaveTextContent('10.46.1.10');
    expect(link).toHaveAttribute('href', '/incidents?period=7d&hostIp=10.46.1.10');
    expect(link).toHaveAccessibleName('호스트 10.46.1.10의 인시던트 3건 보기');
    // 미종결 우선순위 건수(0은 흐리게)와 숫자 열
    const counts = h1.querySelector('[data-priority-counts]') as HTMLElement;
    expect(counts).toHaveTextContent('High 1');
    expect(counts).toHaveTextContent('Medium 1');
    expect(counts).toHaveTextContent('Low 1');
    expect(within(h2).getByTitle('미종결 High 0건').querySelector('.text-slate-600')).not.toBeNull();
    expect(within(h1).getByTitle('미종결 High 1건').querySelector('.text-slate-600')).toBeNull();
    expect(h1).toHaveTextContent('157');
    // 호스트 이름·관측 계정: 첫 값 + "외 N", 전체는 툴팁
    const names = h1.querySelector('[data-host-list="names"]') as HTMLElement;
    expect(names).toHaveTextContent('fin-alias외 2');
    expect(names).toHaveAttribute('title', 'fin-alias, ws-fin-01, ws-fin-01.corp.local');
    const accounts = h8.querySelector('[data-host-list="accounts"]') as HTMLElement;
    expect(accounts).toHaveTextContent('u1.one외 5');
    expect(accounts).toHaveAttribute('title', 'u1.one, u2.two, u3.three, u4.four, u5.five 외 1개');
    // 탐지 모델은 표시 이름으로 보인다(식별자 원문이 아니다)
    expect(h1).toHaveTextContent('기준선 이탈외 1');
    expect(within(h1).getByTitle('통신 관계 이상')).toHaveTextContent('외 1');
    expect(h1).not.toHaveTextContent('tail_rarity_v2');
    // 좁은 폭에서 숨기는 열(세션 수·탐지 모델)의 값은 줄 툴팁에 있다
    expect(h1).toHaveAttribute('title', '세션 157건 · 탐지 모델 기준선 이탈, 통신 관계 이상');
    expect(screen.getByRole('columnheader', { name: /세션 수/ })).toHaveClass('hidden', '2xl:table-cell');
    expect(screen.getByRole('columnheader', { name: '탐지 모델' })).toHaveClass('hidden', '2xl:table-cell');
    expect(within(h1).getByTitle('마지막 탐지 2026-11-20 20:00:00')).toHaveTextContent('11-20 20:00');
    // 전환 표지와 뜻(툴팁)
    const badge = within(h1).getByText(ROLE_TRANSITION_LABEL);
    expect(badge.closest('[title]')).toHaveAttribute('title', ROLE_TRANSITION_TOOLTIP);
    expect(ROLE_TRANSITION_TOOLTIP).toContain('확정이 아닙니다');
    expect(within(h2).queryByText(ROLE_TRANSITION_LABEL)).toBeNull();
    // 마지막 탐지가 없으면 '-'
    expect(within(h8).getByTitle('마지막 탐지 -')).toHaveTextContent('-');

    // IPv6: 링크도 줄 클릭도 없다
    expect(within(v6).queryByRole('link')).toBeNull();
    expect(v6.querySelector('[data-host-no-link]')).toHaveTextContent('fe80::1ff:fe23:4567:890a');
    expect(v6).not.toHaveAttribute('tabindex');

    // 줄을 누르면 그 호스트의 인시던트 목록으로 간다
    const user = userEvent.setup();
    await user.click(within(h2).getByText('adam.cho'));
    await waitFor(() => expect(loc()).toBe('/incidents?period=7d&hostIp=10.46.1.20'));
  });

  it('조건 줄: 기간·수집원·검색·전환 거르기가 URL과 요청에 남고 줄 링크에도 이어진다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));

    await user.click(screen.getByRole('button', { name: '전체' }));
    await waitFor(() => expect(server.last().get('period')).toBe('all'));
    expect(urlParams().get('period')).toBe('all');

    await user.selectOptions(screen.getByLabelText('수집원'), 'cap:lab-20261119');
    await waitFor(() => expect(server.last().get('captureId')).toBe('lab-20261119'));
    expect(server.last().get('source')).toBeNull();

    await user.type(screen.getByLabelText('호스트 주소·이름·계정 검색'), '  alice  ');
    await user.click(screen.getByRole('button', { name: '적용' }));
    await waitFor(() => expect(server.last().get('q')).toBe('alice'));
    expect(urlParams().get('q')).toBe('alice');

    await user.click(screen.getByRole('checkbox', { name: `${ROLE_TRANSITION_LABEL}만` }));
    await waitFor(() => expect(server.last().get('roleTransitionOnly')).toBe('true'));
    expect(urlParams().get('roleTransitionOnly')).toBe('true');

    await waitFor(() => expect(tableRows()).toHaveLength(4));
    const href = within(tableRows()[0]).getByRole('link').getAttribute('href') ?? '';
    // 링크는 기간·수집원(캡처)만 잇는다. 이 화면의 검색·전환 거르기는 인시던트 목록의 조건이 아니다
    expect(Object.fromEntries(new URLSearchParams(href.split('?')[1]))).toEqual({
      period: 'all',
      captureId: 'lab-20261119',
      hostIp: '10.46.1.10',
    });
    expect(href.startsWith('/incidents?')).toBe(true);

    // 기본 기간으로 돌아가면 URL에서 period를 지우지만 요청과 링크에는 적는다
    await user.click(screen.getByRole('button', { name: '7일' }));
    await waitFor(() => expect(server.last().get('period')).toBe('7d'));
    expect(urlParams().get('period')).toBeNull();
    await waitFor(() =>
      expect(within(tableRows()[0]).getByRole('link').getAttribute('href')).toContain('period=7d'),
    );
  });

  it('정렬: 머리글을 누르면 서버 sort·dir이 바뀌고 같은 열을 다시 누르면 방향이 뒤집힌다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    const user = userEvent.setup();
    renderApp('/hosts?page=3', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));
    expect(screen.getByRole('columnheader', { name: /미종결 우선순위/ })).toHaveAttribute('aria-sort', 'descending');

    await user.click(screen.getByRole('button', { name: '인시던트 수 기준 정렬' }));
    await waitFor(() => expect(server.last().get('sort')).toBe('incidents'));
    expect(server.last().get('dir')).toBe('desc');
    // 기본 방향은 URL에 적지 않고, 정렬을 바꾸면 1쪽으로 돌아간다
    expect(Object.fromEntries(urlParams())).toEqual({ sort: 'incidents' });
    expect(server.last().get('page')).toBe('1');

    await user.click(await screen.findByRole('button', { name: '인시던트 수 기준 정렬, 지금 내림차순' }));
    await waitFor(() => expect(server.last().get('dir')).toBe('asc'));
    expect(Object.fromEntries(urlParams())).toEqual({ sort: 'incidents', dir: 'asc' });
    expect(screen.getByRole('columnheader', { name: /인시던트/ })).toHaveAttribute('aria-sort', 'ascending');

    // 세션 수로 정렬하면 그 열을 숨기지 않는다
    await user.click(screen.getByRole('button', { name: '세션 수 기준 정렬' }));
    await waitFor(() => expect(server.last().get('sort')).toBe('connections'));
    expect(screen.getByRole('columnheader', { name: /세션 수/ })).not.toHaveClass('hidden');

    await user.click(screen.getByRole('button', { name: '호스트 주소 기준 정렬' }));
    await waitFor(() => expect(server.last().get('sort')).toBe('hostIp'));
    expect(server.last().get('dir')).toBe('asc');
    expect(Object.fromEntries(urlParams())).toEqual({ sort: 'hostIp' });

    // 위험도로 돌아가면 URL에서 sort를 지운다
    await user.click(screen.getByRole('button', { name: '미종결 우선순위 기준 정렬' }));
    await waitFor(() => expect(server.last().get('sort')).toBe('risk'));
    expect(loc()).toBe('/hosts');
  });

  it('URL의 모르는 정렬·방향 값은 서버에 보내지 않는다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    renderApp('/hosts?sort=priority&dir=up&size=7&page=abc', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));
    expect(Object.fromEntries(server.last())).toEqual({ period: '7d', sort: 'risk', dir: 'desc', page: '1', size: '50' });
  });

  it('쪽 나눔: 기존 쪽 나눔 문구 그대로이고 쪽·크기가 서버로 간다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS, { total: 120 })));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    const nav = await screen.findByRole('navigation', { name: '쪽 이동' });
    expect(nav).toHaveTextContent('전체 120건 중 1–50');
    await user.click(within(nav).getByRole('button', { name: '다음 쪽' }));
    await waitFor(() => expect(server.last().get('page')).toBe('2'));
    expect(urlParams().get('page')).toBe('2');
    await user.selectOptions(within(screen.getByRole('navigation', { name: '쪽 이동' })).getByLabelText('쪽당 건수'), '25');
    await waitFor(() => expect(server.last().get('size')).toBe('25'));
    // 크기를 바꾸면 1쪽으로 돌아간다
    expect(server.last().get('page')).toBe('1');
    expect(Object.fromEntries(urlParams())).toEqual({ size: '25' });
  });

  it('조회자: 대역 안내가 한 번 보이고 전환 거르기·표지가 없으며 줄 링크는 가려진 대역이다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, VIEWER_ROWS, { maskedView: true })));
    const { container } = renderApp('/hosts', server.handler, 'VIEWER');
    await waitFor(() => expect(tableRows()).toHaveLength(1));
    expect(screen.getAllByTestId('hosts-range-notice')).toHaveLength(1);
    expect(screen.getByTestId('hosts-range-notice')).toHaveTextContent(MASKED_RANGE_NOTICE);
    expect(MASKED_RANGE_NOTICE).toContain('같은 대역(A.B.*.*)의 호스트 전부');
    // "마스킹"이라는 낱말을 되풀이하지 않는다(상단의 기존 안내 하나뿐)
    expect(MASKED_RANGE_NOTICE).not.toContain('마스킹');
    expect((container.textContent ?? '').split('마스킹').length - 1).toBe(1);
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.queryByText(ROLE_TRANSITION_LABEL)).toBeNull();
    expect(screen.queryByRole('columnheader', { name: '방향 전환' })).toBeNull();
    expect(screen.getByRole('columnheader', { name: /호스트 대역/ })).toBeInTheDocument();
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('대역 1개');
    const link = within(tableRows()[0]).getByRole('link');
    expect(link).toHaveAttribute('href', '/incidents?period=7d&hostIp=10.46.*.*');
    expect(link).toHaveAccessibleName('대역 10.46.*.*의 인시던트 7건 보기');
    expect(tableRows()[0]).toHaveTextContent('B***외 3');
  });

  it('조회자가 roleTransitionOnly=true 주소를 열면 요청에 그 값이 없고 URL에서도 빠진다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, VIEWER_ROWS, { maskedView: true })));
    renderApp('/hosts?roleTransitionOnly=true&period=30d&q=fin', server.handler, 'VIEWER');
    await waitFor(() => expect(tableRows()).toHaveLength(1));
    await waitFor(() => expect(urlParams().has('roleTransitionOnly')).toBe(false));
    expect(Object.fromEntries(urlParams())).toEqual({ period: '30d', q: 'fin' });
    expect(server.calls.length).toBeGreaterThan(0);
    for (const call of server.calls) {
      expect(new URL(call, 'http://x').searchParams.has('roleTransitionOnly'), call).toBe(false);
    }
    expect(server.last().get('q')).toBe('fin');
  });

  it('분석가가 roleTransitionOnly=true 주소를 열면 그 값을 보내고 체크돼 있다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, [ANALYST_ROWS[0]])));
    renderApp('/hosts?roleTransitionOnly=true', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(1));
    expect(server.last().get('roleTransitionOnly')).toBe('true');
    expect(screen.getByRole('checkbox', { name: `${ROLE_TRANSITION_LABEL}만` })).toBeChecked();
    expect(urlParams().get('roleTransitionOnly')).toBe('true');
  });

  it('불러오기 실패: 0개·빈 목록으로 그리지 않고 오류와 다시 시도만 보인다', async () => {
    let mode: 'fail' | 'ok' = 'fail';
    const server = hostsServer((url) => (mode === 'fail' ? serverError() : json(hostsResponse(url, ANALYST_ROWS))));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('서버 오류 문구');
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('호스트 -');
    expect(screen.getByTestId('hosts-total')).not.toHaveTextContent('0개');
    expect(document.querySelector('[data-empty]')).toBeNull();
    expect(document.querySelector('[data-hosts-table-wrap]')).toBeNull();
    expect(screen.queryByRole('navigation', { name: '쪽 이동' })).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();

    mode = 'ok';
    await user.click(within(alert).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(tableRows()).toHaveLength(4));
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('조건을 바꾼 뒤 실패하면 앞 조건의 줄을 지금 조건의 값처럼 남기지 않는다', async () => {
    let mode: 'fail' | 'ok' = 'ok';
    const server = hostsServer((url) => (mode === 'fail' ? serverError() : json(hostsResponse(url, ANALYST_ROWS))));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));

    mode = 'fail';
    await user.click(screen.getByRole('button', { name: '30일' }));
    await screen.findByRole('alert');
    expect(document.querySelector('[data-hosts-table-wrap]')).toBeNull();
    expect(document.querySelector('[data-empty]')).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('최근 30일 호스트 -');
  });

  it('같은 조건을 다시 읽다 실패하면 줄을 남기고 "최신 값이 아닙니다"를 보인다', async () => {
    let mode: 'fail' | 'ok' = 'ok';
    const server = hostsServer((url) => (mode === 'fail' ? serverError() : json(hostsResponse(url, ANALYST_ROWS))));
    const user = userEvent.setup();
    renderApp('/hosts?q=fin', server.handler);
    await waitFor(() => expect(tableRows()).toHaveLength(4));
    // 조건을 바꿨다가(실패) 처음 조건으로 돌아오면 처음 조건의 값이 남아 있다
    mode = 'fail';
    const input = screen.getByLabelText('호스트 주소·이름·계정 검색');
    await user.clear(input);
    await user.type(input, 'zzz');
    await user.click(screen.getByRole('button', { name: '적용' }));
    await screen.findByRole('alert');
    expect(document.querySelector('[data-hosts-table-wrap]')).toBeNull();
    await user.clear(screen.getByLabelText('호스트 주소·이름·계정 검색'));
    await user.type(screen.getByLabelText('호스트 주소·이름·계정 검색'), 'fin');
    await user.click(screen.getByRole('button', { name: '적용' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(notice).toHaveTextContent('서버 오류 문구');
    expect(tableRows()).toHaveLength(4);
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('호스트 4개');
    // 자동 갱신은 없다
    expect(screen.queryByTestId('stale-auto-retry')).toBeNull();
    mode = 'ok';
    await user.click(within(notice).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
    expect(tableRows()).toHaveLength(4);
  });

  it('늦게 온 앞 조건의 응답은 버린다', async () => {
    const slow = deferred();
    const server = hostsServer((url, call) => (call === 1 ? slow.promise : json(hostsResponse(url, [ANALYST_ROWS[1]]))));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    await screen.findByText('호스트 위험도 목록을 불러오는 중...');
    await user.click(screen.getByRole('button', { name: '전체' }));
    await waitFor(() => expect(tableRows()).toHaveLength(1));
    await act(async () => slow.resolve(json(hostsResponse('/api/hosts?period=7d', ANALYST_ROWS))));
    expect(tableRows()).toHaveLength(1);
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('전체 기간 호스트 1개');
  });

  it('빈 목록: 조건을 적은 안내와 기간 넓히기, 검색 중이면 검색·거르기 지우기', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, [])));
    const user = userEvent.setup();
    renderApp('/hosts', server.handler);
    const empty = await waitFor(() => {
      const el = document.querySelector('[data-empty="none"]');
      expect(el).not.toBeNull();
      return el as HTMLElement;
    });
    expect(empty).toHaveTextContent('최근 7일 동안 인시던트가 탐지된 호스트가 없습니다.');
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('호스트 0개');
    await user.click(within(empty).getByRole('button', { name: '기간: 전체로 보기' }));
    await waitFor(() => expect(server.last().get('period')).toBe('all'));
    await waitFor(() => expect(document.querySelector('[data-empty="none"]')).toHaveTextContent('전체 기간 동안'));
    expect(screen.queryByRole('button', { name: '기간: 전체로 보기' })).toBeNull();

    await user.type(screen.getByLabelText('호스트 주소·이름·계정 검색'), 'nobody');
    await user.click(screen.getByRole('button', { name: '적용' }));
    const filtered = await waitFor(() => {
      const el = document.querySelector('[data-empty="filter"]');
      expect(el).not.toBeNull();
      return el as HTMLElement;
    });
    expect(filtered).toHaveTextContent('검색·거르기 조건에 맞는 호스트가 없습니다.');
    await user.click(within(filtered).getByRole('button', { name: '검색·거르기 지우기' }));
    await waitFor(() => expect(server.last().get('q')).toBeNull());
    expect(urlParams().get('q')).toBeNull();
  });

  it('조회자의 빈 목록 안내는 대역 단위로 적는다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, [], { maskedView: true })));
    renderApp('/hosts?q=nobody', server.handler, 'VIEWER');
    await waitFor(() => expect(document.querySelector('[data-empty="filter"]')).not.toBeNull());
    expect(document.querySelector('[data-empty="filter"]')).toHaveTextContent('검색·거르기 조건에 맞는 대역이 없습니다.');
    expect(screen.getByTestId('hosts-total')).toHaveTextContent('대역 0개');
  });

  it('휴대폰 카드: 줄마다 링크 하나이고 주소 꼴이 아니면 링크가 없다', async () => {
    const server = hostsServer((url) => json(hostsResponse(url, ANALYST_ROWS)));
    renderApp('/hosts', server.handler);
    const list = await screen.findByRole('list', { name: '호스트 위험도 목록' });
    const cards = within(list).getAllByRole('listitem');
    expect(cards).toHaveLength(4);
    expect(within(cards[0]).getAllByRole('link')).toHaveLength(1);
    expect(within(cards[0]).getByRole('link')).toHaveAttribute('href', '/incidents?period=7d&hostIp=10.46.1.10');
    expect(cards[0]).toHaveTextContent(ROLE_TRANSITION_LABEL);
    expect(within(cards[3]).queryByRole('link')).toBeNull();
    // 링크 안에 버튼을 넣지 않는다
    expect(list.querySelector('a button, button a')).toBeNull();
    // 좁은 화면용 정렬 선택
    expect(screen.getByLabelText('정렬 기준')).toHaveValue('risk');
  });
});

/* ───────────────────────── 요약 탭 구역 ───────────────────────── */

function detailResponse(masked: boolean, hostIp: string, incidentNo: number | null = null) {
  const d = baseDetail();
  return {
    maskedView: masked,
    canDecideReview: !masked,
    detail: {
      ...d,
      incident: { ...d.incident, jobId: 42, queueRank: 1, hostIp, eventStart: '2026-11-20T06:00:00Z' },
    },
    queueMeta: DEFAULT_META,
    assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
    assignmentHistory: [],
    canAssign: !masked,
    incidentNo,
  };
}

function relatedItem(i: number, overrides: Partial<RelatedHostIncident> = {}): RelatedHostIncident {
  return {
    incidentNo: 2000 + i,
    jobId: 96061,
    queueRank: i,
    captureId: 'lab-20261119',
    hostIp: '10.50.0.1',
    zeekadRole: 'originator',
    eventStart: new Date(Date.UTC(2026, 10, 20, 6, 0) + (5 - i) * 3600_000).toISOString(),
    detectedAt: '2026-11-20T10:00:00Z',
    priority: 'low',
    zeekadStatus: 'open',
    zeekadResolution: null,
    zeekadPickedBy: 'transformer_v2',
    connectionCount: 1,
    ...overrides,
  };
}

const RELATED_URL = '/api/incidents/42/rank/1/related-host-incidents';

function detailServer(
  related: (call: number) => Response | Promise<Response>,
  opts: { masked?: boolean; hostIp?: string; detail?: (call: number) => Response } = {},
) {
  const order: string[] = [];
  let relatedCalls = 0;
  let detailCalls = 0;
  const handler: Handler = (url) => {
    if (url === RELATED_URL) {
      order.push('related');
      return related(++relatedCalls);
    }
    if (url === '/api/incidents/42/rank/1') {
      order.push('detail');
      detailCalls++;
      return opts.detail ? opts.detail(detailCalls) : json(detailResponse(Boolean(opts.masked), opts.hostIp ?? '10.50.0.1'));
    }
    if (url === '/api/incidents/42/rank/1/transition') return json({ succeeded: true, code: 'OK', message: '바꿨습니다' });
    if (url.startsWith('/api/incidents/queue/neighbors')) return json({ current: null, position: null, total: 0, prev: null, next: null });
    return json({}, 404);
  };
  return { handler, order, relatedCalls: () => relatedCalls };
}

const section = () => document.querySelector('[data-related-host]') as HTMLElement;

describe('T46 요약 탭: 같은 호스트의 다른 인시던트', () => {
  it('상세가 뜬 뒤 따로 부르고, 줄마다 발생 시각·앞뒤 간격·방향·우선순위·상태·판정·모델·수집원·번호 링크를 보인다', async () => {
    const res: RelatedHostIncidentsResponse = {
      hostIp: '10.50.0.1',
      total: 3,
      maskedView: false,
      items: [
        relatedItem(1, { eventStart: '2026-11-22T06:00:00Z', priority: 'high' }),
        relatedItem(2, {
          eventStart: '2026-11-20T03:00:00Z',
          zeekadRole: 'responder',
          priority: null,
          zeekadStatus: 'closed',
          zeekadResolution: 'true_positive',
          zeekadPickedBy: 'tail_rarity_v2',
          captureId: 'cic17-wed',
        }),
        // 번호가 없으면 작업·순위 주소로 잇는다
        relatedItem(3, { incidentNo: null, jobId: 96070, queueRank: 7, eventStart: '2026-11-20T05:50:00Z' }),
      ],
    };
    const slow = deferred();
    const server = detailServer(() => slow.promise);
    renderApp('/incidents/42/rank/1', server.handler);
    await screen.findByRole('region', { name: '조치' });
    // 상세가 먼저 뜨고 구역은 불러오는 중 한 줄
    const sec = section();
    expect(within(sec).getByRole('heading', { name: '같은 호스트의 다른 인시던트' })).toBeInTheDocument();
    expect(sec.querySelector('[data-related-state="loading"]')).toHaveTextContent('불러오는 중...');
    expect(server.order).toEqual(['detail', 'related']);
    // 요약 탭 맨 아래 구역이다
    const panel = document.getElementById('detail-panel-summary') as HTMLElement;
    expect(panel.querySelector('section:last-of-type')).toBe(sec);

    await act(async () => slow.resolve(json(res)));
    await waitFor(() => expect(sec.querySelectorAll('[data-related-row]')).toHaveLength(3));
    expect(screen.getByTestId('related-count')).toHaveTextContent('이 인시던트 말고 3건');
    expect(screen.getByTestId('related-count')).not.toHaveTextContent('가까운');
    expect(within(sec).queryByRole('link', { name: '전체 보기' })).toBeNull();

    const rows = Array.from(sec.querySelectorAll<HTMLElement>('[data-related-row]'));
    expect(within(rows[0]).getByRole('link', { name: '인시던트 번호 2001 상세' })).toHaveAttribute('href', '/incidents/2001');
    expect(rows[0]).toHaveTextContent('#2001');
    expect(rows[0]).toHaveTextContent('2026-11-22 15:00:00');
    expect(rows[0].querySelector('[data-related-gap]')).toHaveTextContent('2일 뒤');
    expect(rows[0]).toHaveTextContent('출발지');
    expect(rows[0]).toHaveTextContent('High');
    expect(rows[0]).toHaveTextContent('신규');
    expect(rows[0]).toHaveTextContent('실습 11-19');

    expect(rows[1].querySelector('[data-related-gap]')).toHaveTextContent('3시간 전');
    expect(rows[1]).toHaveTextContent('목적지');
    expect(rows[1]).toHaveTextContent('종결');
    expect(rows[1]).toHaveTextContent('정탐');
    expect(rows[1]).toHaveTextContent('우선순위 없음');
    expect(rows[1]).toHaveTextContent('CIC 수');
    // 탐지 모델은 표시 이름이다
    expect(rows[1]).toHaveTextContent('기준선 이탈');
    expect(rows[1]).not.toHaveTextContent('tail_rarity_v2');
    expect(rows[0]).toHaveTextContent('행위 패턴 이탈');

    expect(within(rows[2]).getByRole('link', { name: '인시던트 상세: 10.50.0.1' })).toHaveAttribute('href', '/incidents/96070/rank/7');
    expect(rows[2]).toHaveTextContent('상세 보기');
    expect(rows[2].querySelector('[data-related-gap]')).toHaveTextContent('10분 전');
  });

  it('10건을 넘으면 "가까운 10건"과 전체 보기 링크를 둔다', async () => {
    const items = Array.from({ length: 10 }, (_, k) => relatedItem(k + 1));
    const server = detailServer(() => json({ hostIp: '10.50.0.1', total: 14, maskedView: false, items }));
    renderApp('/incidents/42/rank/1', server.handler);
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(10));
    expect(screen.getByTestId('related-count')).toHaveTextContent('이 인시던트 말고 14건 · 가까운 10건');
    expect(within(section()).getByRole('link', { name: '전체 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&hostIp=10.50.0.1',
    );
  });

  it('조회자: 제목이 같은 대역이고 전체 보기는 가려진 대역으로 간다. 주소 꼴이 아니면 전체 보기가 없다', async () => {
    const items = Array.from({ length: 10 }, (_, k) => relatedItem(k + 1, { hostIp: '10.50.*.*' }));
    const server = detailServer(() => json({ hostIp: '10.50.*.*', total: 15, maskedView: true, items }), {
      masked: true,
      hostIp: '10.50.*.*',
    });
    const view = renderApp('/incidents/42/rank/1', server.handler, 'VIEWER');
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(10));
    expect(within(section()).getByRole('heading', { name: '같은 대역(10.50.*.*) 인시던트' })).toBeInTheDocument();
    expect(within(section()).queryByRole('heading', { name: '같은 호스트의 다른 인시던트' })).toBeNull();
    expect(within(section()).getByRole('link', { name: '전체 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&hostIp=10.50.*.*',
    );
    expect(section().textContent).not.toContain('마스킹');
    view.unmount();

    const v6 = detailServer(
      () => json({ hostIp: 'fe80::1', total: 12, maskedView: false, items: items.map((i) => ({ ...i, hostIp: 'fe80::1' })) }),
      { hostIp: 'fe80::1' },
    );
    renderApp('/incidents/42/rank/1', v6.handler);
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(10));
    expect(screen.getByTestId('related-count')).toHaveTextContent('이 인시던트 말고 12건 · 가까운 10건');
    expect(within(section()).queryByRole('link', { name: '전체 보기' })).toBeNull();
  });

  it('0건이면 한 줄 안내(조회자는 대역 문구)', async () => {
    const server = detailServer(() => json({ hostIp: '10.50.0.1', total: 0, maskedView: false, items: [] }));
    const view = renderApp('/incidents/42/rank/1', server.handler);
    await waitFor(() => expect(section().querySelector('[data-related-state="empty"]')).not.toBeNull());
    expect(section()).toHaveTextContent('이 호스트에서 탐지된 다른 인시던트가 없습니다.');
    expect(screen.getByTestId('related-count')).toHaveTextContent('이 인시던트 말고 0건');
    view.unmount();

    const viewer = detailServer(() => json({ hostIp: '10.50.*.*', total: 0, maskedView: true, items: [] }), {
      masked: true,
      hostIp: '10.50.*.*',
    });
    renderApp('/incidents/42/rank/1', viewer.handler, 'VIEWER');
    await waitFor(() => expect(section().querySelector('[data-related-state="empty"]')).not.toBeNull());
    expect(section()).toHaveTextContent('같은 대역에서 탐지된 다른 인시던트가 없습니다.');
  });

  it('실패하면 구역 안에만 오류와 다시 시도가 보이고(0건으로 그리지 않는다) 상세는 그대로다', async () => {
    let mode: 'fail' | 'broken' | 'ok' = 'fail';
    const server = detailServer(() =>
      mode === 'fail'
        ? serverError()
        : mode === 'broken'
          ? json({ unexpected: true })
          : json({ hostIp: '10.50.0.1', total: 1, maskedView: false, items: [relatedItem(1)] }),
    );
    const user = userEvent.setup();
    renderApp('/incidents/42/rank/1', server.handler);
    const panel = await screen.findByRole('region', { name: '조치' });
    await waitFor(() => expect(section().querySelector('[data-related-state="error"]')).not.toBeNull());
    expect(section()).toHaveTextContent('서버 오류 문구');
    expect(section()).not.toHaveTextContent('0건');
    expect(section()).not.toHaveTextContent('없습니다');
    expect(screen.queryByTestId('related-count')).toBeNull();
    // 상세의 다른 부분은 그대로: 화면 전체 오류 배너도 "최신 값이 아닙니다"도 없고 조치 버튼이 눌린다
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    expect(within(panel).getByLabelText('변경 사유 (필수)')).toBeEnabled();
    expect(screen.getByRole('heading', { name: '무슨 일인가' })).toBeInTheDocument();

    // 모양이 다른 응답도 0건이 아니라 실패로 본다
    mode = 'broken';
    await user.click(within(section()).getByRole('button', { name: '같은 호스트 인시던트 다시 시도' }));
    await waitFor(() => expect(server.relatedCalls()).toBe(2));
    await waitFor(() => expect(section()).toHaveTextContent(RELATED_LOAD_FAILED_TEXT));
    expect(screen.queryByTestId('related-count')).toBeNull();

    mode = 'ok';
    await user.click(within(section()).getByRole('button', { name: '같은 호스트 인시던트 다시 시도' }));
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(1));
    expect(section().querySelector('[data-related-state="error"]')).toBeNull();
  });

  it('상세를 다시 불러오면 이 구역도 함께 다시 부른다', async () => {
    const server = detailServer((call) =>
      json({ hostIp: '10.50.0.1', total: call, maskedView: false, items: Array.from({ length: call }, (_, k) => relatedItem(k + 1)) }),
    );
    const user = userEvent.setup();
    renderApp('/incidents/42/rank/1', server.handler);
    const panel = await screen.findByRole('region', { name: '조치' });
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(1));
    expect(server.relatedCalls()).toBe(1);
    // 상태 변경이 성공하면 상세를 다시 읽는다
    await user.type(within(panel).getByLabelText('변경 사유 (필수)'), '조사 끝');
    await user.click(within(panel).getByRole('button', { name: '종결 처리' }));
    await waitFor(() => expect(server.relatedCalls()).toBe(2));
    await waitFor(() => expect(section().querySelectorAll('[data-related-row]')).toHaveLength(2));
    expect(server.order.filter((x) => x === 'detail')).toHaveLength(2);
    expect(screen.getByTestId('related-count')).toHaveTextContent('이 인시던트 말고 2건');
  });
});
