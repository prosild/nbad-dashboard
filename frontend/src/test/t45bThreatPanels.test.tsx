import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import {
  ATTACK_NOTE_TITLE,
  MASKED_RANGE_NOTE,
  THREAD_COUNT_TITLE,
  ThreatPanels,
  threadCountText,
  TOP_THREADS_NOTE_TITLE,
} from '../components/dashboard/ThreatPanels';
import type { DashboardAttack, DashboardOverviewResponse, DashboardTopHosts, TopThreadRow } from '../types/api';
import { fakeQueue } from './fakeQueueServer';

/**
 * T45b 현황판 위협 가시성 세 패널: ATT&CK 전술·기법 후보, 위험 호스트 상위 5, 주요 알림 묶음.
 * 글·링크(조건 유지 여부), 주소 꼴이 아닌 호스트(링크 없음), 빈 값·계산 생략 안내, 조회자 대역 설명,
 * 새 필드가 없는 응답, 현황판 안에서의 자리와 실패 처리를 본다.
 */

const ANCHOR = '2026-11-21T00:00:00Z';

const ATTACK: DashboardAttack = {
  incidentsWithCandidates: 8,
  tactics: [
    { tactic: 'credential-access', count: 3 },
    { tactic: 'execution', count: 3 },
    { tactic: 'custom-stage', count: 1 },
  ],
  techniques: [
    { attackId: 'T1059', name: 'Command and Scripting Interpreter', count: 4 },
    { attackId: 'T2001', name: null, count: 2 },
    { attackId: 'T1558.003', name: 'Kerberoasting', count: 1 },
  ],
  techniqueCount: 14,
};

const HOSTS: DashboardTopHosts = {
  originator: [
    { hostIp: '10.50.1.2', high: 2, medium: 1, low: 0, total: 3, lastDetectedAt: '2026-11-20T10:00:00Z' },
    { hostIp: 'fe80::1', high: 0, medium: 0, low: 1, total: 1, lastDetectedAt: null },
  ],
  responder: [{ hostIp: '10.60.1.2', high: 0, medium: 0, low: 1, total: 4, lastDetectedAt: '2026-11-20T11:00:00Z' }],
};

const THREADS: TopThreadRow[] = [
  { headIncidentNo: 41, headHostIp: '10.80.0.1', headPickedBy: 'tgn_recon', periodIncidentCount: 4, totalMemberCount: 4, latestDetectedAt: '2026-11-20T11:00:00Z' },
  { headIncidentNo: 7, headHostIp: null, headPickedBy: null, periodIncidentCount: 2, totalMemberCount: 3, latestDetectedAt: '2026-11-20T10:00:00Z' },
];

function overview(extra: Partial<DashboardOverviewResponse> = {}): DashboardOverviewResponse {
  return {
    anchor: ANCHOR,
    anchorMode: 'now',
    snapshot: false,
    period: '24h',
    timeZone: 'Asia/Seoul',
    staleAfterSeconds: 900,
    downAfterSeconds: 3600,
    trend: { bucket: '1h', buckets: [], unbucketed: { noDetectedAt: 0, afterAnchor: 0 } },
    sensors: [],
    captures: [],
    alerting: {
      latestDeliveryMode: null,
      latestDeliveryStatus: null,
      latestDryRun: false,
      latestCreatedAt: null,
      latestDeliveredAt: null,
      latestCaptureId: null,
      summariesInPeriod: 0,
    },
    maskedView: false,
    ...extra,
  };
}

/** 현황판 conditionQuery와 같은 모양: 지금 조건(period·source) 뒤에 더한 조건을 붙인다 */
const listQuery = (extra: Record<string, string>) => new URLSearchParams({ period: '7d', source: 'live', ...extra }).toString();

function renderPanels(ov: DashboardOverviewResponse) {
  return render(
    <MemoryRouter>
      <ThreatPanels overview={ov} listQuery={listQuery} />
    </MemoryRouter>,
  );
}

const hrefParams = (a: Element) => Object.fromEntries(new URLSearchParams((a.getAttribute('href') ?? '').split('?')[1] ?? ''));
const hrefPath = (a: Element) => (a.getAttribute('href') ?? '').split('?')[0];

describe('ATT&CK 전술·기법 후보 패널', () => {
  it('전술은 표시 이름·건수·비례 막대, 기법은 ID·이름·건수이고 줄을 누르면 지금 조건에 attack을 붙여 간다', () => {
    renderPanels(overview({ attack: ATTACK }));
    const panel = screen.getByRole('region', { name: 'ATT&CK 전술·기법 후보' });
    // 머리: 확정이 아닌 가설임과 기준
    const note = within(panel).getByText('확정이 아닌 가설 · 후보가 있는 인시던트 8건');
    expect(note).toHaveAttribute('title', ATTACK_NOTE_TITLE);
    expect(ATTACK_NOTE_TITLE).toContain('리포트의 관련 ATT&CK 기법 후보');

    const tactics = within(panel).getByRole('list', { name: 'ATT&CK 전술 후보' });
    const tacticLinks = within(tactics).getAllByRole('link');
    expect(tacticLinks.map((a) => a.textContent)).toEqual(['자격 증명 접근3건', '실행3건', 'custom-stage1건']);
    expect(hrefPath(tacticLinks[0])).toBe('/incidents');
    expect(hrefParams(tacticLinks[0])).toEqual({ period: '7d', source: 'live', attack: 'credential-access' });
    // 사전에 없는 전술은 슬러그 그대로(원문 표시)
    expect(tacticLinks[2].querySelector('[data-raw]')).toHaveTextContent('custom-stage');
    expect(hrefParams(tacticLinks[2])).toEqual({ period: '7d', source: 'live', attack: 'custom-stage' });
    // 비례 막대는 순수 SVG이고 가장 큰 값이 꽉 찬다
    const bars = tactics.querySelectorAll('svg');
    expect(bars).toHaveLength(3);
    expect(bars[0].querySelectorAll('rect')[1]).toHaveAttribute('width', '100');
    expect(Number(bars[2].querySelectorAll('rect')[1].getAttribute('width'))).toBeCloseTo(33.33, 1);

    const techniques = within(panel).getByRole('list', { name: 'ATT&CK 기법 후보' });
    const techLinks = within(techniques).getAllByRole('link');
    expect(techLinks.map((a) => a.textContent)).toEqual([
      'T1059Command and Scripting Interpreter4건',
      'T20012건',
      'T1558.003Kerberoasting1건',
    ]);
    expect(hrefParams(techLinks[0])).toEqual({ period: '7d', source: 'live', attack: 'T1059' });
    expect(hrefParams(techLinks[2])).toEqual({ period: '7d', source: 'live', attack: 'T1558.003' });
    // 고유 기법 14개 가운데 3개만 왔으므로 "외 11개"
    expect(panel.querySelector('[data-attack-more]')).toHaveTextContent('외 11개');
    expect(panel.querySelector('[data-empty]')).toBeNull();
  });

  it('보인 기법이 전부면 "외 N개"가 없고, 후보가 없으면 한 줄 안내만 보인다', () => {
    const all = renderPanels(overview({ attack: { ...ATTACK, techniqueCount: 3 } }));
    expect(all.container.querySelector('[data-attack-more]')).toBeNull();
    all.unmount();

    renderPanels(overview({ attack: { incidentsWithCandidates: 0, tactics: [], techniques: [], techniqueCount: 0 } }));
    const panel = screen.getByRole('region', { name: 'ATT&CK 전술·기법 후보' });
    expect(panel.querySelector('[data-empty="attack"]')).toHaveTextContent('이 조건의 인시던트에는 ATT&CK 기법 후보가 없습니다.');
    expect(within(panel).queryAllByRole('link')).toHaveLength(0);
    expect(within(panel).getByText('확정이 아닌 가설 · 후보가 있는 인시던트 0건')).toBeInTheDocument();
  });
});

describe('위험 호스트 상위 5 패널', () => {
  it('출발지·목적지 묶음마다 주소·미종결 우선순위 건수·전체 건수·마지막 탐지 시각을 보이고 role·hostIp를 붙여 간다', () => {
    renderPanels(overview({ topHosts: HOSTS }));
    const panel = screen.getByRole('region', { name: '위험 호스트 상위 5' });
    expect(within(panel).getByText('미종결 우선순위 건수 순')).toHaveAttribute('title', expect.stringContaining('위험 점수를 새로 매긴 값이 아닙니다'));

    const origin = within(panel).getByRole('list', { name: '출발지 위험 호스트' });
    const rows = within(origin).getAllByRole('listitem');
    expect(rows).toHaveLength(2);
    const first = within(rows[0]).getByRole('link');
    expect(first).toHaveTextContent('10.50.1.2');
    expect(first).toHaveTextContent('High 2');
    expect(first).toHaveTextContent('Medium 1');
    expect(first).toHaveTextContent('Low 0');
    expect(first).toHaveTextContent('전체 3건');
    // 마지막 탐지 시각은 짧은 표기(한국 표준시), 온전한 값은 툴팁
    expect(first).toHaveTextContent('11-20 19:00');
    expect(within(first).getByText('11-20 19:00')).toHaveAttribute('title', '마지막 탐지 시각 2026-11-20 19:00:00');
    expect(hrefPath(first)).toBe('/incidents');
    expect(hrefParams(first)).toEqual({ period: '7d', source: 'live', role: 'originator', hostIp: '10.50.1.2' });
    // 주소 꼴이 아닌 호스트(IPv6)는 글로만 둔다(큐가 400으로 답하는 값이라 링크가 없다)
    expect(rows[1]).toHaveTextContent('fe80::1');
    expect(within(rows[1]).queryByRole('link')).toBeNull();

    const responder = within(panel).getByRole('list', { name: '목적지 위험 호스트' });
    const target = within(responder).getByRole('link');
    expect(hrefParams(target)).toEqual({ period: '7d', source: 'live', role: 'responder', hostIp: '10.60.1.2' });
    expect(target).toHaveTextContent('전체 4건');
    // 분석가 화면에는 대역 설명이 없다
    expect(panel.querySelector('[data-masked-range-note]')).toBeNull();
  });

  it('조회자 화면: 가려진 주소 그대로 링크를 만들고 대역이라는 설명을 보인다', () => {
    renderPanels(
      overview({
        maskedView: true,
        topHosts: {
          originator: [{ hostIp: '10.50.*.*', high: 5, medium: 1, low: 1, total: 7, lastDetectedAt: '2026-11-20T11:00:00Z' }],
          responder: [],
        },
      }),
    );
    const panel = screen.getByRole('region', { name: '위험 호스트 상위 5' });
    expect(panel.querySelector('[data-masked-range-note]')).toHaveTextContent(MASKED_RANGE_NOTE);
    expect(MASKED_RANGE_NOTE).toContain('호스트 하나가 아니라');
    const link = within(panel).getByRole('link');
    expect(hrefParams(link)).toEqual({ period: '7d', source: 'live', role: 'originator', hostIp: '10.50.*.*' });
    // 한쪽 방향만 비면 그 묶음에 "없음"
    expect(within(panel).getByText('목적지').parentElement).toHaveTextContent('없음');
    expect(panel.querySelector('[data-empty]')).toBeNull();
  });

  it('두 방향이 모두 비면 한 줄 안내만 보인다', () => {
    renderPanels(overview({ maskedView: true, topHosts: { originator: [], responder: [] } }));
    const panel = screen.getByRole('region', { name: '위험 호스트 상위 5' });
    expect(panel.querySelector('[data-empty="hosts"]')).toHaveTextContent('이 조건에는 통신 방향이 출발지나 목적지인 인시던트가 없습니다.');
    expect(panel.querySelector('[data-masked-range-note]')).toBeNull();
    expect(within(panel).queryAllByRole('link')).toHaveLength(0);
  });
});

describe('주요 알림 묶음 패널', () => {
  it('머리 번호·호스트·탐지 모델·건수를 보이고 누르면 기간을 유지하지 않고 묶음 전체로 간다', () => {
    renderPanels(overview({ topThreads: THREADS }));
    const panel = screen.getByRole('region', { name: '주요 알림 묶음' });
    expect(within(panel).getByText('Slack 스레드로 묶인 알림')).toHaveAttribute('title', TOP_THREADS_NOTE_TITLE);
    expect(TOP_THREADS_NOTE_TITLE).toContain('공격으로 확정된 묶음이 아닙니다');

    const links = within(within(panel).getByRole('list', { name: '주요 알림 묶음 목록' })).getAllByRole('link');
    expect(links).toHaveLength(2);
    // 기간 내와 전체가 같으면 "묶음 N건", 다르면 둘 다
    expect(links[0]).toHaveTextContent('#41');
    expect(links[0]).toHaveTextContent('10.80.0.1');
    expect(links[0]).toHaveTextContent('통신 관계 이상');
    expect(links[0].querySelector('[data-thread-count]')).toHaveTextContent(/^묶음 4건$/);
    expect(links[1].querySelector('[data-thread-count]')).toHaveTextContent(/^기간 내 2건 · 전체 3건$/);
    for (const link of links) {
      expect(link.querySelector('[data-thread-count]')).toHaveAttribute('title', THREAD_COUNT_TITLE);
    }
    expect(THREAD_COUNT_TITLE).toContain('지금 기간·수집원·캡처 조건 안');
    // 링크: 현황판 조건(period=7d, source=live)을 붙이지 않는다
    expect(links[0]).toHaveAttribute('href', '/incidents?period=all&thread=41');
    expect(links[1]).toHaveAttribute('href', '/incidents?period=all&thread=7');
    // 머리의 호스트·탐지 모델을 모르면 호스트 자리에 '-'만 둔다
    expect(links[1]).toHaveTextContent('#7-기간 내 2건 · 전체 3건');
    expect(threadCountText({ periodIncidentCount: 1234, totalMemberCount: 1234 })).toBe('묶음 1,234건');
  });

  it('계산을 생략했으면 빈 값 안내 대신 생략 안내를 보이고, 묶음이 없으면 빈 값 안내를 보인다', () => {
    const omitted = renderPanels(overview({ topThreads: [], topThreadsOmitted: true }));
    let panel = screen.getByRole('region', { name: '주요 알림 묶음' });
    expect(panel.querySelector('[data-threads-omitted]')).toHaveTextContent('알림 묶음이 많아 묶음 계산을 생략했습니다.');
    expect(panel.querySelector('[data-empty]')).toBeNull();
    omitted.unmount();

    renderPanels(overview({ topThreads: [], topThreadsOmitted: false }));
    panel = screen.getByRole('region', { name: '주요 알림 묶음' });
    expect(panel.querySelector('[data-empty="threads"]')).toHaveTextContent('이 조건의 인시던트가 든 알림 묶음이 없습니다.');
    expect(panel.querySelector('[data-threads-omitted]')).toBeNull();
  });
});

describe('새 필드가 없는 응답', () => {
  it('세 패널을 빈 값으로 그린다(오류 없이)', () => {
    const { container } = renderPanels(overview());
    expect(container.querySelector('[data-empty="attack"]')).not.toBeNull();
    expect(container.querySelector('[data-empty="hosts"]')).not.toBeNull();
    expect(container.querySelector('[data-empty="threads"]')).not.toBeNull();
    expect(screen.queryAllByRole('link')).toHaveLength(0);
  });
});

/* ───────────────────────── 현황판 안에서 ───────────────────────── */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const analystUser = {
  username: 'analyst1',
  displayName: '분석가1',
  role: 'ANALYST',
  maskedView: false,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['lab-*'],
};

function renderDashboard(path: string, overviewResponse: (url: string) => Response) {
  document.cookie = 'XSRF-TOKEN=dashboard-test-token; path=/';
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return json({ authenticated: true, user: analystUser });
      if (url === '/api/time-context') return json({ anchor: ANCHOR, anchorMode: 'now', snapshot: false });
      calls.push(url);
      if (url.startsWith('/api/dashboard/overview')) return overviewResponse(url);
      if (url.startsWith('/api/incidents/queue')) return json(fakeQueue(url, { items: [], anchor: ANCHOR }));
      return json({}, 404);
    }),
  );
  const utils = render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { ...utils, calls };
}

const FULL = { attack: ATTACK, topHosts: HOSTS, topThreads: THREADS, topThreadsOmitted: false };

const before = (a: Element, b: Element) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);

describe('현황판의 위협 가시성 세 패널', () => {
  it('추이·최근 인시던트와 수집원 상태 사이에 있고 overview를 따로 부르지 않는다. 기본 기간도 링크에 period를 적는다', async () => {
    const { calls } = renderDashboard('/', () => json(overview(FULL)));
    const attack = await screen.findByRole('region', { name: 'ATT&CK 전술·기법 후보' });
    const hosts = screen.getByRole('region', { name: '위험 호스트 상위 5' });
    const threads = screen.getByRole('region', { name: '주요 알림 묶음' });
    const recent = screen.getByRole('region', { name: '최근 인시던트' });
    const sources = screen.getByRole('region', { name: '수집원 상태' });
    expect(before(recent, attack)).toBe(true);
    expect(before(attack, hosts)).toBe(true);
    expect(before(hosts, threads)).toBe(true);
    expect(before(threads, sources)).toBe(true);
    expect(calls.filter((c) => c.startsWith('/api/dashboard/overview'))).toEqual(['/api/dashboard/overview?period=24h']);

    // 현황판 기본 기간(24시간)이라고 period를 빼지 않는다(빼면 인시던트 목록이 자기 기본값으로 읽는다)
    const tactic = within(attack).getByRole('link', { name: /자격 증명 접근/ });
    expect(hrefParams(tactic)).toEqual({ period: '24h', attack: 'credential-access' });
    const host = within(hosts).getByRole('link', { name: /10\.50\.1\.2/ });
    expect(hrefParams(host)).toEqual({ period: '24h', role: 'originator', hostIp: '10.50.1.2' });
    expect(within(threads).getByRole('link', { name: /#41/ })).toHaveAttribute('href', '/incidents?period=all&thread=41');
  });

  it('지정 기간·캡처 조건을 링크에 그대로 유지하고 알림 묶음 링크만 기간을 유지하지 않는다', async () => {
    const start = '2026-11-19T00:00:00Z';
    const end = '2026-11-20T00:00:00Z';
    renderDashboard(
      `/?period=custom&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&captureId=lab-20261120`,
      () => json(overview({ ...FULL, period: 'custom', periodStart: start, periodEnd: end })),
    );
    const attack = await screen.findByRole('region', { name: 'ATT&CK 전술·기법 후보' });
    const kept = { period: 'custom', start, end, captureId: 'lab-20261120' };
    expect(hrefParams(within(attack).getByRole('link', { name: /T1059/ }))).toEqual({ ...kept, attack: 'T1059' });
    const hosts = screen.getByRole('region', { name: '위험 호스트 상위 5' });
    expect(hrefParams(within(hosts).getByRole('link', { name: /10\.60\.1\.2/ }))).toEqual({
      ...kept,
      role: 'responder',
      hostIp: '10.60.1.2',
    });
    const threads = screen.getByRole('region', { name: '주요 알림 묶음' });
    expect(within(threads).getByRole('link', { name: /#7/ })).toHaveAttribute('href', '/incidents?period=all&thread=7');
  });

  it('새 필드가 없는 overview 응답도 받아 세 패널을 빈 값 안내로 그린다', async () => {
    renderDashboard('/?period=7d', () => json(overview({ period: '7d' })));
    const attack = await screen.findByRole('region', { name: 'ATT&CK 전술·기법 후보' });
    expect(attack.querySelector('[data-empty="attack"]')).not.toBeNull();
    expect(screen.getByRole('region', { name: '위험 호스트 상위 5' }).querySelector('[data-empty="hosts"]')).not.toBeNull();
    expect(screen.getByRole('region', { name: '주요 알림 묶음' }).querySelector('[data-empty="threads"]')).not.toBeNull();
    expect(screen.getByRole('region', { name: '수집원 상태' })).toBeInTheDocument();
  });

  it('overview를 불러오지 못하면 세 패널을 0건으로 그리지 않는다(오류만 보인다)', async () => {
    renderDashboard('/', () => json({ message: '서버 오류' }, 500));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText('관제 현황을 불러오는 중...')).toBeNull());
    for (const name of ['ATT&CK 전술·기법 후보', '위험 호스트 상위 5', '주요 알림 묶음']) {
      expect(screen.queryByRole('region', { name })).toBeNull();
    }
    expect(document.querySelector('[data-empty="attack"], [data-empty="hosts"], [data-empty="threads"]')).toBeNull();
  });
});
