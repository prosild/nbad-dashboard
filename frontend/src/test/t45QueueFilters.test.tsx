import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { DetailHeader } from '../components/incident/DetailHeader';
import { ToastProvider } from '../components/ToastContext';
import { NEW_INCIDENT_POLL_MS, SignalChips, ThreadBadge } from '../pages/IncidentQueuePage';
import type { IncidentDetailView, UnifiedQueueItem } from '../types/api';
import { attackFilterLabel, attackTacticSlug, attackTechniqueId } from '../utils/attackFilter';
import { QUEUE_CSV_HEADERS, queueCsv } from '../utils/incidentExport';
import { hostIpKind } from '../utils/ipScope';
import { parseQueueQuery, queueApiParams } from '../utils/triage';
import { baseDetail, DEFAULT_META, queueItem } from './detailFixture';
import { fakeNewCount, fakeQueue, unified, type FakeQueueOptions } from './fakeQueueServer';

/**
 * T45 큐 hostIp·attack 조건(칩, 세 API 파라미터), 큐 행 `묶음 N건` 표지(표·휴대폰 카드),
 * 상세 헤더 호스트 링크, CSV 시각 열 머리줄.
 */

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

/* ───────────────────────── 조건 값 규칙(서버와 같다) ───────────────────────── */

describe('T45 조건 값 규칙', () => {
  it('hostIp: 온전한 IPv4와 가려진 IPv4(A.B.*.*)만, 옥텟 0~255·앞 0 금지', () => {
    for (const ok of ['0.0.0.0', '10.45.1.1', '192.168.0.255', '255.255.255.255']) {
      expect(hostIpKind(ok), ok).toBe('exact');
    }
    for (const ok of ['10.45.*.*', '0.0.*.*', '255.255.*.*']) {
      expect(hostIpKind(ok), ok).toBe('masked');
    }
    for (const bad of [
      '', ' ', '10.45.1', '10.45.1.1.1', '10.45.1.1:80', '10.*.*.*', '10.45.1.*', '10.45.*.1', '*.*.*.*', '10..1.1',
      '01.2.3.4', '1.2.3.04', '256.1.1.1', '1.2.3.1000', '::1', 'fe80::1', 'abc', ' 10.45.1.1', '10.45.1.1/24',
    ]) {
      expect(hostIpKind(bad), bad).toBeNull();
    }
    expect(hostIpKind(null)).toBeNull();
    expect(hostIpKind(undefined)).toBeNull();
  });

  it('attack: 기법 ID를 먼저 보고(대문자), 아니면 전술 슬러그(소문자, 공백·밑줄 → 하이픈)', () => {
    expect(attackTechniqueId('t1059')).toBe('T1059');
    expect(attackTechniqueId(' t1059.001 ')).toBe('T1059.001');
    for (const no of ['T105', 'T10591', 'T1059.1', 'T1059.0001', 'X1059', '1059']) {
      expect(attackTechniqueId(no), no).toBeNull();
    }
    for (const same of ['Credential Access', 'credential_access', 'credential-access', '  CREDENTIAL   ACCESS ', 'credential _ access']) {
      expect(attackTacticSlug(same), same).toBe('credential-access');
    }
    expect(attackTacticSlug('Command and Control')).toBe('command-and-control');
    for (const bad of ['', 'a', '-x', 'x-', 'x--y', 'credential/access', 'a.b', '자격 증명', 'x'.repeat(65)]) {
      expect(attackTacticSlug(bad), bad).toBeNull();
    }
    expect(attackTacticSlug('x'.repeat(64))).toHaveLength(64);
  });

  it('attack 칩 글: 기법은 대문자 ID, 전술은 사전의 표시 이름(밑줄·공백 표기도), 없으면 받은 값', () => {
    expect(attackFilterLabel('t1059.001')).toEqual({ kind: 'technique', label: 'ATT&CK 기법', value: 'T1059.001' });
    for (const same of ['credential_access', 'Credential Access', 'credential-access', 'CREDENTIAL_ACCESS']) {
      expect(attackFilterLabel(same), same).toEqual({ kind: 'tactic', label: 'ATT&CK 전술', value: '자격 증명 접근' });
    }
    expect(attackFilterLabel('lateral_movement').value).toBe('내부 확산');
    // 사전에 없는 전술, 형식이 틀린 값: 받은 값 그대로
    expect(attackFilterLabel('made-up-tactic')).toEqual({ kind: 'tactic', label: 'ATT&CK 전술', value: 'made-up-tactic' });
    expect(attackFilterLabel('T1059.1')).toEqual({ kind: 'tactic', label: 'ATT&CK 전술', value: 'T1059.1' });
    // 객체 기본 속성 이름을 사전 항목으로 읽지 않는다
    expect(attackFilterLabel('constructor').value).toBe('constructor');
  });

  it('URL의 hostIp·attack을 다듬어 읽고 세 API 파라미터(목록·새 건수·이전·다음)에 넣는다', () => {
    const q = parseQueueQuery(new URLSearchParams('period=all&hostIp=%2010.45.1.1%20&attack=%20credential_access%20'));
    expect(q.hostIp).toBe('10.45.1.1');
    expect(q.attack).toBe('credential_access');
    // 목록
    expect(queueApiParams(q)).toMatchObject({ hostIp: '10.45.1.1', attack: 'credential_access' });
    // 새 건수(쪽·정렬·기간 없이)
    const poll = queueApiParams(q, { paging: false, sort: false, period: false });
    expect(poll).toMatchObject({ hostIp: '10.45.1.1', attack: 'credential_access' });
    expect(poll.period).toBeUndefined();
    // 이전·다음(상세가 from=을 같은 규칙으로 읽는다)
    expect(queueApiParams(q, { paging: false })).toMatchObject({ hostIp: '10.45.1.1', attack: 'credential_access', period: 'all' });

    // 없으면 보내지 않는다. 형식이 틀린 값은 지우지 않고 그대로 보낸다(서버 400)
    const none = queueApiParams(parseQueueQuery(new URLSearchParams('hostIp=%20&attack=')));
    expect(none.hostIp).toBeUndefined();
    expect(none.attack).toBeUndefined();
    const bad = queueApiParams(parseQueueQuery(new URLSearchParams('hostIp=10.45.1.*&attack=T1059.1')));
    expect(bad).toMatchObject({ hostIp: '10.45.1.*', attack: 'T1059.1' });
    // 조건이 다르면 조건 키도 다르다
    const other = parseQueueQuery(new URLSearchParams('period=all&hostIp=10.45.1.2&attack=credential_access'));
    expect(JSON.stringify(queueApiParams(other, { paging: false, sort: false }))).not.toBe(
      JSON.stringify(queueApiParams(q, { paging: false, sort: false })),
    );
  });
});

/* ───────────────────────── 큐 화면 ───────────────────────── */

/** 시험 행 6건(호스트 10.45.i.1). 1·2·3은 A1(#101) 묶음 123건, 4는 #204 묶음 2건, 5·6은 묶음 없음 */
function makeItem(i: number): UnifiedQueueItem {
  return unified(
    queueItem({
      jobId: 50,
      captureId: 'lab-t45',
      queueRank: i,
      incidentId: `lab-t45|10.45.${i}.1|originator|${i}`,
      hostIp: `10.45.${i}.1`,
      hostName: [],
      connectionCount: i * 10,
    }),
    {
      detectedAt: new Date(Date.UTC(2026, 10, 20, 0, i)).toISOString(),
      priority: 'medium',
      threadHeadNo: i <= 3 ? 101 : i === 4 ? 204 : null,
      threadMemberCount: i <= 3 ? 123 : i === 4 ? 2 : null,
    },
  );
}

const ITEMS = Array.from({ length: 6 }, (_, idx) => ({ ...makeItem(idx + 1), incidentNo: 100 + idx + 1 }));

const meResponse = {
  authenticated: true,
  user: {
    username: 'analyst1',
    displayName: '분석가1',
    role: 'ANALYST',
    maskedView: false,
    totpEnabled: false,
    totpVerified: true,
    totpRequired: false,
    allowedCapturePatterns: ['lab-*'],
  },
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function renderQueue(path: string, options: Partial<FakeQueueOptions> & { queueStatus?: (url: string) => number } = {}) {
  document.cookie = 'XSRF-TOKEN=xsrf-test-token; path=/';
  const queueCalls: string[] = [];
  const newCountCalls: string[] = [];
  const opts = (): FakeQueueOptions => ({ anchor: '2026-11-20T01:30:00Z', items: ITEMS, ...options });
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json(meResponse);
    if (url === '/api/time-context') return json({ anchor: opts().anchor, anchorMode: 'now', snapshot: false });
    if (url.startsWith('/api/incidents/queue/new-count')) {
      newCountCalls.push(url);
      return json(fakeNewCount(url, opts()));
    }
    if (url.startsWith('/api/incidents/queue')) {
      queueCalls.push(url);
      const status = options.queueStatus?.(url) ?? 200;
      if (status !== 200) return json({ code: 'INVALID_REQUEST', message: '호스트 IP 값이 올바르지 않습니다.' }, status);
      return json(fakeQueue(url, opts()));
    }
    return json({ message: '없음' }, 404);
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
  return { ...utils, queueCalls, newCountCalls };
}

const loc = () => screen.getByTestId('loc').textContent ?? '';
const params = () => new URLSearchParams(loc().split('?')[1] ?? '');
const lastCall = (calls: string[]) => new URLSearchParams(calls[calls.length - 1].split('?')[1] ?? '');
const chipList = () => screen.getByRole('list', { name: '적용 중인 필터' });

describe('T45 큐 hostIp·attack 칩', () => {
  it('온전한 주소: "호스트: 주소" 칩(고정폭 값)과 API 파라미터, X로 지운다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue('/incidents?period=all&hostIp=10.45.2.1');
    await screen.findByRole('table');
    expect(lastCall(queueCalls).get('hostIp')).toBe('10.45.2.1');
    const chip = within(chipList()).getByRole('button', { name: '호스트 10.45.2.1 필터 지우기' });
    expect(chip).toHaveTextContent('호스트: 10.45.2.1');
    expect(chip.querySelector('[data-raw]')).toHaveTextContent('10.45.2.1');
    expect(chip.querySelector('[data-raw]')).toHaveClass('font-mono');
    expect(chip).toHaveAttribute('title', '호스트 IP가 이 주소와 정확히 같은 인시던트만 표시합니다');
    // 정확 일치: 그 호스트 한 건만
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2);
    // 필터 패널에는 입력이 없다(패널 필터 수에 세지 않는다)
    expect(screen.getByRole('button', { name: '필터' })).toHaveTextContent(/^필터$/);

    await user.click(chip);
    expect(params().get('hostIp')).toBeNull();
    expect(params().get('period')).toBe('all');
    await waitFor(() => expect(lastCall(queueCalls).get('hostIp')).toBeNull());
    expect(screen.queryByRole('button', { name: /^호스트/ })).toBeNull();
  });

  it('가려진 주소는 "호스트 대역", 형식이 틀린 값은 "호스트: 받은 값"으로 남고 그대로 보낸다', async () => {
    const masked = renderQueue('/incidents?period=all&hostIp=10.45.*.*');
    await screen.findByRole('table');
    expect(lastCall(masked.queueCalls).get('hostIp')).toBe('10.45.*.*');
    const chip = within(chipList()).getByRole('button', { name: '호스트 대역 10.45.*.* 필터 지우기' });
    expect(chip).toHaveTextContent('호스트 대역: 10.45.*.*');
    expect(chip).toHaveAttribute('title', '호스트 IP가 이 대역인 인시던트만 표시합니다');
    masked.unmount();

    const user = userEvent.setup();
    const bad = renderQueue('/incidents?period=all&hostIp=10.45.1.*', {
      queueStatus: (url) => (new URLSearchParams(url.split('?')[1]).get('hostIp') ? 400 : 200),
    });
    // 서버 400 → 기존 오류 안내. 칩이 남아 있어 지울 수 있다
    expect(await screen.findByText('호스트 IP 값이 올바르지 않습니다.')).toBeInTheDocument();
    expect(lastCall(bad.queueCalls).get('hostIp')).toBe('10.45.1.*');
    const badChip = within(chipList()).getByRole('button', { name: '호스트 10.45.1.* 필터 지우기' });
    expect(badChip).toHaveTextContent('호스트: 10.45.1.*');
    expect(badChip).not.toHaveAttribute('title');
    await user.click(badChip);
    await screen.findByRole('table');
    expect(params().get('hostIp')).toBeNull();
  });

  it('attack: 기법은 "ATT&CK 기법: 대문자 ID", 전술은 표시 이름. 툴팁에 후보(가설)라는 뜻, X와 필터 초기화로 지운다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue('/incidents?period=all&attack=t1059.001&hostIp=10.45.*.*', {
      attackMatch: (item, attack) => attack === 't1059.001' && item.queueRank <= 2,
    });
    await screen.findByRole('table');
    // 받은 값 그대로 보낸다(정규화는 서버가 한다)
    expect(lastCall(queueCalls).get('attack')).toBe('t1059.001');
    expect(lastCall(queueCalls).get('hostIp')).toBe('10.45.*.*');
    const chip = within(chipList()).getByRole('button', { name: 'ATT&CK 기법 T1059.001 필터 지우기' });
    expect(chip).toHaveTextContent('ATT&CK 기법: T1059.001');
    expect(chip).toHaveAttribute(
      'title',
      '리포트의 관련 ATT&CK 기법 후보(확정이 아닌 가설)에 이 값이 있는 인시던트만 표시합니다',
    );
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(3);
    // 상세로 가는 링크의 from=에 두 조건이 실린다(상세의 이전·다음이 같은 조건 안에서 움직인다)
    const firstRow = within(screen.getByRole('table')).getAllByRole('row')[1];
    const href = within(firstRow).getAllByRole('link')[0].getAttribute('href') ?? '';
    const from = new URLSearchParams(new URLSearchParams(href.split('?')[1] ?? '').get('from') ?? '');
    expect(from.get('attack')).toBe('t1059.001');
    expect(from.get('hostIp')).toBe('10.45.*.*');

    await user.click(chip);
    expect(params().get('attack')).toBeNull();
    expect(params().get('hostIp')).toBe('10.45.*.*');
    await waitFor(() => expect(lastCall(queueCalls).get('attack')).toBeNull());

    await user.click(screen.getByRole('button', { name: '필터 초기화' }));
    expect(params().get('hostIp')).toBeNull();
    expect(params().get('period')).toBe('all');
    await waitFor(() => expect(screen.queryByRole('list', { name: '적용 중인 필터' })).toBeNull());
  });

  it('attack 전술: 밑줄 표기도 사전의 표시 이름으로, 사전에 없으면 받은 값(고정폭)으로 보인다', async () => {
    const known = renderQueue('/incidents?period=all&attack=credential_access', { attackMatch: () => true });
    await screen.findByRole('table');
    expect(lastCall(known.queueCalls).get('attack')).toBe('credential_access');
    const chip = within(chipList()).getByRole('button', { name: 'ATT&CK 전술: 자격 증명 접근 필터 지우기' });
    expect(chip).toHaveTextContent('ATT&CK 전술: 자격 증명 접근');
    expect(chip.querySelector('[data-raw]')).toBeNull();
    known.unmount();

    renderQueue('/incidents?period=all&attack=made-up-tactic', { attackMatch: () => true });
    await screen.findByRole('table');
    const raw = within(chipList()).getByRole('button', { name: 'ATT&CK 전술 made-up-tactic 필터 지우기' });
    expect(raw).toHaveTextContent('ATT&CK 전술: made-up-tactic');
    expect(raw.querySelector('[data-raw]')).toHaveTextContent('made-up-tactic');
  });

  it('새 건수 확인(new-count)에도 hostIp·attack을 보낸다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' });
    const { newCountCalls } = renderQueue('/incidents?period=all&hostIp=10.45.*.*&attack=execution', {
      attackMatch: () => true,
    });
    await screen.findByRole('table');
    await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await waitFor(() => expect(newCountCalls).toHaveLength(1));
    const sent = new URLSearchParams(newCountCalls[0].split('?')[1]);
    expect(sent.get('hostIp')).toBe('10.45.*.*');
    expect(sent.get('attack')).toBe('execution');
    expect(sent.get('period')).toBeNull();
  });
});

describe('T45 큐 행 알림 묶음 표지', () => {
  it('표: `묶음 N건` 링크가 전체 기간 thread 목록으로 가고, 접근성 이름·툴팁에 최초 알림 인시던트 번호가 있다', async () => {
    const user = userEvent.setup();
    renderQueue('/incidents?period=all&sort=connections&dir=asc');
    const table = await screen.findByRole('table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(6);
    const badge = within(rows[0]).getByRole('link', { name: '알림 묶음 123건 · 최초 알림 인시던트 #101' });
    expect(badge).toHaveAttribute('href', '/incidents?period=all&thread=101');
    expect(badge).toHaveAttribute('title', '알림 묶음 123건 · 최초 알림 인시던트 #101');
    expect(badge).toHaveTextContent(/^묶음 123건$/);
    expect(within(rows[3]).getByRole('link', { name: '알림 묶음 2건 · 최초 알림 인시던트 #204' })).toHaveAttribute(
      'href',
      '/incidents?period=all&thread=204',
    );
    // 값이 없는 행에는 표지가 없다
    expect(within(rows[4]).queryByRole('link', { name: /알림 묶음/ })).toBeNull();
    expect(rows[4].querySelector('[data-thread-badge]')).toBeNull();
    // 표지는 리포트·판단 칸의 아이콘 칩 묶음 뒤(밖)에 있다
    const cell = badge.closest('td') as HTMLElement;
    const chipsBox = cell.querySelector('[data-thread-badge]')?.previousElementSibling as HTMLElement;
    expect(chipsBox.children).toHaveLength(3);
    expect(chipsBox.contains(badge)).toBe(false);
    // 링크·버튼 안에 있지 않다
    expect(badge.parentElement?.closest('a, button')).toBeNull();

    // 행 클릭(상세로 이동)과 겹치지 않는다: 표지를 누르면 묶음 목록으로만 간다
    await user.click(badge);
    expect(loc()).toBe('/incidents?period=all&thread=101');
    expect(await screen.findByRole('button', { name: '알림 묶음 #101 필터 지우기' })).toBeInTheDocument();
  });

  it('휴대폰 카드: 카드 링크 밖에 표지 링크가 있고, 값이 없는 카드에는 없다', async () => {
    renderQueue('/incidents?period=all&sort=connections&dir=asc');
    await screen.findByRole('table');
    const cards = within(screen.getByRole('list', { name: '인시던트 목록' })).getAllByRole('listitem');
    expect(cards).toHaveLength(6);
    const links = within(cards[0]).getAllByRole('link');
    expect(links).toHaveLength(2);
    const badge = within(cards[0]).getByRole('link', { name: '알림 묶음 123건 · 최초 알림 인시던트 #101' });
    expect(badge).toHaveAttribute('href', '/incidents?period=all&thread=101');
    expect(badge).toHaveTextContent(/^묶음 123건$/);
    // 링크 안에 링크를 넣지 않는다
    expect(links[0].contains(badge)).toBe(false);
    expect(links[0].querySelector('a, button')).toBeNull();
    expect(within(cards[4]).getAllByRole('link')).toHaveLength(1);
    expect(cards[4].querySelector('[data-mobile-thread]')).toBeNull();
  });

  it('SignalChips의 자식은 그대로 셋이고 표지를 품지 않는다. 표지는 번호·건수가 모두 있을 때만 그린다', () => {
    const item = { ...makeItem(1), incidentNo: 101 };
    const chips = render(
      <MemoryRouter>
        <SignalChips item={item} />
      </MemoryRouter>,
    );
    expect((chips.container.firstElementChild as HTMLElement).children).toHaveLength(3);
    expect(chips.container.querySelector('[data-thread-badge]')).toBeNull();
    chips.unmount();

    for (const partial of [
      { threadHeadNo: null, threadMemberCount: 3 },
      { threadHeadNo: 101, threadMemberCount: null },
      { threadHeadNo: undefined, threadMemberCount: undefined },
    ]) {
      const { container, unmount } = render(
        <MemoryRouter>
          <ThreadBadge item={{ ...item, ...partial }} />
        </MemoryRouter>,
      );
      expect(container.querySelector('a')).toBeNull();
      unmount();
    }
    const big = render(
      <MemoryRouter>
        <ThreadBadge item={{ ...item, threadHeadNo: 2269, threadMemberCount: 1234 }} />
      </MemoryRouter>,
    );
    expect(big.getByRole('link', { name: '알림 묶음 1,234건 · 최초 알림 인시던트 #2269' })).toHaveTextContent('묶음 1,234건');
    expect(big.container.querySelector('[style]')).toBeNull();
  });
});

/* ───────────────────────── 상세 헤더 호스트 링크 ───────────────────────── */

function renderHeader(hostIp: string) {
  const detail: IncidentDetailView = baseDetail();
  detail.incident = { ...detail.incident, hostIp };
  return render(
    <MemoryRouter initialEntries={['/detail']}>
      <ToastProvider>
        <Routes>
          <Route path="/detail" element={<DetailHeader detail={detail} meta={DEFAULT_META} incidentNo={7} />} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('T45 상세 헤더 호스트 피벗', () => {
  it('온전한 주소: 전체 기간 hostIp 정확 일치 목록으로 가는 링크', async () => {
    const user = userEvent.setup();
    const { container } = renderHeader('192.168.10.5');
    const link = screen.getByRole('link', { name: '호스트 192.168.10.5 인시던트 보기' });
    expect(link).toHaveAttribute('href', '/incidents?period=all&hostIp=192.168.10.5');
    expect(link).toHaveAttribute('title', '호스트 192.168.10.5 인시던트 보기');
    expect(link).toHaveTextContent(/^192\.168\.10\.5$/);
    expect(link.querySelector('a, button')).toBeNull();
    expect(container.querySelector('[style]')).toBeNull();
    await user.click(link);
    expect(screen.getByTestId('loc')).toHaveTextContent('/incidents?period=all&hostIp=192.168.10.5');
  });

  it('가려진 주소(조회자): 같은 대역 목록으로 가는 링크', () => {
    renderHeader('192.168.*.*');
    const link = screen.getByRole('link', { name: '같은 대역(192.168.*.*) 인시던트 보기' });
    expect(link).toHaveAttribute('href', '/incidents?period=all&hostIp=192.168.*.*');
    expect(link).toHaveAttribute('title', '같은 대역(192.168.*.*) 인시던트 보기');
    expect(link).toHaveTextContent(/^192\.168\.\*\.\*$/);
  });

  it('서버가 받지 않는 꼴(IPv6, A.B.C.*, 가명 등)은 링크 없이 글로 둔다', () => {
    for (const text of ['fe80::1', '192.168.10.*', 'host-a', '192.168.10.5:445', '01.2.3.4']) {
      const { unmount } = renderHeader(text);
      expect(screen.getByText(text)).toBeInTheDocument();
      expect(screen.getByText(text).closest('a')).toBeNull();
      expect(screen.queryByRole('link', { name: /인시던트 보기$/ })).toHaveAttribute(
        'href',
        expect.stringContaining('pickedBy='),
      );
      unmount();
    }
  });
});

/* ───────────────────────── CSV 머리줄 ───────────────────────── */

describe('T45 CSV 시각 열 머리줄', () => {
  it('시각 열 머리줄에 (KST)를 붙이고 값은 그대로다', () => {
    expect(QUEUE_CSV_HEADERS[2]).toBe('탐지 시각(KST)');
    expect(QUEUE_CSV_HEADERS[7]).toBe('발생 시작(KST)');
    expect(QUEUE_CSV_HEADERS[8]).toBe('발생 종료(KST)');
    expect(QUEUE_CSV_HEADERS).toHaveLength(19);
    const lines = queueCsv([{ ...makeItem(1), incidentNo: 101 }]).slice(1).split('\r\n');
    const head = lines[0].split(',');
    expect(head[2]).toBe('"탐지 시각(KST)"');
    expect(head[7]).toBe('"발생 시작(KST)"');
    expect(head[8]).toBe('"발생 종료(KST)"');
    // 값은 화면과 같은 KST 시각(시간대 글자 없음)
    expect(lines[1].split(',')[2]).toBe('"2026-11-20 09:01:00"');
    // 묶음 표지는 CSV 열에 넣지 않는다
    expect(lines[0]).not.toContain('묶음');
  });
});
