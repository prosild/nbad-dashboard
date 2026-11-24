import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RATE_LIMITED_MESSAGE } from '../api/client';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { STALE_ACTION_BLOCKED, STALE_ACTION_BLOCKED_DETAIL } from '../components/StaleNotice';
import { ToastProvider } from '../components/ToastContext';
import { NEW_INCIDENT_POLL_MS } from '../pages/IncidentQueuePage';
import type { UnifiedQueueItem } from '../types/api';
import { baseDetail, DEFAULT_META, queueItem } from './detailFixture';
import { fakeNewCount, fakeQueue, unified, type FakeQueueOptions } from './fakeQueueServer';

/**
 * T42: 목록 화면이 불러오기 실패를 "0건"·"없습니다"로 보이지 않는다.
 * (가) 지금 조건으로 받은 값만 지금 조건의 값으로 그린다. (나) 실패를 0·빈 목록으로 그리지 않는다.
 * (다) 같은 조건의 값이 있는데 다시 불러오기가 실패하면 값을 남기고 "최신 값이 아닙니다"를 붙인다.
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const serverError = () => json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500);
const wafRateLimited = () =>
  new Response('<html><body>429</body></html>', { status: 429, headers: { 'Content-Type': 'text/html' } });

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

const userOf = (role: 'ANALYST' | 'ADMIN') => ({
  username: role === 'ADMIN' ? 'admin' : 'analyst1',
  displayName: role,
  role,
  maskedView: false,
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
const params = () => new URLSearchParams(loc().split('?')[1] ?? '');

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

function renderApp(path: string, handler: Handler, role: 'ANALYST' | 'ADMIN' = 'ANALYST') {
  document.cookie = 'XSRF-TOKEN=t42-token; path=/';
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (url === '/api/time-context') return json({ anchor: '2026-11-20T01:30:00Z', anchorMode: 'now', snapshot: false });
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
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/* ───────────────────────── 인시던트 큐 ───────────────────────── */

function makeItem(i: number): UnifiedQueueItem {
  return unified(
    queueItem({
      jobId: 42,
      queueRank: i,
      incidentId: `cic17-wed|10.0.${i}.1|originator|${i}`,
      hostIp: `10.0.${i}.1`,
      hostName: [],
      zeekadStatus: 'open',
      zeekadReviewPending: false,
      alerted: false,
    }),
    { detectedAt: new Date(Date.UTC(2026, 10, 20, 0, i)).toISOString(), priority: i % 3 === 0 ? 'high' : 'low' },
  );
}
const ITEMS = Array.from({ length: 30 }, (_, k) => makeItem(k + 1));
const HIGH_COUNT = ITEMS.filter((i) => i.priority === 'high').length;

type QueueMode = 'ok' | 'fail' | '429' | 'defer';

function queueServer(init: { mode?: QueueMode; items?: () => UnifiedQueueItem[]; opts?: Partial<FakeQueueOptions> } = {}) {
  const state = { mode: init.mode ?? ('ok' as QueueMode) };
  const queueCalls: string[] = [];
  const newCountCalls: string[] = [];
  const waiting: { url: string; d: Deferred }[] = [];
  const opts = (): FakeQueueOptions => ({
    anchor: '2026-11-20T01:30:00Z',
    ...init.opts,
    items: init.items ? init.items() : ITEMS,
  });
  const handler: Handler = (url) => {
    if (url.startsWith('/api/incidents/queue/new-count')) {
      newCountCalls.push(url);
      return json(fakeNewCount(url, opts()));
    }
    if (url.startsWith('/api/incidents/queue')) {
      queueCalls.push(url);
      if (state.mode === 'fail') return serverError();
      if (state.mode === '429') return wafRateLimited();
      if (state.mode === 'defer') {
        const d = deferred();
        waiting.push({ url, d });
        return d.promise;
      }
      return json(fakeQueue(url, opts()));
    }
    return json({}, 404);
  };
  const resolveAll = () => {
    for (const w of waiting.splice(0)) w.d.resolve(json(fakeQueue(w.url, opts())));
  };
  return { state, queueCalls, newCountCalls, handler, resolveAll };
}

const strip = () => screen.getByRole('region', { name: '인시던트 요약' });
const stripTotal = () => within(strip()).getByText('전체 인시던트').nextElementSibling?.textContent;
const highButton = () => within(strip()).getByRole('button', { name: /우선순위 High/ });
const anyEmptyText = () =>
  screen.queryByText(/표시할 인시던트가 없습니다|탐지된 인시던트가 없습니다|조건에 맞는 인시던트가 없습니다/);
const tableIds = () =>
  within(screen.getByRole('table'))
    .getAllByRole('row')
    .slice(1)
    .map((r) => Number((within(r).getAllByRole('link')[0].textContent ?? '').split('.')[2]));

async function pollArmed() {
  await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
}
function setVisible() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' });
}
async function settle(ms = 30) {
  await act(async () => {
    await new Promise((r) => setTimeout(r, ms));
  });
}

describe('T42 인시던트 큐: 실패를 0건·빈 목록으로 보이지 않는다', () => {
  it('처음 불러오기 실패: 배너만, 띠 수는 "-", 빈 목록 문구·쪽 표시·행·최신 아님 표시 없음', async () => {
    const q = queueServer({ mode: 'fail' });
    renderApp('/incidents', q.handler);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('서버 오류 문구');
    expect(stripTotal()).toBe('-');
    expect(highButton()).toHaveTextContent('-');
    expect(highButton()).toHaveAccessibleName('우선순위 High만 보기');
    expect(anyEmptyText()).toBeNull();
    expect(document.querySelector('[data-empty]')).toBeNull();
    expect(screen.queryByText(/전체 0건 중/)).toBeNull();
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    expect(screen.queryByTestId('outside-period')).toBeNull();
  });

  it('429면 요청 제한 문구(배너), 띠는 "-"', async () => {
    const q = queueServer({ mode: '429' });
    renderApp('/incidents', q.handler);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(alert).toHaveTextContent(RATE_LIMITED_MESSAGE);
    expect(stripTotal()).toBe('-');
    expect(anyEmptyText()).toBeNull();
  });

  it('성공한 0건일 때만 빈 목록 문구가 보이고 띠는 0이다', async () => {
    const q = queueServer({ items: () => [] });
    renderApp('/incidents', q.handler);
    await waitFor(() => expect(document.querySelector('[data-empty]')).not.toBeNull());
    expect(stripTotal()).toBe('0');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('같은 조건 다시 불러오기 실패(기본 정렬 1쪽의 새 인시던트 불러오기·다시 시도): 행·합계가 남고 "최신 값이 아닙니다"와 마지막 성공 시각, 요청은 한 번씩', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisible();
    let items = ITEMS.slice(0, 28);
    const q = queueServer({ items: () => items });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderApp('/incidents?sort=detected&dir=desc', q.handler);
    await screen.findByRole('table');
    expect(stripTotal()).toBe('28');
    await pollArmed();
    items = ITEMS.slice(0, 30);
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await screen.findByText('새 인시던트 2건');
    const before = tableIds();
    const callsBefore = q.queueCalls.length;

    q.state.mode = 'fail';
    await user.click(screen.getByRole('button', { name: '불러오기' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(q.queueCalls.length).toBe(callsBefore + 1);
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(notice).toHaveTextContent('서버 오류 문구');
    expect(notice).toHaveTextContent('마지막 성공');
    // 큐에는 목록 자동 갱신이 없으므로 "60초마다" 말이 붙지 않는다
    expect(screen.queryByTestId('stale-auto-retry')).toBeNull();
    expect(tableIds()).toEqual(before);
    expect(stripTotal()).toBe('28');
    expect(screen.queryByRole('alert')).toBeNull();

    // 표시의 다시 시도도 같은 조건 다시 불러오기다(실패면 그대로 남는다)
    await user.click(within(notice).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(q.queueCalls.length).toBe(callsBefore + 2));
    await settle();
    expect(screen.getByTestId('stale-notice')).toBeInTheDocument();
    expect(tableIds()).toEqual(before);

    // 429도 같은 자리에 요청 제한 문구
    q.state.mode = '429';
    await user.click(within(screen.getByTestId('stale-notice')).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(screen.getByTestId('stale-notice')).toHaveTextContent(RATE_LIMITED_MESSAGE));

    q.state.mode = 'ok';
    await user.click(within(screen.getByTestId('stale-notice')).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
    expect(stripTotal()).toBe('30');
    expect(tableIds().slice(0, 2)).toEqual([30, 29]);
  });

  it('다른 정렬에서 누른 "불러오기"는 조건 변경이고 요청은 한 번만 나간다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisible();
    let items = ITEMS.slice(0, 28);
    const q = queueServer({ items: () => items });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderApp('/incidents', q.handler);
    await screen.findByRole('table');
    await pollArmed();
    items = ITEMS.slice(0, 30);
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await screen.findByText('새 인시던트 2건');
    const callsBefore = q.queueCalls.length;
    await user.click(screen.getByRole('button', { name: '불러오기' }));
    await waitFor(() => expect(tableIds().slice(0, 2)).toEqual([30, 29]));
    await settle();
    expect(q.queueCalls.length).toBe(callsBefore + 1);
    expect(new URLSearchParams(q.queueCalls[q.queueCalls.length - 1].split('?')[1]).get('sort')).toBe('detected');
  });

  it('거르기를 바꾼 뒤 실패: 앞 조건의 행·합계가 없고 배너만, 수집원 선택지는 남는다', async () => {
    const q = queueServer();
    const user = userEvent.setup();
    renderApp('/incidents', q.handler);
    await screen.findByRole('table');
    expect(stripTotal()).toBe('30');
    q.state.mode = 'fail';
    await user.click(highButton());
    await screen.findByRole('alert');
    expect(params().get('priority')).toBe('high');
    expect(screen.queryByRole('table')).toBeNull();
    expect(stripTotal()).toBe('-');
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    expect(anyEmptyText()).toBeNull();
    expect(document.querySelector('option[value="cap:cic17-wed"]')).not.toBeNull();

    // 조건을 되돌리면 그 조건으로 다시 부른다
    q.state.mode = 'ok';
    await user.click(highButton());
    await screen.findByRole('table');
    expect(stripTotal()).toBe('30');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('거르기를 바꾼 뒤 불러오는 동안: 앞 조건의 행·합계를 지금 조건의 것처럼 보이지 않는다', async () => {
    const q = queueServer();
    const user = userEvent.setup();
    renderApp('/incidents', q.handler);
    await screen.findByRole('table');
    q.state.mode = 'defer';
    await user.click(highButton());
    await waitFor(() => expect(params().get('priority')).toBe('high'));
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.getByText('인시던트 목록을 불러오는 중...')).toBeInTheDocument();
    expect(stripTotal()).toBe('-');
    await act(async () => q.resolveAll());
    await screen.findByRole('table');
    // 띠 합계는 서버가 띠 거르기 전 기준으로 준다(가짜 서버도 같다). 새 조건의 응답 값이다
    expect(stripTotal()).toBe('30');
    expect(highButton()).toHaveTextContent(String(HIGH_COUNT));
    expect(tableIds().every((id) => id % 3 === 0)).toBe(true);
  });

  it('정렬만 바꾼 동안: 띠 합계는 그대로, 행 자리만 불러오는 중이다', async () => {
    const q = queueServer();
    const user = userEvent.setup();
    renderApp('/incidents', q.handler);
    await screen.findByRole('table');
    q.state.mode = 'defer';
    await user.click(screen.getByRole('button', { name: /세션 수 기준 정렬/ }));
    await waitFor(() => expect(params().get('sort')).toBe('connections'));
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.getByText('인시던트 목록을 불러오는 중...')).toBeInTheDocument();
    expect(stripTotal()).toBe('30');
    await act(async () => q.resolveAll());
    await screen.findByRole('table');
    expect(stripTotal()).toBe('30');
  });

  it('서버가 쪽 번호를 고쳐 준 응답은 숨기지 않고 같은 요청을 다시 보내지 않는다', async () => {
    const q = queueServer();
    renderApp('/incidents?page=9&size=25', q.handler);
    await waitFor(() => expect(params().get('page')).toBe('2'));
    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getByText(/전체 30건 중 26–30/)).toBeInTheDocument();
    await settle(50);
    expect(q.queueCalls).toHaveLength(1);
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('새 건수 띠: 지금 조건의 성공 응답이 없으면 묻지 않고, 앞 조건의 since로 지금 조건을 묻지 않는다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisible();
    const q = queueServer({ mode: 'fail' });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderApp('/incidents', q.handler);
    await screen.findByRole('alert');
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS * 2);
    });
    expect(q.newCountCalls).toHaveLength(0);

    // 성공(전체) → 거르기 바꾼 뒤 실패: 앞 조건의 since로 High 조건을 묻지 않는다
    q.state.mode = 'ok';
    await user.click(within(screen.getByRole('alert')).getByRole('button', { name: '다시 시도' }));
    await screen.findByRole('table');
    q.state.mode = 'fail';
    await user.click(highButton());
    await screen.findByRole('alert');
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS * 2);
    });
    expect(q.newCountCalls.filter((u) => u.includes('priority=high'))).toHaveLength(0);

    // High 조건 성공 → 그 응답의 최신 탐지 시각으로 묻는다
    q.state.mode = 'ok';
    await user.click(within(screen.getByRole('alert')).getByRole('button', { name: '다시 시도' }));
    await screen.findByRole('table');
    await pollArmed();
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await waitFor(() => expect(q.newCountCalls.filter((u) => u.includes('priority=high')).length).toBeGreaterThan(0));
    const sent = new URLSearchParams(q.newCountCalls[q.newCountCalls.length - 1].split('?')[1]);
    const latestHigh = ITEMS.filter((i) => i.priority === 'high')
      .map((i) => i.detectedAt as string)
      .sort()
      .pop();
    expect(sent.get('since')).toBe(latestHigh);
  });

  it('기간 밖 안내는 지금 조건의 성공 응답이 있을 때만', async () => {
    const q = queueServer({ opts: { periodFilter: (item) => (item.queueRank ?? 0) <= 10 } });
    const user = userEvent.setup();
    renderApp('/incidents', q.handler);
    expect(await screen.findByTestId('outside-period')).toHaveTextContent('선택한 기간 밖 인시던트 20건');
    q.state.mode = 'fail';
    await user.click(highButton());
    await screen.findByRole('alert');
    expect(screen.queryByTestId('outside-period')).toBeNull();
  });
});

/* ───────────────────────── 에스컬레이션 ───────────────────────── */

const REVIEW_ID = 'cic17-wed|192.168.10.5|originator|100';
function reviewsBody(reviews: unknown[], pendingOnly = false) {
  return {
    maskedView: false,
    canDecideReview: true,
    allowedCaptures: ['cic17-wed', 'syn1-thu'],
    selectedCaptureId: null,
    pendingOnly,
    reviews,
  };
}
const pendingReview = (incidentId = REVIEW_ID, reason = '경계선 점수 검토') => ({
  jobId: 99,
  reviewJobId: 88,
  captureId: 'cic17-wed',
  incidentId,
  queueRank: 1,
  hostIp: '192.168.10.5',
  zeekadRole: 'originator',
  zeekadReviewReason: reason,
  requestedAt: '2026-11-18T01:00:00Z',
  zeekadReviewAction: null,
  analyst: null,
  analystDisplay: null,
  decidedAt: null,
  zeekadReviewResumedAt: null,
  zeekadReviewResumeFailed: false,
});

describe('T42 에스컬레이션', () => {
  it('처음 실패: 배너만, "총 -", 빈 목록 문구 없음', async () => {
    renderApp('/reviews', (url) => (url.startsWith('/api/reviews') ? serverError() : json({}, 404)));
    await screen.findByRole('alert');
    expect(screen.getByTestId('reviews-total')).toHaveTextContent('총 -');
    expect(screen.queryByText('대기 중인 에스컬레이션이 없습니다.')).toBeNull();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('성공 0건: "총 0건"과 빈 목록 문구', async () => {
    renderApp('/reviews', (url) => (url.startsWith('/api/reviews') ? json(reviewsBody([])) : json({}, 404)));
    expect(await screen.findByText('대기 중인 에스컬레이션이 없습니다.')).toBeInTheDocument();
    expect(screen.getByTestId('reviews-total')).toHaveTextContent('총 0건');
  });

  it('결정 저장 뒤 다시 읽기 실패: 값이 남고 "최신 값이 아닙니다", 결정 버튼이 막히고 이유를 보인다. 다시 읽기가 성공하면 풀린다', async () => {
    let listMode: 'ok' | 'fail' = 'ok';
    const user = userEvent.setup();
    renderApp(
      '/reviews',
      (url) => {
        if (url === '/api/reviews/decide') return json({ succeeded: true, code: 'OK', message: '검토 결정 반영됨' });
        if (url.startsWith('/api/reviews')) {
          return listMode === 'ok'
            ? json(reviewsBody([pendingReview(), pendingReview(`${REVIEW_ID}-2`, '두 번째 검토')]))
            : serverError();
        }
        return json({}, 404);
      },
      'ADMIN',
    );
    expect(await screen.findByText('두 번째 검토')).toBeInTheDocument();
    listMode = 'fail';
    await user.click(screen.getAllByRole('button', { name: '승인' })[0]);
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(notice).toHaveTextContent('마지막 성공');
    expect(screen.getByText('두 번째 검토')).toBeInTheDocument();
    expect(screen.getByTestId('reviews-total')).toHaveTextContent('총 2건');
    for (const b of screen.getAllByRole('button', { name: '승인' })) {
      expect(b).toBeDisabled();
      expect(b).toHaveAttribute('title', STALE_ACTION_BLOCKED);
    }
    for (const b of screen.getAllByRole('button', { name: '오탐 종결' })) expect(b).toBeDisabled();
    expect(screen.getAllByTestId('decision-blocked')[0]).toHaveTextContent(STALE_ACTION_BLOCKED);

    listMode = 'ok';
    await user.click(within(notice).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
    for (const b of screen.getAllByRole('button', { name: '승인' })) expect(b).toBeEnabled();
  });

  it('조건을 바꾼 뒤 실패: 앞 조건의 목록이 없고 배너만, 캡처 선택지는 남는다', async () => {
    let listMode: 'ok' | 'fail' = 'ok';
    const user = userEvent.setup();
    renderApp('/reviews', (url) => {
      if (url.startsWith('/api/reviews')) return listMode === 'ok' ? json(reviewsBody([pendingReview()])) : serverError();
      return json({}, 404);
    });
    expect(await screen.findByText('경계선 점수 검토')).toBeInTheDocument();
    listMode = 'fail';
    await user.click(screen.getByRole('checkbox', { name: '대기만 보기' }));
    await screen.findByRole('alert');
    expect(screen.queryByText('경계선 점수 검토')).toBeNull();
    expect(screen.getByTestId('reviews-total')).toHaveTextContent('총 -');
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    expect(document.querySelector('#reviews-capture option[value="syn1-thu"]')).not.toBeNull();
  });

  it('조건을 빠르게 바꿨을 때 늦게 온 앞 조건 응답은 그려지지 않는다', async () => {
    const waiting: { url: string; d: Deferred }[] = [];
    const user = userEvent.setup();
    renderApp('/reviews', (url) => {
      if (url.startsWith('/api/reviews')) {
        const d = deferred();
        waiting.push({ url, d });
        return d.promise;
      }
      return json({}, 404);
    });
    await waitFor(() => expect(waiting).toHaveLength(1));
    await user.click(screen.getByRole('checkbox', { name: '대기만 보기' }));
    await waitFor(() => expect(waiting).toHaveLength(2));
    // 뒤 요청(대기만)이 먼저 오고, 앞 요청(전체)이 늦게 온다
    await act(async () => waiting[1].d.resolve(json(reviewsBody([pendingReview(REVIEW_ID, '대기만 응답')], true))));
    expect(await screen.findByText('대기만 응답')).toBeInTheDocument();
    await act(async () => waiting[0].d.resolve(json(reviewsBody([pendingReview(REVIEW_ID, '늦게 온 전체 응답')]))));
    await settle();
    expect(screen.queryByText('늦게 온 전체 응답')).toBeNull();
    expect(screen.getByText('대기만 응답')).toBeInTheDocument();
  });
});

/* ───────────────────────── 인시던트 상세 ───────────────────────── */

function detailResponse(jobId: number, rank: number) {
  const d = baseDetail();
  return {
    maskedView: false,
    canDecideReview: true,
    detail: { ...d, incident: { ...d.incident, jobId, queueRank: rank, hostIp: `10.9.${rank}.1` } },
    queueMeta: DEFAULT_META,
    assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
    assignmentHistory: [],
    canAssign: true,
    incidentNo: null,
  };
}

describe('T42 인시던트 상세', () => {
  it('같은 인시던트 다시 읽기 실패(상태 변경 뒤): 내용이 남고 "최신 값이 아닙니다", 조치 버튼이 막힌다', async () => {
    let detailMode: 'ok' | 'fail' = 'ok';
    const user = userEvent.setup();
    renderApp('/incidents/42/rank/1', (url) => {
      if (url === '/api/incidents/42/rank/1/transition') return json({ succeeded: true, code: 'OK', message: '바꿨습니다' });
      if (url === '/api/incidents/42/rank/1') return detailMode === 'ok' ? json(detailResponse(42, 1)) : serverError();
      if (url.startsWith('/api/incidents/queue/neighbors')) return json({ current: null, position: null, total: 0, prev: null, next: null });
      return json({}, 404);
    });
    const panel = await screen.findByRole('region', { name: '조치' });
    await user.type(within(panel).getByLabelText('변경 사유 (필수)'), '조사 끝');
    detailMode = 'fail';
    await user.click(within(panel).getByRole('button', { name: '종결 처리' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(notice).toHaveTextContent('마지막 성공');
    expect(screen.getByRole('region', { name: '조치' })).toBeInTheDocument();
    expect(screen.getByTestId('action-blocked')).toHaveTextContent(STALE_ACTION_BLOCKED_DETAIL);
    const p = screen.getByRole('region', { name: '조치' });
    await user.type(within(p).getByLabelText('변경 사유 (필수)'), '다시');
    expect(within(p).getByRole('button', { name: '종결 처리' })).toBeDisabled();
    expect(within(p).getByRole('button', { name: '승인' })).toBeDisabled();
    expect(within(p).getByRole('button', { name: '오탐 종결' })).toBeDisabled();
    expect(within(p).getByRole('button', { name: /내가 맡기/ })).toBeDisabled();
    expect(within(p).getByRole('button', { name: /담당자 변경/ })).toBeDisabled();

    detailMode = 'ok';
    await user.click(within(notice).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
    expect(within(screen.getByRole('region', { name: '조치' })).getByRole('button', { name: '승인' })).toBeEnabled();
  });

  it('다른 인시던트로 옮긴 뒤 실패: 앞 인시던트 내용이 남지 않고 배너만', async () => {
    const user = userEvent.setup();
    renderApp('/incidents/42/rank/1', (url) => {
      if (url === '/api/incidents/42/rank/1') return json(detailResponse(42, 1));
      if (url === '/api/incidents/42/rank/2') return serverError();
      if (url.startsWith('/api/incidents/queue/neighbors'))
        return json({ current: null, position: 1, total: 2, prev: null, next: { jobId: 42, queueRank: 2, hostIp: '10.9.2.1' } });
      return json({}, 404);
    });
    await screen.findByRole('region', { name: '조치' });
    await user.click(screen.getByRole('link', { name: '다음 인시던트' }));
    await waitFor(() =>
      expect(screen.getAllByRole('alert').some((a) => a.textContent?.includes('서버 오류 문구'))).toBe(true),
    );
    expect(screen.queryByRole('region', { name: '조치' })).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
  });

  it('늦게 온 앞 인시던트 응답은 버린다(지금 인시던트가 그대로 보인다)', async () => {
    const slow = deferred();
    const user = userEvent.setup();
    let firstCall = true;
    renderApp('/incidents/42/rank/1', (url) => {
      if (url === '/api/incidents/42/rank/1/transition') return json({ succeeded: true, code: 'OK', message: '바꿨습니다' });
      if (url === '/api/incidents/42/rank/1') {
        if (firstCall) {
          firstCall = false;
          return json(detailResponse(42, 1));
        }
        return slow.promise;
      }
      if (url === '/api/incidents/42/rank/2') return json(detailResponse(42, 2));
      if (url.startsWith('/api/incidents/queue/neighbors'))
        return json({ current: null, position: 1, total: 2, prev: null, next: { jobId: 42, queueRank: 2, hostIp: '10.9.2.1' } });
      return json({}, 404);
    });
    const panel = await screen.findByRole('region', { name: '조치' });
    // 상태 변경 뒤 같은 인시던트 다시 읽기(느림)를 띄운 채 다음 인시던트로 옮긴다
    await user.type(within(panel).getByLabelText('변경 사유 (필수)'), '조사');
    await user.click(within(panel).getByRole('button', { name: '종결 처리' }));
    await user.click(screen.getByRole('link', { name: '다음 인시던트' }));
    await waitFor(() => expect(loc()).toContain('/incidents/42/rank/2'));
    await waitFor(() => expect(screen.getAllByText('10.9.2.1').length).toBeGreaterThan(0));
    await act(async () => slow.resolve(json(detailResponse(42, 1))));
    await settle();
    expect(screen.getAllByText('10.9.2.1').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('stale-notice')).toBeNull();
  });
});

/* ───────────────────────── 운영 현황 ───────────────────────── */

describe('T42 운영 현황', () => {
  it('운영 현황 API 실패: "탐지 작업 0건"·"판정이 기록된 인시던트가 없습니다" 같은 0건 문구가 없고 배너만', async () => {
    renderApp('/operations', () => serverError());
    await screen.findByRole('alert');
    expect(screen.queryByText(/탐지 작업 0건/)).toBeNull();
    expect(screen.queryByText(/Slack 일일 요약 0건/)).toBeNull();
    expect(screen.queryByText('아직 분석가 판정이 기록된 인시던트가 없습니다.')).toBeNull();
    expect(screen.queryByText('이 기간에 탐지 작업 기록이 없습니다.')).toBeNull();
    expect(screen.queryByText('조건에 맞는 센서가 없습니다')).toBeNull();
    expect(screen.getByText(/탐지 작업 -/)).toBeInTheDocument();
  });

  it('overview만 실패: 수집원 칸은 "불러오지 못했습니다"이고 "센서가 없습니다"·"0개 캡처"가 아니다', async () => {
    renderApp('/operations', (url) => {
      if (url.startsWith('/api/operations')) {
        return json({
          maskedView: false,
          allowedCaptures: ['cic17-wed'],
          selectedCaptureId: null,
          jobs: [],
          bundles: [],
          feedbackSummaries: [],
          slackSummaries: [],
        });
      }
      return serverError();
    });
    expect(await screen.findByTestId('ops-sources-missing')).toHaveTextContent('불러오지 못했습니다');
    expect(screen.queryByText('조건에 맞는 센서가 없습니다')).toBeNull();
    expect(screen.queryByText(/개 캡처/)).toBeNull();
    expect(screen.getByRole('alert')).toHaveTextContent('서버 오류 문구');
  });
});

/* ───────────────────────── 관리 화면 ───────────────────────── */

const auditLog = (id: number, actor: string) => ({
  id,
  occurredAt: '2026-11-19T01:00:00Z',
  actorUsername: actor,
  actorRole: 'ADMIN',
  actionType: 'LOGIN_SUCCESS',
  targetCaptureId: null,
  targetJobId: null,
  targetIncidentId: null,
  detailJson: null,
  clientIp: '127.0.0.1',
});
const auditBody = (logs: unknown[]) => ({
  logs,
  actionTypes: ['LOGIN_SUCCESS', 'USER_ADMIN_CHANGE'],
  selectedActionType: '',
  selectedActorUsername: '',
  selectedLimit: 100,
});

describe('T42 관리 화면', () => {
  it('감사 로그: 처음 실패는 "(0건)"·"조회된 감사 로그가 없습니다"가 아니고, 제출한 새 조건이 실패하면 앞 조건 기록이 남지 않는다. 다시 시도는 제출한 조건으로', async () => {
    let mode: 'ok' | 'fail' = 'fail';
    const auditCalls: string[] = [];
    const user = userEvent.setup();
    renderApp(
      '/admin/audit-logs',
      (url) => {
        if (url.startsWith('/api/admin/audit-logs')) {
          auditCalls.push(url);
          return mode === 'ok' ? json(auditBody([auditLog(1, 'first-actor')])) : serverError();
        }
        return json({}, 404);
      },
      'ADMIN',
    );
    await screen.findByRole('alert');
    expect(screen.queryByText(/감사 로그 \(0건\)/)).toBeNull();
    expect(screen.queryByText('조회된 감사 로그가 없습니다.')).toBeNull();

    mode = 'ok';
    await user.click(within(screen.getByRole('alert')).getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByText('first-actor')).toBeInTheDocument();

    mode = 'fail';
    await user.type(screen.getByLabelText('사용자 아이디'), 'someone');
    await user.click(screen.getByRole('button', { name: /조회/ }));
    await screen.findByRole('alert');
    expect(screen.queryByText('first-actor')).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    // 동작 유형 선택지는 남는다
    expect(document.querySelector('#audit-action-type option[value="USER_ADMIN_CHANGE"]')).not.toBeNull();

    // 입력 칸만 고친 뒤 다시 시도: 제출한 조건(someone)으로 부른다
    await user.clear(screen.getByLabelText('사용자 아이디'));
    await user.type(screen.getByLabelText('사용자 아이디'), 'typed-only');
    await user.click(within(screen.getByRole('alert')).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(auditCalls[auditCalls.length - 1]).toContain('actorUsername=someone'));
  });

  it('사용자 관리: 처음 실패는 "(0명)"이 아니고, 저장 뒤 다시 읽기 실패면 옛 목록에 "최신 값이 아닙니다"가 붙는다', async () => {
    let mode: 'ok' | 'fail' = 'fail';
    const user = userEvent.setup();
    const users = {
      users: [
        {
          id: 1,
          username: 'analyst1',
          displayName: '분석가1',
          role: 'ANALYST',
          totpEnabled: false,
          failedAttempts: 0,
          lockedUntil: null,
          enabled: true,
          createdAt: '2026-11-18T00:00:00Z',
          updatedAt: '2026-11-18T00:00:00Z',
          capturePatterns: ['cic17-*'],
        },
      ],
      roles: ['VIEWER', 'ANALYST', 'ADMIN'],
    };
    renderApp(
      '/admin/users',
      (url, init) => {
        if (url === '/api/admin/users' && (!init?.method || init.method === 'GET')) {
          return mode === 'ok' ? json(users) : serverError();
        }
        if (url.startsWith('/api/admin/users/')) return json({ message: '바꿨습니다' });
        return json({}, 404);
      },
      'ADMIN',
    );
    await screen.findByRole('alert');
    expect(screen.queryByText(/등록 사용자 \(0명\)/)).toBeNull();

    mode = 'ok';
    await user.click(within(screen.getByRole('alert')).getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByText('analyst1')).toBeInTheDocument();

    mode = 'fail';
    await user.click(screen.getByRole('button', { name: /잠금 해제/ }));
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(screen.getByText('analyst1')).toBeInTheDocument();
    expect(screen.getByText(/등록 사용자 \(1명\)/)).toBeInTheDocument();
  });
});
