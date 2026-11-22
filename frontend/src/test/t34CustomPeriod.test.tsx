import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { EmptyPeriodText, isOutsidePeriod, OutsidePeriodNotice } from '../components/OutsidePeriodNotice';
import { ToastProvider } from '../components/ToastContext';
import { bucketLinkLabel, bucketQueueRange } from '../components/dashboard/TrendChart';
import { DASHBOARD_REFRESH_MS } from '../pages/DashboardPage';
import { NEW_INCIDENT_POLL_MS } from '../pages/IncidentQueuePage';
import type { DashboardOverviewResponse, IncidentQueueItem, TrendBucket, UnifiedQueueItem } from '../types/api';
import {
  initialRangeInputs,
  kstInputToMs,
  msToKstInput,
  parseOffsetIso,
  parseRangeParams,
  rangeError,
  rangeFromInputs,
  toUtcIso,
} from '../utils/periodRange';
import { parsePeriodSelection, parseQueueQuery, queueApiParams } from '../utils/triage';
import { fakeNewCount, fakeQueue, unified } from './fakeQueueServer';

/**
 * T34 사용자 지정 기간 화면: KST 변환(브라우저 시간대 무관), 창 검사 문장, URL 왕복(지정 → 프리셋이면 start·end 지움,
 * 섞인 URL은 프리셋 요청), 상세로 넘기는 쿼리, 자동 갱신·새 인시던트 띠 꺼짐(new-count 0회), 추이 막대 링크(자른 구간, 0건 없음),
 * 기간 밖 안내.
 */

const ANCHOR = '2026-11-21T00:00:00Z';
const S = '2026-11-19T00:30:00Z'; // 11-19 09:30 KST
const E = '2026-11-19T03:00:00Z'; // 11-19 12:00 KST
const CUSTOM_QS = `period=custom&start=${encodeURIComponent(S)}&end=${encodeURIComponent(E)}`;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const me = {
  authenticated: true,
  user: {
    username: 'analyst1',
    displayName: '분석가1',
    role: 'ANALYST',
    maskedView: false,
    totpEnabled: false,
    totpVerified: true,
    totpRequired: false,
    allowedCapturePatterns: ['cic17-*', 'lab-*'],
  },
};

function base(i: number): IncidentQueueItem {
  return {
    jobId: 42,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    queueRank: i,
    incidentId: `cic17-wed|10.0.${i}.1|originator|${i}`,
    hostIp: `10.0.${i}.1`,
    zeekadRole: 'originator',
    eventStart: '2026-11-18T00:00:00Z',
    eventEnd: '2026-11-18T00:30:00Z',
    zeekadPickedBy: 'ae_v2',
    zeekadAlsoFlaggedBy: [],
    connectionCount: 10,
    hostName: [],
    zeekadStatus: 'open',
    zeekadResolution: null,
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

const ITEMS: UnifiedQueueItem[] = [1, 2, 3].map((i) =>
  unified(base(i), { detectedAt: `2026-11-19T0${i}:00:00Z`, priority: 'medium' }),
);

function bucket(start: string, end: string, total: number, partial = false): TrendBucket {
  return { start, end, partial, high: 0, medium: total, low: 0, none: 0, total };
}

function fakeOverview(url: string): DashboardOverviewResponse {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const period = p.get('period') ?? '24h';
  const custom = period === 'custom';
  return {
    anchor: ANCHOR,
    anchorMode: 'now',
    snapshot: false,
    period,
    periodStart: custom ? p.get('start') : period === 'all' ? null : '2026-11-20T00:00:00Z',
    periodEnd: custom ? p.get('end') : period === 'all' ? null : ANCHOR,
    timeZone: 'Asia/Seoul',
    staleAfterSeconds: 900,
    downAfterSeconds: 3600,
    trend: custom
      ? {
          bucket: '1h',
          buckets: [
            bucket('2026-11-19T00:00:00Z', '2026-11-19T01:00:00Z', 12, true),
            bucket('2026-11-19T01:00:00Z', '2026-11-19T02:00:00Z', 0),
            bucket('2026-11-19T02:00:00Z', '2026-11-19T03:00:00Z', 3),
          ],
          unbucketed: { noDetectedAt: 0, afterAnchor: 0 },
        }
      : { bucket: '1h', buckets: [bucket('2026-11-20T23:00:00Z', ANCHOR, 2)], unbucketed: { noDetectedAt: 0, afterAnchor: 0 } },
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
  };
}

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

function renderAt(path: string, items: UnifiedQueueItem[] = ITEMS) {
  document.cookie = 'XSRF-TOKEN=t34-token; path=/';
  const calls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json(me);
    if (url === '/api/time-context') return json({ anchor: ANCHOR, anchorMode: 'now', snapshot: false });
    calls.push(url);
    if (url.startsWith('/api/incidents/queue/new-count')) return json(fakeNewCount(url, { items, anchor: ANCHOR }));
    if (url.startsWith('/api/incidents/queue')) return json(fakeQueue(url, { items, anchor: ANCHOR }));
    if (url.startsWith('/api/dashboard/overview')) return json(fakeOverview(url));
    if (url.startsWith('/api/operations')) {
      const p = new URLSearchParams(url.split('?')[1] ?? '');
      return json({
        maskedView: false,
        allowedCaptures: ['cic17-wed'],
        selectedCaptureId: null,
        jobs: [],
        bundles: [],
        feedbackSummaries: [],
        slackSummaries: [],
        period: p.get('period'),
        periodStart: p.get('start'),
        periodEnd: p.get('end'),
        source: null,
        anchor: ANCHOR,
        jobsTruncated: false,
        jobsTotal: 0,
        latestJobs: [],
        sources: [{ captureId: 'cic17-wed', sourceType: 'imported', latestJobId: 42 }],
      });
    }
    return json({}, 404);
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
  return { ...utils, calls };
}

const loc = () => screen.getByTestId('loc').textContent ?? '';
const locParams = () => new URLSearchParams(loc().split('?')[1] ?? '');
const paramsOf = (url: string) => new URLSearchParams(url.split('?')[1] ?? '');

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  document.dispatchEvent(new Event('visibilitychange'));
}

const ORIGINAL_TZ = process.env.TZ;

afterEach(() => {
  vi.useRealTimers();
  setVisibility('visible');
  process.env.TZ = ORIGINAL_TZ;
});

/* ───────────────────────── KST 변환 ───────────────────────── */

describe('KST 입력 변환(브라우저 시간대 무관)', () => {
  function snapshot() {
    return {
      toMs: kstInputToMs('2026-11-19T09:30'),
      toInput: msToKstInput(Date.UTC(2026, 10, 19, 0, 30)),
      ceil: msToKstInput(Date.UTC(2026, 10, 19, 0, 30, 0, 1), 'ceil'),
      floor: msToKstInput(Date.UTC(2026, 10, 19, 0, 30, 59, 999), 'floor'),
      midnight: msToKstInput(Date.UTC(2026, 10, 18, 15, 0)),
      initial: initialRangeInputs('2026-11-20T00:00:30.123456Z', '2026-11-21T00:00:00.5Z', ANCHOR),
      allInitial: initialRangeInputs(null, null, ANCHOR),
      fromInputs: rangeFromInputs('2026-11-19T09:30', '2026-11-19T12:00'),
      dst: kstInputToMs('2026-03-08T02:30'), // 미국 일광 절약 시작 시각(뉴욕에는 없는 시각)
    };
  }

  it('KST가 아닌 시간대(뉴욕·UTC·로스앤젤레스)에서도 같은 값이고 지역 시간에 기대지 않는다', () => {
    const results: ReturnType<typeof snapshot>[] = [];
    for (const tz of ['Asia/Seoul', 'America/New_York', 'UTC', 'America/Los_Angeles']) {
      process.env.TZ = tz;
      results.push(snapshot());
    }
    // 시간대가 실제로 바뀌었는지 확인(뉴욕 11월 오프셋 300분)
    process.env.TZ = 'America/New_York';
    expect(new Date(Date.UTC(2026, 10, 19)).getTimezoneOffset()).toBe(300);
    const first = results[0];
    expect(first.toMs).toBe(Date.UTC(2026, 10, 19, 0, 30));
    expect(first.toInput).toBe('2026-11-19T09:30');
    expect(first.ceil).toBe('2026-11-19T09:31');
    expect(first.floor).toBe('2026-11-19T09:30');
    expect(first.midnight).toBe('2026-11-19T00:00');
    // 처음 값: 시작은 분 내림, 끝은 분 올림
    expect(first.initial).toEqual({ start: '2026-11-20T09:00', end: '2026-11-21T09:01' });
    // 전체 기간이면 기준 시각 − 24시간 ~ 기준 시각
    expect(first.allInitial).toEqual({ start: '2026-11-20T09:00', end: '2026-11-21T09:00' });
    expect(first.fromInputs).toEqual({ range: { start: '2026-11-19T00:30:00Z', end: '2026-11-19T03:00:00Z' } });
    expect(first.dst).toBe(Date.UTC(2026, 2, 7, 17, 30));
    for (const r of results) expect(r).toEqual(first);
  });

  it('오프셋 없는 값·없는 날짜는 받지 않고, URL 값은 서버와 같은 규칙으로 검사한다', () => {
    expect(parseOffsetIso('2026-11-19T00:00:00')).toBeNull();
    expect(parseOffsetIso('2026-02-30T00:00:00Z')).toBeNull();
    expect(parseOffsetIso('2026-11-19T09:00+09:00')).toBe(Date.UTC(2026, 10, 19, 0, 0));
    expect(parseOffsetIso('2026-11-19T00:00:00.123456Z')).toBe(Date.UTC(2026, 10, 19, 0, 0, 0, 123));
    expect(kstInputToMs('2026-11-19 09:30')).toBeNull();
    expect(toUtcIso(Date.UTC(2026, 10, 19))).toBe('2026-11-19T00:00:00Z');
    expect(parseRangeParams('2025-11-19T00:00:00Z', '2026-11-20T00:00:00Z')).not.toBeNull(); // 366일
    expect(parseRangeParams('2025-11-19T00:00:00Z', '2026-11-20T00:00:01Z')).toBeNull();
    expect(parseRangeParams('1999-12-31T15:00:00Z', '2000-01-02T00:00:00Z')).not.toBeNull(); // 2000-01-01 00:00 KST
    expect(parseRangeParams('1999-12-31T14:59:59Z', '2000-01-02T00:00:00Z')).toBeNull();
    expect(parseRangeParams(E, S)).toBeNull();
    expect(parseRangeParams(S, S)).toBeNull();
    expect(rangeError(null, 1)).toBe('시작과 끝을 모두 입력하세요.');
  });
});

/* ───────────────────────── URL 해석 ───────────────────────── */

describe('URL 해석(T34)', () => {
  it('custom은 start·end가 맞을 때만, 섞인 URL은 프리셋으로 읽고 API에서 start·end를 뺀다', () => {
    const q = (s: string) => new URLSearchParams(s);
    expect(parsePeriodSelection(q(CUSTOM_QS), '24h')).toEqual({ period: 'custom', range: { start: S, end: E } });
    expect(parsePeriodSelection(q('period=custom'), '7d')).toEqual({ period: '7d', range: null });
    expect(parsePeriodSelection(q(`period=custom&start=x&end=${E}`), '24h')).toEqual({ period: '24h', range: null });
    expect(parsePeriodSelection(q(`period=24h&start=${S}&end=${E}`), '7d')).toEqual({ period: '24h', range: null });
    expect(parsePeriodSelection(q(''), '7d')).toEqual({ period: '7d', range: null });

    const mixed = parseQueueQuery(q(`period=7d&start=${S}&end=${E}`));
    expect(queueApiParams(mixed)).toMatchObject({ period: '7d', start: undefined, end: undefined });
    const custom = parseQueueQuery(q(CUSTOM_QS));
    // 상세의 이전·다음(paging=false)도 범위를 넘긴다. 새 인시던트 수(period=false)는 넘기지 않는다
    expect(queueApiParams(custom, { paging: false })).toMatchObject({ period: 'custom', start: S, end: E });
    expect(queueApiParams(custom, { paging: false, sort: false, period: false })).toMatchObject({
      period: undefined,
      start: undefined,
      end: undefined,
    });
  });
});

/* ───────────────────────── 큐 화면 ───────────────────────── */

describe('인시던트 큐 기간 지정(T34)', () => {
  it('창에서 지정하면 URL·API가 start·end를 쓰고, 프리셋을 고르면 start·end가 지워진다', async () => {
    const user = userEvent.setup();
    const { calls } = renderAt('/incidents');
    await screen.findAllByText('10.0.1.1');
    const toggle = screen.getByTestId('period-custom');
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    await user.click(toggle);
    const dialog = screen.getByRole('dialog', { name: '기간 지정' });
    const start = within(dialog).getByLabelText('시작 시각(KST)');
    const end = within(dialog).getByLabelText('끝 시각(KST)');
    // 처음 값 = 지금 보이는 24시간(응답 periodStart·periodEnd, KST)
    expect(start).toHaveValue('2026-11-20T09:00');
    expect(end).toHaveValue('2026-11-21T09:00');
    expect(start).toHaveFocus();
    fireEvent.change(start, { target: { value: '2026-11-19T09:30' } });
    fireEvent.change(end, { target: { value: '2026-11-19T12:00' } });
    await user.click(within(dialog).getByRole('button', { name: '적용' }));

    await waitFor(() => expect(locParams().get('period')).toBe('custom'));
    expect(locParams().get('start')).toBe(S);
    expect(locParams().get('end')).toBe(E);
    await waitFor(() => expect(paramsOf(calls.filter((c) => c.startsWith('/api/incidents/queue?')).at(-1)!).get('start')).toBe(S));
    const last = paramsOf(calls.filter((c) => c.startsWith('/api/incidents/queue?')).at(-1)!);
    expect(last.get('period')).toBe('custom');
    expect(last.get('end')).toBe(E);
    // 눌린 상태로 범위를 짧게 보이고 포커스는 버튼으로 돌아온다
    expect(screen.getByTestId('period-custom')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('period-custom')).toHaveTextContent('11-19 09:30 – 11-19 12:00');
    expect(screen.getByTestId('period-custom')).toHaveFocus();
    // 상세로 넘기는 목록 쿼리(from)에 범위가 있다
    const rowLink = screen.getAllByRole('link').find((a) => (a.getAttribute('href') ?? '').includes('from='))!;
    const from = new URLSearchParams(new URLSearchParams(rowLink.getAttribute('href')!.split('?')[1]).get('from')!);
    expect(from.get('period')).toBe('custom');
    expect(from.get('start')).toBe(S);
    expect(from.get('end')).toBe(E);

    // 프리셋(7일)을 고르면 start·end를 지운다
    await user.click(screen.getByRole('button', { name: '7일' }));
    await waitFor(() => expect(locParams().get('period')).toBe('7d'));
    expect(locParams().has('start')).toBe(false);
    expect(locParams().has('end')).toBe(false);
    await waitFor(() => expect(paramsOf(calls.at(-1)!).get('period')).toBe('7d'));
    expect(paramsOf(calls.at(-1)!).has('start')).toBe(false);
  });

  it('섞인 URL(period=24h&start&end)은 24시간 요청이고, 잘못된 custom은 기본 기간이다', async () => {
    const { calls, unmount } = renderAt(`/incidents?period=24h&start=${S}&end=${E}`);
    await screen.findAllByText('10.0.1.1');
    const q = paramsOf(calls.find((c) => c.startsWith('/api/incidents/queue?'))!);
    expect(q.get('period')).toBe('24h');
    expect(q.has('start')).toBe(false);
    expect(q.has('end')).toBe(false);
    unmount();
    const bad = renderAt(`/incidents?period=custom&start=${encodeURIComponent('2026-11-19T00:30:00')}&end=${E}`);
    await screen.findAllByText('10.0.1.1');
    const q2 = paramsOf(bad.calls.find((c) => c.startsWith('/api/incidents/queue?'))!);
    expect(q2.get('period')).toBe('24h');
    expect(q2.has('start')).toBe(false);
    expect(screen.getByTestId('period-custom')).toHaveAttribute('aria-pressed', 'false');
  });

  it('창 검사: 시작 ≥ 끝, 366일 초과, 2000년 앞은 창 안에 한국어로 알리고 적용하지 않는다. Esc로 닫고 포커스가 돌아온다', async () => {
    const user = userEvent.setup();
    renderAt('/incidents');
    await screen.findAllByText('10.0.1.1');
    const toggle = screen.getByTestId('period-custom');
    await user.click(toggle);
    const dialog = screen.getByRole('dialog', { name: '기간 지정' });
    const start = within(dialog).getByLabelText('시작 시각(KST)');
    const end = within(dialog).getByLabelText('끝 시각(KST)');
    const apply = within(dialog).getByRole('button', { name: '적용' });
    const cases: [string, string, string][] = [
      ['2026-11-19T12:00', '2026-11-19T12:00', '시작은 끝보다 앞이어야 합니다.'],
      ['2026-11-19T12:00', '2026-11-19T09:00', '시작은 끝보다 앞이어야 합니다.'],
      ['2025-11-19T09:00', '2026-11-20T09:01', '기간은 366일을 넘을 수 없습니다.'],
      ['1999-12-31T23:59', '2000-01-02T00:00', '시작은 2000-01-01 00:00 KST 이후여야 합니다.'],
      ['', '2026-11-19T09:00', '시작과 끝을 날짜와 시각(분)까지 입력하세요.'],
    ];
    for (const [s, e, msg] of cases) {
      fireEvent.change(start, { target: { value: s } });
      fireEvent.change(end, { target: { value: e } });
      await user.click(apply);
      expect(within(dialog).getByRole('alert')).toHaveTextContent(msg);
      expect(locParams().get('period')).toBeNull();
    }
    // 경계값 366일·2000-01-01 00:00 KST는 통과
    fireEvent.change(start, { target: { value: '2000-01-01T00:00' } });
    fireEvent.change(end, { target: { value: '2000-12-31T00:00' } });
    await user.click(apply);
    await waitFor(() => expect(locParams().get('start')).toBe('1999-12-31T15:00:00Z'));

    await user.click(screen.getByTestId('period-custom'));
    expect(screen.getByRole('dialog', { name: '기간 지정' })).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: '기간 지정' })).toBeNull();
    expect(screen.getByTestId('period-custom')).toHaveFocus();
  });

  it('T35: aria-controls는 창이 열려 있을 때만 있고, 가리키는 id가 DOM에 있다', async () => {
    const user = userEvent.setup();
    renderAt('/incidents');
    await screen.findAllByText('10.0.1.1');
    const toggle = screen.getByTestId('period-custom');
    expect(toggle).not.toHaveAttribute('aria-controls');
    expect(document.getElementById('period-range-dialog')).toBeNull();
    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-controls', 'period-range-dialog');
    expect(document.getElementById('period-range-dialog')).toBe(screen.getByRole('dialog', { name: '기간 지정' }));
    await user.keyboard('{Escape}');
    expect(screen.getByTestId('period-custom')).not.toHaveAttribute('aria-controls');
    expect(document.getElementById('period-range-dialog')).toBeNull();
  });

  it('지정 기간이면 new-count를 한 번도 부르지 않고 꺼졌다는 글을 보인다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { calls } = renderAt(`/incidents?${CUSTOM_QS}`);
    await screen.findAllByText('10.0.2.1');
    expect(screen.getByTestId('new-count-off')).toHaveTextContent('새 인시던트 알림을 멈춥니다');
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS * 3);
    });
    setVisibility('hidden');
    setVisibility('visible');
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    expect(calls.filter((c) => c.startsWith('/api/incidents/queue/new-count'))).toHaveLength(0);
  });

  it('빈 목록 글이 지정 범위를 쓴다', async () => {
    renderAt(`/incidents?period=custom&start=${encodeURIComponent('2026-11-10T00:00:00Z')}&end=${encodeURIComponent('2026-11-11T00:00:00Z')}`, []);
    expect(await screen.findByText('11-10 09:00 – 11-11 09:00 동안 탐지된 인시던트가 없습니다.')).toBeInTheDocument();
    expect(screen.getByTestId('period-custom')).toHaveTextContent('11-10 09:00 – 11-11 09:00');
  });
});

/* ───────────────────────── 현황판 ───────────────────────── */

describe('현황판 기간 지정(T34)', () => {
  it('지정 기간이면 60초 자동 갱신을 끄고 글로 알린다. 수동 새로 고침은 된다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { calls } = renderAt(`/?${CUSTOM_QS}`);
    await screen.findByRole('region', { name: '탐지 추이' });
    expect(screen.getByTestId('auto-refresh-off')).toHaveTextContent('자동 갱신 꺼짐');
    const overviews = () => calls.filter((c) => c.startsWith('/api/dashboard/overview'));
    expect(overviews()).toHaveLength(1);
    expect(paramsOf(overviews()[0]).get('start')).toBe(S);
    // 에스컬레이션 대기(기간 무관) 큐 호출에는 start·end가 없다
    const allQueue = calls.filter((c) => c.startsWith('/api/incidents/queue?') && paramsOf(c).get('period') === 'all');
    expect(allQueue).toHaveLength(1);
    expect(paramsOf(allQueue[0]).has('start')).toBe(false);
    await act(async () => {
      vi.advanceTimersByTime(DASHBOARD_REFRESH_MS * 3);
    });
    expect(overviews()).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: /새로 고침/ }));
    await waitFor(() => expect(overviews()).toHaveLength(2));
  });

  it('추이 막대: 건수가 있는 막대만 링크이고, 구간은 기간 경계로 자르고 이름에 구간·건수가 있다. 누르면 그 구간 큐로 간다', async () => {
    const user = userEvent.setup();
    renderAt(`/?${CUSTOM_QS}&source=imported`);
    const panel = await screen.findByRole('region', { name: '탐지 추이' });
    expect(within(panel).getByText(/11-19 09:30 – 11-19 12:00 · 구간 1시간/)).toBeInTheDocument();
    const links = panel.querySelectorAll('a[data-bucket-link]');
    expect(links).toHaveLength(2); // 0건 막대는 링크가 없다
    expect(links[0]).toHaveAttribute('aria-label', '11-19 09:30–10:00 인시던트 12건 보기');
    expect(links[1]).toHaveAttribute('aria-label', '11-19 11:00–12:00 인시던트 3건 보기');
    const href = new URLSearchParams(links[0].getAttribute('href')!.split('?')[1]);
    expect(href.get('period')).toBe('custom');
    expect(href.get('start')).toBe(S); // 구간 시작 00:00Z를 기간 시작 00:30Z로 자름
    expect(href.get('end')).toBe('2026-11-19T01:00:00Z');
    expect(href.get('source')).toBe('imported');
    await user.click(links[1] as Element);
    await waitFor(() => expect(loc().startsWith('/incidents?')).toBe(true));
    expect(locParams().get('start')).toBe('2026-11-19T02:00:00Z');
    expect(locParams().get('end')).toBe(E);
    expect(locParams().get('source')).toBe('imported');
  });

  it('구간 자르기: 기준 시각과 기간 끝 중 앞선 것, 기간 시작 중 늦은 것. 0건은 null', () => {
    const b = bucket('2026-11-20T23:00:00Z', '2026-11-21T00:00:00Z', 4);
    expect(bucketQueueRange(b, '2026-11-20T00:30:00Z', '2026-11-22T00:00:00Z', '2026-11-20T23:40:00Z')).toEqual({
      start: '2026-11-20T23:00:00Z',
      end: '2026-11-20T23:40:00Z',
    });
    expect(bucketQueueRange(b, '2026-11-20T23:10:00.123456Z', null, ANCHOR)).toEqual({
      start: '2026-11-20T23:10:00.123456Z',
      end: '2026-11-21T00:00:00Z',
    });
    expect(bucketQueueRange({ ...b, total: 0 }, null, null, ANCHOR)).toBeNull();
    expect(bucketLinkLabel({ start: '2026-11-19T14:00:00Z', end: '2026-11-19T15:00:00Z' }, 1234, ANCHOR)).toBe(
      '11-19 23:00–11-20 00:00 인시던트 1,234건 보기',
    );
  });

  it('현황판 링크(운영 현황·큐)가 범위를 넘긴다', async () => {
    renderAt(`/?${CUSTOM_QS}`);
    await screen.findByRole('region', { name: '탐지 추이' });
    const ops = screen.getByRole('link', { name: /누적 판정·탐지 모델 성능은 운영 현황/ });
    const p = new URLSearchParams(ops.getAttribute('href')!.split('?')[1]);
    expect(p.get('period')).toBe('custom');
    expect(p.get('start')).toBe(S);
    const kpi = within(screen.getByRole('region', { name: '핵심 지표' }));
    const total = new URLSearchParams(kpi.getByRole('link', { name: /탐지된 인시던트/ }).getAttribute('href')!.split('?')[1]);
    expect(total.get('end')).toBe(E);
    const pending = new URLSearchParams(kpi.getByRole('link', { name: /에스컬레이션 대기/ }).getAttribute('href')!.split('?')[1]);
    expect(pending.get('period')).toBe('all');
    expect(pending.has('start')).toBe(false);
  });
});

/* ───────────────────────── 운영 현황 ───────────────────────── */

describe('운영 현황 기간 지정(T34)', () => {
  it('지정 기간을 두 API에 넘기고 범위 글이 지정 범위다', async () => {
    const { calls } = renderAt(`/operations?${CUSTOM_QS}`);
    await waitFor(() => expect(calls.some((c) => c.startsWith('/api/operations?'))).toBe(true));
    const ops = paramsOf(calls.find((c) => c.startsWith('/api/operations?'))!);
    const ov = paramsOf(calls.find((c) => c.startsWith('/api/dashboard/overview?'))!);
    for (const p of [ops, ov]) {
      expect(p.get('period')).toBe('custom');
      expect(p.get('start')).toBe(S);
      expect(p.get('end')).toBe(E);
    }
    expect(await screen.findAllByText(/11-19 09:30 – 11-19 12:00/)).not.toHaveLength(0);
  });
});

/* ───────────────────────── 기간 밖 안내 ───────────────────────── */

describe('기간 밖 안내(T34)', () => {
  it('isOutsidePeriod는 응답의 periodStart·periodEnd를 쓴다', () => {
    expect(isOutsidePeriod('2026-11-19T00:30:00Z', S, E)).toBe(true); // 시작과 같으면 밖
    expect(isOutsidePeriod('2026-11-19T03:00:00Z', S, E)).toBe(false); // 끝과 같으면 안
    expect(isOutsidePeriod('2026-11-19T03:00:01Z', S, E)).toBe(true);
    expect(isOutsidePeriod('2026-11-19T03:00:01Z', null, null)).toBe(false); // 전체
  });

  it('지정 기간이면 수와 "전체 기간 보기"만 보이고, 빈 결과 글은 고른 수집원이 범위 밖임을 알린다', () => {
    const queue = {
      ...fakeQueue(`/api/incidents/queue?${CUSTOM_QS}`, { items: [], anchor: ANCHOR }),
      total: 5,
      outsidePeriod: 7,
      newestOutsidePeriod: null,
      sources: [{ captureId: 'cic17-wed', sourceType: 'imported' as const, latestJobId: 42, lastDetectedAt: '2026-11-12T03:10:00Z' }],
    };
    const { unmount } = render(<OutsidePeriodNotice queue={queue} onAllPeriod={() => undefined} />);
    const notice = screen.getByTestId('outside-period');
    expect(notice).toHaveTextContent('선택한 기간 밖 인시던트 7건');
    expect(notice).not.toHaveTextContent('가장 최근');
    expect(within(notice).getByRole('button', { name: '전체 기간 보기' })).toBeInTheDocument();
    unmount();
    render(<EmptyPeriodText queue={{ ...queue, total: 0 }} sourceValue="cap:cic17-wed" />);
    expect(screen.getByText(/이 기간에 탐지된 인시던트가 없습니다/)).not.toHaveTextContent('가장 최근 탐지');
    expect(screen.getByTestId('source-outside')).toHaveTextContent('선택한 기간 밖입니다');
  });
});
