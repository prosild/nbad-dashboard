import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { DASHBOARD_REFRESH_MS } from '../pages/DashboardPage';
import type {
  CaptureRow,
  DashboardOverviewResponse,
  IncidentQueueItem,
  SensorRow,
  TrendBucket,
  UnifiedQueueItem,
} from '../types/api';
import { fakeQueue, unified } from './fakeQueueServer';
import { expectAllTablesInScrollBox, tablesOutsideScrollBox } from './tableScrollBox';

/**
 * T24 현황판·운영 현황(시간·수집원 기준). 기존 T20·T26 현황판 시험의 단언은 지우지 않고 새 동작 단언으로 바꿨다:
 * - "API 두 번" → overview·큐(최근)·큐(전체 기간) 세 번
 * - KPI(누적 합) → 같은 조건 큐 summary, 링크 목록 수 = 카드 수
 * - 기준 띠(데이터 기준) → 조건 줄의 기준 시각, 없어진 "데이터 기준"은 없다는 단언
 * - 탐지 모델 상태·캡처별 현황·파이프라인 패널 → 없어졌다는 단언(누적 정탐률·작업 기록은 운영 현황 쪽 단언)
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const ANCHOR = '2026-11-21T00:00:00Z';
const minutesAgo = (m: number) => new Date(new Date(ANCHOR).getTime() - m * 60_000).toISOString();

const analystUser = {
  username: 'analyst1',
  displayName: '분석가1',
  role: 'ANALYST',
  maskedView: false,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['cic17-*', 'syn1-*', 'lab-*'],
};

function base(i: number, captureId: string): IncidentQueueItem {
  return {
    jobId: 40 + i,
    captureId,
    bundleId: 'zeekad-fusion/3',
    queueRank: i,
    incidentId: `${captureId}|10.0.${i}.1|originator|${i}`,
    hostIp: `10.0.${i}.1`,
    zeekadRole: 'originator',
    eventStart: minutesAgo(600),
    eventEnd: minutesAgo(590),
    zeekadPickedBy: 'tgn_recon',
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

function item(
  i: number,
  captureId: string,
  detectedMinutesAgo: number,
  priority: 'high' | 'medium' | 'low' | null,
  extra: Partial<IncidentQueueItem> = {},
): UnifiedQueueItem {
  return unified({ ...base(i, captureId), ...extra }, { detectedAt: minutesAgo(detectedMinutesAgo), priority });
}

/** 시험 인시던트: 기간마다 다르게 나뉜다(1시간 3건, 24시간 5건, 7일 7건, 30일 8건, 전체 9건) */
const ITEMS: UnifiedQueueItem[] = [
  item(1, 'lab-20261120', 10, 'high', { alerted: true, zeekadWouldSend: true }),
  item(2, 'lab-20261120', 20, 'medium'),
  item(3, 'lab-20261120', 30, null, { zeekadStatus: 'closed' }),
  item(4, 'lab-20261120', 300, 'high', { zeekadReviewPending: true }),
  item(5, 'lab-20261119', 1200, 'low'),
  item(6, 'cic17-wed', 3 * 1440, 'low', { alerted: true }),
  item(7, 'cic17-wed', 5 * 1440, 'medium'),
  item(8, 'syn1-thu', 20 * 1440, 'low'),
  item(9, 'syn1-thu', 40 * 1440, 'high', { zeekadReviewPending: true }),
];

const PERIOD_MIN: Record<string, number> = { '1h': 60, '24h': 1440, '7d': 7 * 1440, '30d': 30 * 1440 };
const periodFilter = (it: UnifiedQueueItem, period: string) =>
  period === 'all' || new Date(ANCHOR).getTime() - new Date(it.detectedAt as string).getTime() < PERIOD_MIN[period] * 60_000;

const BUCKET_COUNT: Record<string, number> = { '1h': 12, '24h': 24, '7d': 28, '30d': 30, all: 41 };

function buckets(period: string, total: number): TrendBucket[] {
  const n = BUCKET_COUNT[period] ?? 24;
  const out: TrendBucket[] = [];
  for (let i = 0; i < n; i++) {
    const t = i === n - 1 ? total : 0;
    out.push({
      start: minutesAgo((n - i) * 60),
      end: minutesAgo((n - i - 1) * 60),
      partial: i === 0,
      high: t,
      medium: 0,
      low: 0,
      none: 0,
      total: t,
    });
  }
  return out;
}

function jobRef(jobId: number, captureId: string, status: string, finishedMinutesAgo: number, error: string | null = null) {
  return { jobId, captureId, bundleId: 'zeekad-fusion/3', status, startedAt: minutesAgo(finishedMinutesAgo + 2), finishedAt: minutesAgo(finishedMinutesAgo), error };
}

const SENSOR: SensorRow = {
  sensorKey: 'lab-*',
  label: '실습망 센서',
  health: 'ok',
  latestJob: jobRef(60, 'lab-20261120', 'succeeded', 5),
  activeCaptureId: 'lab-20261120',
  lastScoredAt: minutesAgo(5),
  lastActivityAt: minutesAgo(12),
  total: 0,
  high: 0,
  alerted: 0,
  failedJobs: 0,
  captureCount: 2,
};

const CAPTURES: CaptureRow[] = [
  { captureId: 'lab-20261120', sourceType: 'live', sensorKey: 'lab-*', state: 'active', latestJob: jobRef(60, 'lab-20261120', 'succeeded', 5), lastScoredAt: minutesAgo(5), lastActivityAt: minutesAgo(12), total: 0, high: 0, alerted: 0, failedJobs: 0 },
  { captureId: 'lab-20261119', sourceType: 'live', sensorKey: 'lab-*', state: 'ended', latestJob: jobRef(55, 'lab-20261119', 'succeeded', 1000), lastScoredAt: minutesAgo(1000), lastActivityAt: null, total: 0, high: 0, alerted: 0, failedJobs: 0 },
  { captureId: 'cic17-wed', sourceType: 'imported', sensorKey: null, state: 'imported', latestJob: jobRef(2, 'cic17-wed', 'succeeded', 9000), lastScoredAt: minutesAgo(9000), lastActivityAt: minutesAgo(9100), total: 0, high: 0, alerted: 0, failedJobs: 0 },
  { captureId: 'syn1-thu', sourceType: 'imported', sensorKey: null, state: 'failed', latestJob: jobRef(9, 'syn1-thu', 'failed', 600, '근거 API 시간 초과 10.0.0.*'), lastScoredAt: minutesAgo(30000), lastActivityAt: minutesAgo(30100), total: 0, high: 0, alerted: 0, failedJobs: 1 },
];

/** 가짜 overview: 조건에 맞는 캡처만, 수는 가짜 큐와 같은 집합으로 센다(불변식) */
function fakeOverview(url: string, opts: { snapshot?: boolean; sensors?: SensorRow[]; captures?: CaptureRow[] } = {}): DashboardOverviewResponse {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const period = p.get('period') ?? '24h';
  const inCond = (c: { captureId: string; sourceType: string }) =>
    (!p.get('source') || c.sourceType === p.get('source')) && (!p.get('captureId') || c.captureId === p.get('captureId'));
  const queue = fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter });
  const captures = (opts.captures ?? CAPTURES).filter(inCond).map((c) => {
    const mine = ITEMS.filter((i) => i.captureId === c.captureId && periodFilter(i, period));
    return { ...c, total: mine.length, high: mine.filter((i) => i.priority === 'high').length, alerted: mine.filter((i) => i.alerted).length };
  });
  const sensors = (opts.sensors ?? [SENSOR])
    .map((s) => {
      const mine = captures.filter((c) => c.sensorKey === s.sensorKey);
      return mine.length === 0 && !opts.sensors
        ? null
        : { ...s, total: mine.reduce((a, c) => a + c.total, 0), high: mine.reduce((a, c) => a + c.high, 0) };
    })
    .filter((s): s is SensorRow => s !== null);
  return {
    anchor: ANCHOR,
    anchorMode: opts.snapshot ? 'latest-data' : 'now',
    snapshot: Boolean(opts.snapshot),
    period,
    timeZone: 'Asia/Seoul',
    staleAfterSeconds: 900,
    downAfterSeconds: 3600,
    trend: { bucket: period === '1h' ? '5m' : period === '24h' ? '1h' : period === '7d' ? '6h' : '1d', buckets: buckets(period, queue.summary.total), unbucketed: { noDetectedAt: 0, afterAnchor: 0 } },
    sensors,
    captures,
    alerting: {
      latestDeliveryMode: 'dry_run',
      latestDeliveryStatus: 'recorded',
      latestDryRun: true,
      latestCreatedAt: '2026-11-20T15:40:00Z',
      latestDeliveredAt: null,
      latestCaptureId: 'lab-20261120',
      summariesInPeriod: 1,
    },
    maskedView: false,
  };
}

const baseRow = {
  bundleId: 'zeekad-fusion/3',
  truePositive: 0,
  falsePositive: 0,
  benign: 0,
  zeekadPrecision: null,
  zeekadAlertPrecision: null,
  zeekadAlertResolvedRate: null,
  alertedResolved: null,
  extraAttributes: {},
};

/** cic17-wed: 판정 9건(표본 부족), syn1-thu: 판정 10건(정탐률 표시). 탐지 모델 행도 9/10건 경계. */
const FEEDBACK = [
  { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'all', allModel: true, incidents: 79, alerted: 9, resolved: 9, truePositive: 8, zeekadPrecision: 0.889, alertedResolved: 1, zeekadAlertPrecision: 1, zeekadAlertResolvedRate: 0.111 },
  { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'tgn_recon', allModel: false, incidents: 30, resolved: 9, truePositive: 8, zeekadPrecision: 0.889 },
  { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'transformer_v2', allModel: false, incidents: 49, alerted: 0, resolved: 0 },
  { ...baseRow, captureId: 'syn1-thu', zeekadPickedBy: 'all', allModel: true, incidents: 21, alerted: 3, resolved: 10, truePositive: 6, zeekadPrecision: 0.6, alertedResolved: 3, zeekadAlertPrecision: 0.667, zeekadAlertResolvedRate: 1 },
  { ...baseRow, captureId: 'syn1-thu', zeekadPickedBy: 'tail_rarity_v2', allModel: false, incidents: 21, resolved: 10, truePositive: 6, zeekadPrecision: 0.6 },
];

const ALL_JOBS = [
  { jobId: 9, captureId: 'syn1-thu', bundleId: 'zeekad-fusion/3', status: 'failed', startedAt: null, finishedAt: minutesAgo(600), error: '근거 API 시간 초과', incidentCount: null },
  { jobId: 8, captureId: 'syn1-thu', bundleId: 'zeekad-fusion/3', status: 'succeeded', startedAt: null, finishedAt: minutesAgo(30000), error: null, incidentCount: 21 },
  { jobId: 2, captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', status: 'succeeded', startedAt: null, finishedAt: minutesAgo(9000), error: null, incidentCount: 79 },
];

const SOURCES = [
  { captureId: 'cic17-wed', sourceType: 'imported', latestJobId: 2 },
  { captureId: 'lab-20261119', sourceType: 'live', latestJobId: 55 },
  { captureId: 'lab-20261120', sourceType: 'live', latestJobId: 60 },
  { captureId: 'syn1-thu', sourceType: 'imported', latestJobId: 8 },
];

/** 가짜 /api/operations: 작업·Slack 요약은 기간 안만, 판정 집계·latestJobs는 기간 무관 */
function fakeOperations(url: string, opts: { truncated?: boolean } = {}) {
  const p = new URLSearchParams(url.split('?')[1] ?? '');
  const period = p.get('period');
  const within = (iso: string | null) =>
    !period || period === 'all' || (iso !== null && new Date(ANCHOR).getTime() - new Date(iso).getTime() < PERIOD_MIN[period] * 60_000);
  const jobs = ALL_JOBS.filter((j) => within(j.finishedAt));
  return {
    maskedView: false,
    allowedCaptures: SOURCES.map((s) => s.captureId),
    selectedCaptureId: p.get('captureId'),
    jobs,
    bundles: [],
    feedbackSummaries: FEEDBACK,
    slackSummaries: [
      { jobId: 8, captureId: 'syn1-thu', zeekadMessageVersion: 'daily-summary.v1', zeekadDeliveryMode: 'dry_run', zeekadDeliveryStatus: 'recorded', slackPayload: null, slackTs: null, deliveredAt: null, createdAt: minutesAgo(30000), dryRunOrRecorded: true, payloadTextPreview: '요약', payloadChannel: '#sec' },
    ].filter((s) => within(s.createdAt)),
    period,
    source: p.get('source'),
    anchor: ANCHOR,
    jobsTruncated: Boolean(opts.truncated),
    jobsTotal: opts.truncated ? 1234 : jobs.length,
    latestJobs: [
      { captureId: 'cic17-wed', latestEnded: jobRef(2, 'cic17-wed', 'succeeded', 9000), latestSucceeded: jobRef(2, 'cic17-wed', 'succeeded', 9000) },
      { captureId: 'syn1-thu', latestEnded: jobRef(9, 'syn1-thu', 'failed', 600, '근거 API 시간 초과'), latestSucceeded: jobRef(8, 'syn1-thu', 'succeeded', 30000) },
    ],
    sources: SOURCES,
  };
}

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

interface RenderOptions {
  overview?: (url: string) => Response;
  queue?: (url: string) => Response;
  operations?: (url: string) => Response;
  snapshot?: boolean;
}

function renderAt(path: string, options: RenderOptions = {}) {
  document.cookie = 'XSRF-TOKEN=dashboard-test-token; path=/';
  const calls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: analystUser });
    if (url === '/api/time-context') return json({ anchor: ANCHOR, anchorMode: options.snapshot ? 'latest-data' : 'now', snapshot: Boolean(options.snapshot) });
    calls.push(url);
    if (url.startsWith('/api/dashboard/overview')) {
      return options.overview ? options.overview(url) : json(fakeOverview(url, { snapshot: options.snapshot }));
    }
    if (url.startsWith('/api/incidents/queue')) {
      return options.queue
        ? options.queue(url)
        : json(fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter, snapshot: options.snapshot, newestOutsidePeriod: minutesAgo(10) }));
    }
    if (url.startsWith('/api/operations')) return options.operations ? options.operations(url) : json(fakeOperations(url));
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
  return { ...utils, fetchMock, calls };
}

const paramsOf = (url: string) => Object.fromEntries(new URLSearchParams(url.split('?')[1] ?? ''));
const hrefParams = (a: HTMLElement) => new URLSearchParams((a.getAttribute('href') ?? '').split('?')[1] ?? '');

async function kpiRegion() {
  const kpi = await screen.findByRole('region', { name: '핵심 지표' });
  await waitFor(() => expect(within(kpi).getByRole('link', { name: /에스컬레이션 대기/ })).not.toHaveTextContent(/^에스컬레이션 대기현재-$/));
  return kpi;
}

const kpiValue = (link: HTMLElement) => Number((link.querySelector('[data-kpi-value]')?.textContent ?? '').replace(/,/g, ''));

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  document.dispatchEvent(new Event('visibilitychange'));
}

afterEach(() => {
  vi.useRealTimers();
  setVisibility('visible');
});

describe('라우팅과 사이드바(T20)', () => {
  it("'/'는 현황판이고 사이드바의 현황판만 활성이다", async () => {
    renderAt('/');
    expect(await screen.findByRole('heading', { name: '현황판' })).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: '주 메뉴' });
    const links = within(nav).getAllByRole('link');
    expect(links[0]).toHaveTextContent('현황판');
    expect(within(nav).getByRole('link', { name: '현황판' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: '인시던트' })).not.toHaveAttribute('aria-current');
  });

  it("'/incidents'는 인시던트 목록이고 사이드바의 인시던트만 활성이다", async () => {
    renderAt('/incidents');
    expect(await screen.findByRole('heading', { name: '인시던트' })).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: '주 메뉴' });
    expect(within(nav).getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: '현황판' })).not.toHaveAttribute('aria-current');
  });

  it('모르는 경로는 현황판으로 간다', async () => {
    renderAt('/nowhere');
    expect(await screen.findByRole('heading', { name: '현황판' })).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/$/);
  });
});

describe('관제 현황판(T24 시간·수집원 기준)', () => {
  it('API 세 번(overview·큐 최근·큐 전체 기간)으로 그리고 KPI 넷은 같은 조건 큐 summary다(기본 24시간)', async () => {
    const { calls } = renderAt('/');
    const kpi = await kpiRegion();
    expect(calls.map(paramsOf)).toEqual(
      expect.arrayContaining([
        { period: '24h' },
        { period: '24h', sort: 'detected', dir: 'desc', size: '25' },
        { period: 'all', size: '25' },
      ]),
    );
    expect(calls.filter((c) => c.startsWith('/api/dashboard/overview'))).toEqual(['/api/dashboard/overview?period=24h']);
    expect(calls.some((c) => c.startsWith('/api/operations') || c.startsWith('/api/reviews'))).toBe(false);

    const total = within(kpi).getByRole('link', { name: /탐지된 인시던트/ });
    expect(kpiValue(total)).toBe(5);
    expect(total).toHaveTextContent('최근 24시간');
    expect(kpiValue(within(kpi).getByRole('link', { name: /High\(미종결\)/ }))).toBe(2);
    expect(kpiValue(within(kpi).getByRole('link', { name: /경보 발송/ }))).toBe(1);
    const pending = within(kpi).getByRole('link', { name: /에스컬레이션 대기/ });
    expect(kpiValue(pending)).toBe(2); // 전체 기간: 4번(24시간 안)·9번(40일 전)
    expect(pending).toHaveTextContent('현재');
    expect(pending.getAttribute('title')).toContain('최신 분석 결과 기준');
  });

  it('KPI 링크는 조건(period·source·captureId)을 그대로 싣고, 카드 수 = 그 링크로 부른 큐 목록 수다', async () => {
    for (const path of ['/', '/?period=1h', '/?period=7d&source=live', '/?period=30d&source=imported', '/?period=all&captureId=lab-20261120']) {
      const view = renderAt(path);
      const kpi = await kpiRegion();
      const want = new URLSearchParams(path.split('?')[1] ?? '');
      for (const link of within(kpi).getAllByRole('link')) {
        const q = hrefParams(link);
        const label = link.textContent ?? '';
        expect(q.get('source'), `${path} ${label}`).toBe(want.get('source'));
        expect(q.get('captureId'), `${path} ${label}`).toBe(want.get('captureId'));
        if (label.startsWith('에스컬레이션 대기')) {
          expect(q.get('period')).toBe('all');
          expect(q.get('reviewPending')).toBe('true');
        } else {
          expect(q.get('period'), `${path} ${label}`).toBe(want.get('period') ?? '24h');
        }
        // 카드 수 = 같은 링크 조건으로 부른 큐의 목록 수(total, 띠 축 포함)
        const listed = fakeQueue(`/api/incidents/queue?${q.toString()}`, { items: ITEMS, anchor: ANCHOR, periodFilter });
        expect(kpiValue(link), `${path} ${label}`).toBe(listed.total);
      }
      view.unmount();
    }
  });

  it('KPI를 누르면 같은 조건의 인시던트 목록으로 간다', async () => {
    const user = userEvent.setup();
    renderAt('/?period=7d&source=live');
    const kpi = await kpiRegion();
    await user.click(within(kpi).getByRole('link', { name: /High\(미종결\)/ }));
    expect(screen.getByTestId('location')).toHaveTextContent('/incidents?period=7d&source=live&priority=high');
  });

  it('기간·수집원을 바꾸면 URL과 요청 조건이 바뀐다. 조건 줄에 기준 시각 = 현재와 불러온 시각이 있다', async () => {
    const user = userEvent.setup();
    const { calls } = renderAt('/');
    await kpiRegion();
    const bar = screen.getByRole('region', { name: '보기 조건' });
    expect(within(bar).getByTestId('dashboard-anchor')).toHaveTextContent('기준 시각 = 현재');
    expect(bar).toHaveTextContent('불러온 시각');
    await user.click(within(bar).getByRole('button', { name: '7일' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/?period=7d');
    await waitFor(() => expect(calls).toContain('/api/dashboard/overview?period=7d'));
    await user.selectOptions(within(bar).getByLabelText('수집원'), 'src:imported');
    expect(screen.getByTestId('location')).toHaveTextContent('/?period=7d&source=imported');
    await waitFor(() => expect(calls).toContain('/api/dashboard/overview?period=7d&source=imported'));
    await user.selectOptions(within(bar).getByLabelText('수집원'), 'cap:lab-20261120');
    expect(screen.getByTestId('location')).toHaveTextContent('/?period=7d&captureId=lab-20261120');
    // 기본 기간(24시간)을 고르면 주소에서 뺀다
    await user.click(within(bar).getByRole('button', { name: '24시간' }));
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/\?captureId=lab-20261120$/);
  });

  it('자동 갱신: 60초마다 다시 부르고, 화면이 숨겨지면 멈췄다가 보이면 곧바로 부른다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const { calls } = renderAt('/');
    await kpiRegion();
    await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
    const overviews = () => calls.filter((c) => c.startsWith('/api/dashboard/overview')).length;
    expect(overviews()).toBe(1);
    await act(async () => {
      vi.advanceTimersByTime(DASHBOARD_REFRESH_MS);
    });
    await waitFor(() => expect(overviews()).toBe(2));
    act(() => setVisibility('hidden'));
    await act(async () => {
      vi.advanceTimersByTime(DASHBOARD_REFRESH_MS * 3);
    });
    expect(overviews()).toBe(2);
    act(() => setVisibility('visible'));
    await waitFor(() => expect(overviews()).toBe(3));
  });

  it('자동 갱신: 고정 스냅샷이면 꺼지고 조건 줄의 기준 시각은 맨 위 띠와 같은 값이다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const { calls } = renderAt('/', { snapshot: true });
    await kpiRegion();
    expect(screen.getByTestId('dashboard-anchor')).toHaveTextContent('기준 시각 2026-11-21 09:00:00 KST');
    await act(async () => {
      vi.advanceTimersByTime(DASHBOARD_REFRESH_MS * 3);
    });
    expect(calls.filter((c) => c.startsWith('/api/dashboard/overview'))).toHaveLength(1);
  });

  it('탐지 추이: 구간 수만큼 막대 묶음, 구간마다 툴팁, 화면 판독기용 표', async () => {
    const view = renderAt('/');
    const trend = await screen.findByRole('region', { name: '탐지 추이' });
    await waitFor(() => expect(trend.querySelectorAll('[data-bucket]')).toHaveLength(24));
    expect(trend.querySelectorAll('[data-bucket][data-partial="true"]')).toHaveLength(1);
    expect(trend.querySelector('[data-bucket] title')?.textContent).toContain('KST');
    // 표 자체가 아니라 감싼 상자가 sr-only여야 한다(표는 내용 폭보다 좁아지지 않아 휴대폰에서 페이지가 넘쳤다).
    const table = trend.querySelector('div.sr-only[data-trend-table] > table') as HTMLTableElement;
    expect(table).not.toBeNull();
    expect(table).not.toHaveClass('sr-only');
    expect(table.caption?.textContent).toBe('탐지 추이 구간별 인시던트 수');
    expect(table.querySelectorAll('tbody tr')).toHaveLength(24);
    expect(trend.querySelector('[data-axis-max]')).toHaveTextContent('5');
    expect(trend).toHaveTextContent('구간 1시간');
    view.unmount();

    renderAt('/?period=7d');
    const week = await screen.findByRole('region', { name: '탐지 추이' });
    await waitFor(() => expect(week.querySelectorAll('[data-bucket]')).toHaveLength(28));
    expect(week).toHaveTextContent('구간 6시간');
  });

  it('탐지 추이: 기간 안 0건이면 가장 최근 탐지와 [기간: 전체로 보기]를 보인다', async () => {
    const user = userEvent.setup();
    const empty = (url: string) => fakeQueue(url, { items: [], anchor: ANCHOR, newestOutsidePeriod: '2026-11-12T03:00:00Z' });
    renderAt('/?period=1h', {
      queue: (url) => json({ ...empty(url), sources: SOURCES }),
      overview: (url) => json({ ...fakeOverview(url), trend: { bucket: '5m', buckets: buckets('1h', 0), unbucketed: { noDetectedAt: 0, afterAnchor: 0 } } }),
    });
    const trend = await screen.findByRole('region', { name: '탐지 추이' });
    expect(await within(trend).findByText(/이 기간에 탐지된 인시던트가 없습니다\. 가장 최근 탐지:/)).toHaveTextContent('2026-11-12 12:00:00');
    expect(trend.querySelectorAll('[data-bucket]')).toHaveLength(0);
    await user.click(within(trend).getByRole('button', { name: '기간: 전체로 보기' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/?period=all');
  });

  it('탐지 추이: 구간에 들지 않은 인시던트가 있으면 한 줄로 알린다', async () => {
    renderAt('/?period=all', {
      overview: (url) => {
        const ov = fakeOverview(url);
        return json({ ...ov, trend: { ...ov.trend, unbucketed: { noDetectedAt: 2, afterAnchor: 1 } } });
      },
    });
    const trend = await screen.findByRole('region', { name: '탐지 추이' });
    expect(await within(trend).findByText(/추이에 넣지 않은 인시던트/)).toHaveTextContent('탐지 시각 없음 2건 · 기준 시각 뒤 탐지 1건');
  });

  it('최근 인시던트: 탐지 시각 최근순 최대 8줄, 상세 링크에 from=(같은 조건·정렬), [모두 보기]', async () => {
    const many = Array.from({ length: 12 }, (_, i) => item(20 + i, 'lab-20261120', 5 + i, 'low'));
    renderAt('/?source=live', {
      queue: (url) => json(fakeQueue(url, { items: [...ITEMS, ...many], anchor: ANCHOR, periodFilter })),
    });
    const panel = await screen.findByRole('region', { name: '최근 인시던트' });
    await waitFor(() => expect(panel.querySelectorAll('[data-recent-row]')).toHaveLength(8));
    const first = panel.querySelector('[data-recent-row]') as HTMLAnchorElement;
    const href = first.getAttribute('href') ?? '';
    expect(href).toMatch(/^\/incidents\/\d+\/rank\/\d+\?from=/);
    const from = new URLSearchParams(new URLSearchParams(href.split('?')[1]).get('from') ?? '');
    expect(Object.fromEntries(from)).toEqual({ period: '24h', source: 'live', sort: 'detected', dir: 'desc' });
    // 짧은 수집원 이름이 보이고 전체 이름은 판독기 글자에 있다
    expect(first).toHaveTextContent('실습 11-20');
    expect(first).toHaveTextContent('수집원: 실습망 2026-11-20 · 캡처 ID: lab-20261120');
    expect(within(panel).getByRole('link', { name: '모두 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=24h&source=live&sort=detected&dir=desc',
    );
  });

  it('수집원 상태: 센서 행(상태·마지막 채점·마지막 이상 활동·수)과 수집 중 캡처, 지난 날짜 접기, 가져온 데이터(실패 먼저), 행 링크', async () => {
    renderAt('/');
    const panel = await screen.findByRole('region', { name: '수집원 상태' });
    const sensor = await within(panel).findByRole('link', { name: '실습망 센서 인시던트 목록' });
    expect(sensor).toHaveAttribute('href', '/incidents?period=24h&source=live');
    expect(within(sensor).getByText('정상')).toBeInTheDocument();
    expect(sensor).toHaveTextContent('인시던트 5 · High 2');
    const li = sensor.closest('li') as HTMLElement;
    expect(within(li).getByText('5분 전')).toHaveAttribute('title', expect.stringContaining('마지막 채점'));
    expect(within(li).getByText('12분 전')).toHaveAttribute('title', expect.stringContaining('마지막 이상 활동'));
    expect(within(li).getByText('실습 11-20').closest('a')).toHaveAttribute('href', '/incidents?period=24h&captureId=lab-20261120');
    const ended = li.querySelector('details[data-ended-captures]') as HTMLElement;
    expect(ended).not.toHaveAttribute('open');
    expect(within(ended).getByText('지난 날짜 1개')).toBeInTheDocument();
    expect(within(ended).getByText('실습 11-19')).toBeInTheDocument();

    const imported = within(panel).getByRole('list', { name: '가져온 데이터' });
    const rows = within(imported).getAllByRole('link');
    expect(rows.map((r) => r.getAttribute('data-capture'))).toEqual(['syn1-thu', 'cic17-wed']);
    expect(within(rows[0]).getByText('실패')).toBeInTheDocument();
    expect(within(rows[0]).getByText('CIC+APT 목')).toBeInTheDocument();
    expect(rows[0]).toHaveAttribute('href', '/incidents?period=24h&captureId=syn1-thu');
    expect(rows[0].getAttribute('title')).toContain('오류: 근거 API 시간 초과');
    expect(within(rows[1]).getByText('가져온 데이터')).toBeInTheDocument();
  });

  it('수집원 상태: 오늘 캡처가 실패하면(state=failed) 지난 날짜에 접지 않고 실패 표시와 함께 펼쳐 둔다(T24)', async () => {
    const sensors = [{ ...SENSOR, health: 'failed' as const, latestJob: jobRef(61, 'lab-20261120', 'failed', 3, '수집 중단') }];
    const captures = CAPTURES.map((c) => (c.captureId === 'lab-20261120' ? { ...c, state: 'failed' as const } : c));
    renderAt('/', { overview: (url) => json(fakeOverview(url, { sensors, captures })) });
    const panel = await screen.findByRole('region', { name: '수집원 상태' });
    const sensor = await within(panel).findByRole('link', { name: '실습망 센서 인시던트 목록' });
    const li = sensor.closest('li') as HTMLElement;
    const ended = li.querySelector('details[data-ended-captures]') as HTMLElement;
    expect(within(ended).getByText('지난 날짜 1개')).toBeInTheDocument();
    expect(within(ended).queryByText('실습 11-20')).toBeNull();
    const chip = li.querySelector('a[data-capture-chip="failed"]') as HTMLElement;
    expect(chip).not.toBeNull();
    expect(chip.closest('details')).toBeNull();
    expect(chip).toHaveTextContent('실습 11-20');
    expect(chip).toHaveTextContent('실패');
    expect(chip).toHaveAttribute('href', '/incidents?period=24h&captureId=lab-20261120');
  });

  it('수집원 상태 배지 문구 여섯 가지(정상·지연·중단·실패·기록 없음·가져온 데이터)와 뜻 툴팁', async () => {
    const healths = ['ok', 'stale', 'down', 'failed', 'none'] as const;
    const sensors = healths.map((h, i) => ({ ...SENSOR, sensorKey: `s${i}-*`, label: `센서 s${i}-*`, health: h }));
    renderAt('/', { overview: (url) => json(fakeOverview(url, { sensors })) });
    const panel = await screen.findByRole('region', { name: '수집원 상태' });
    await within(panel).findByText('지연');
    for (const label of ['정상', '지연', '중단', '실패', '기록 없음', '가져온 데이터']) {
      expect(within(panel).getAllByText(label).length, label).toBeGreaterThan(0);
    }
    expect(within(panel).getByText('지연').closest('[title]')).toHaveAttribute('title', expect.stringContaining('15분을 넘었고 1시간 안'));
    expect(within(panel).getByText('중단').closest('[title]')).toHaveAttribute('title', expect.stringContaining('1시간을 넘었습니다'));
  });

  it('경보 발송 상태(작게): 발송 방식 Dry-run, 최근 일일 요약 시각, 기간 안 일일 요약 수', async () => {
    renderAt('/');
    const panel = await screen.findByRole('region', { name: '경보 발송 상태' });
    expect(await within(panel).findByText('Dry-run')).toBeInTheDocument();
    expect(panel).toHaveTextContent('2026-11-21 00:40:00');
    expect(panel).toHaveTextContent('최근 24시간 일일 요약1건');
  });

  it('없어진 것: 캡처별 현황·탐지 모델 상태·파이프라인 패널, 판정 완료 KPI, 데이터 기준 띠. 운영 현황 링크가 있다', async () => {
    renderAt('/');
    await kpiRegion();
    for (const name of ['캡처별 현황', '탐지 모델 상태', '파이프라인', '기준 시각', '경보']) {
      expect(screen.queryByRole('region', { name }), name).not.toBeInTheDocument();
    }
    expect(screen.queryByText('판정 완료')).not.toBeInTheDocument();
    expect(screen.queryByText(/데이터 기준/)).not.toBeInTheDocument();
    expect(screen.queryByText('전체 인시던트')).not.toBeInTheDocument();
    expect(screen.queryByTestId('data-as-of')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /누적 판정·탐지 모델 성능은 운영 현황/ })).toHaveAttribute('href', '/operations?period=24h');
  });

  it('T26 휴대폰 폭: 현황판의 모든 표(화면 판독기 전용 표 제외)는 가로 스크롤 상자 안에 있다', async () => {
    renderAt('/');
    const trend = await screen.findByRole('region', { name: '탐지 추이' });
    await waitFor(() => expect(trend.querySelectorAll('[data-bucket]').length).toBeGreaterThan(0));
    // 현황판의 표는 화면 판독기 전용 추이 표 하나뿐이다(패널은 목록으로 그린다)
    const tables = Array.from(document.querySelectorAll('table'));
    expect(tables.every((t) => t.closest('.sr-only'))).toBe(true);
    expect(tablesOutsideScrollBox()).toEqual([]);
  });

  it('overview·큐 API가 실패하면 오류와 다시 시도를 보이고, 에스컬레이션(전체 기간 큐)만 실패하면 그 KPI만 비운다', async () => {
    const first = renderAt('/', { overview: () => json({ message: '서버 오류' }, 500) });
    expect(await screen.findByRole('button', { name: /다시 시도/ })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: '핵심 지표' })).not.toBeInTheDocument();
    first.unmount();

    renderAt('/', {
      queue: (url) =>
        paramsOf(url).period === 'all' && !paramsOf(url).sort
          ? json({ message: '서버 오류' }, 500)
          : json(fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter })),
    });
    const kpi = await screen.findByRole('region', { name: '핵심 지표' });
    const pending = within(kpi).getByRole('link', { name: /에스컬레이션 대기/ });
    await waitFor(() => expect(pending).toHaveTextContent('불러오지 못했습니다'));
    expect(kpiValue(within(kpi).getByRole('link', { name: /탐지된 인시던트/ }))).toBe(5);
  });

  it('허용 밖 캡처(403)면 서버 문구를 보인다', async () => {
    renderAt('/?captureId=lab-20261201', {
      overview: () => json({ status: 403, code: 'ACCESS_DENIED', message: '접근 권한이 없는 캡처입니다.' }, 403),
    });
    expect(await screen.findByText(/접근 권한이 없는 캡처입니다/)).toBeInTheDocument();
  });
});

describe('운영 현황(T24 기간·수집원 조건)', () => {
  it('조건 줄: 기본 7일로 운영 현황·overview를 부르고, 기간·수집원을 바꾸면 URL과 요청이 바뀐다', async () => {
    const user = userEvent.setup();
    const { calls } = renderAt('/operations');
    await screen.findByRole('region', { name: '상태 요약' });
    expect(calls).toEqual(expect.arrayContaining(['/api/operations?period=7d', '/api/dashboard/overview?period=7d']));
    const bar = screen.getByRole('region', { name: '보기 조건' });
    expect(within(bar).getByRole('button', { name: '7일' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(within(bar).getByRole('button', { name: '1시간' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/operations?period=1h');
    await waitFor(() => expect(calls).toContain('/api/operations?period=1h'));
    await user.selectOptions(within(bar).getByLabelText('수집원'), 'src:live');
    await waitFor(() => expect(calls).toContain('/api/operations?period=1h&source=live'));
  });

  it('옛 captureId 링크는 수집원 선택 안의 캡처로 읽는다', async () => {
    const { calls } = renderAt('/operations?captureId=syn1-thu');
    await screen.findByRole('region', { name: '상태 요약' });
    expect(calls).toEqual(expect.arrayContaining(['/api/operations?period=7d&captureId=syn1-thu', '/api/dashboard/overview?period=7d&captureId=syn1-thu']));
    expect(screen.getByLabelText('수집원')).toHaveValue('cap:syn1-thu');
  });

  it('상태 카드 3개(수집원·모델 판정·경보)와 합계 문장', async () => {
    renderAt('/operations');
    const cards = await screen.findByRole('region', { name: '상태 요약' });
    const sourceCard = within(cards).getByRole('region', { name: '수집원 상태' });
    await waitFor(() => expect(sourceCard).toHaveTextContent('실습망 센서정상'));
    expect(sourceCard).toHaveTextContent('가져온 데이터 실패 1개 / 2개 캡처');
    // 판정 19/100, 정탐 14 → 73.7%
    expect(within(cards).getByRole('region', { name: '모델 판정 상태' })).toHaveTextContent('정탐률 73.7% · 판정 19/100건(19.0%)');
    const alert = within(cards).getByRole('region', { name: '경보 상태' });
    expect(alert).toHaveTextContent('경보 발송 12건');
    expect(alert).toHaveTextContent('표본 부족 · 경보 판정 4/12건(33.3%)');
    expect(alert).toHaveTextContent('2026-11-21 00:40:00');
  });

  it('판정 집계는 "누적(기간 없음)"이고 기간을 바꿔도 값이 같다. 탐지 작업·Slack 요약은 기간 안만', async () => {
    const user = userEvent.setup();
    renderAt('/operations?period=all');
    const table = (await screen.findAllByText('모든 모델 합계'))[0].closest('table') as HTMLElement;
    const section = table.closest('section') as HTMLElement;
    expect(within(section).getByTestId('cumulative-note')).toHaveTextContent('누적(기간 없음)');
    const before = table.textContent;
    expect(screen.getByText(/^탐지 작업 기록/, { selector: 'summary' })).toHaveTextContent('전체 기간 3건');
    expect(screen.getByText(/^Slack 일일 요약/, { selector: 'summary' })).toHaveTextContent('전체 기간 1건');

    await user.click(screen.getByRole('button', { name: '1시간' }));
    await waitFor(() => expect(screen.getByText(/^탐지 작업 기록/, { selector: 'summary' })).toHaveTextContent('최근 1시간 0건'));
    expect(screen.getByText(/^Slack 일일 요약/, { selector: 'summary' })).toHaveTextContent('최근 1시간 0건');
    const after = (await screen.findAllByText('모든 모델 합계'))[0].closest('table') as HTMLElement;
    expect(after.textContent).toBe(before);
  });

  it('작업 기록이 잘렸으면 "최근 500건만 보임(전체 N건)"을 적는다', async () => {
    renderAt('/operations?period=all', {
      operations: (url) => {
        const ops = fakeOperations(url, { truncated: true });
        return json({ ...ops, jobs: Array.from({ length: 500 }, (_, i) => ({ ...ALL_JOBS[2], jobId: 1000 + i })) });
      },
    });
    expect(await screen.findByTestId('jobs-truncated')).toHaveTextContent('최근 500건만 보임(전체 1,234건)');
  });

  it('수집원 상태 표: 센서 행·캡처 행(지난 날짜 포함)의 값, 짧은 이름(전체 이름은 판독기 글자), 오류 글', async () => {
    renderAt('/operations');
    const section = await screen.findByRole('region', { name: '수집원 상태 표' });
    const table = await within(section).findByRole('table');
    const sensorRow = table.querySelector('[data-sensor-row="lab-*"]') as HTMLElement;
    expect(within(sensorRow).getByText('정상')).toBeInTheDocument();
    // T27: '#'은 인시던트 번호에만 쓴다. "최근 끝난 작업" 칸은 숫자만(판독기 이름 "작업 60")
    expect(sensorRow).not.toHaveTextContent('#60');
    expect(within(sensorRow).getByLabelText('작업 60')).toHaveTextContent('60');
    const rows = Array.from(table.querySelectorAll('[data-capture-row]')).map((r) => r.getAttribute('data-capture-row'));
    expect(rows).toEqual(['lab-20261120', 'lab-20261119', 'syn1-thu', 'cic17-wed']);
    const ended = table.querySelector('[data-capture-row="lab-20261119"]') as HTMLElement;
    expect(within(ended).getByText('지난 날짜')).toBeInTheDocument();
    expect(ended).toHaveTextContent('실습 11-19');
    expect(ended).toHaveTextContent('실습망 2026-11-19 · Kali 공격 + 정상 배경 · 캡처 ID: lab-20261119');
    const failed = table.querySelector('[data-capture-row="syn1-thu"]') as HTMLElement;
    expect(failed).toHaveTextContent('근거 API 시간 초과 10.0.0.*');
  });

  it('T26 휴대폰 폭: 운영 현황의 모든 표(접힌 영역 포함)는 가로 스크롤 상자 안에 있다', async () => {
    renderAt('/operations');
    await screen.findAllByText('모든 모델 합계');
    await screen.findByRole('region', { name: '수집원 상태 표' });
    expectAllTablesInScrollBox();
  });

  it('판정 집계는 모든 모델 합계 행만 기본 표시하고, 펼치면 탐지 모델별 행과 판정 없음 한 줄이 보인다', async () => {
    const user = userEvent.setup();
    renderAt('/operations');
    const table = (await screen.findAllByText('모든 모델 합계'))[0].closest('table') as HTMLElement;
    expect(within(table).getAllByText('모든 모델 합계')).toHaveLength(2);
    expect(within(table).queryByText('통신 관계 이상')).not.toBeInTheDocument();
    expect(within(table).getByText('표본 부족 · 판정 9/79건(11.4%)')).toHaveAttribute('title', expect.stringContaining('정탐률 88.9%'));
    expect(within(table).getByText('정탐률 60.0% · 판정 10/21건(47.6%)')).toBeInTheDocument();
    expect(within(table).getByRole('img', { name: '정탐률' })).toBeInTheDocument();

    await user.click(within(table).getByRole('button', { name: /탐지 모델별 2개 펼치기/ }));
    expect(within(table).getByText('통신 관계 이상')).toBeInTheDocument();
    const quiet = within(table).getByText('행위 패턴 이탈').closest('tr') as HTMLElement;
    expect(within(quiet).getByText('판정 없음')).toHaveAttribute('colspan', '3');
    expect(within(table).queryByText('기준선 이탈')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '탐지 모델별 행 모두 펼치기' }));
    expect(within(table).getByText('기준선 이탈')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '탐지 모델별 행 모두 접기' }));
    expect(within(table).queryByText('통신 관계 이상')).not.toBeInTheDocument();
  });

  it('탐지 작업·모델 버전·Slack 일일 요약은 접힌 영역이고 수집원 선택은 표시 이름', async () => {
    renderAt('/operations');
    await screen.findByRole('region', { name: '상태 요약' });
    for (const title of ['탐지 작업 기록', '모델 버전', 'Slack 일일 요약']) {
      const summary = screen.getByText(new RegExp(`^${title}`), { selector: 'summary' });
      expect(summary.closest('details')).not.toHaveAttribute('open');
    }
    const select = screen.getByLabelText('수집원');
    expect(within(select).getByRole('option', { name: 'CIC-IDS2017 수요일' })).toHaveAttribute('value', 'cap:cic17-wed');
    expect(within(select).getByRole('option', { name: 'CIC 목요일 + 합성 APT' })).toHaveAttribute(
      'title',
      expect.stringContaining('캡처 ID: syn1-thu'),
    );
  });
});

describe('T25 운영 현황: 처리 시간·담당 현황', () => {
  const stat = (n: number, median: number | null, p90: number | null, excluded = 0) => ({
    n,
    medianSeconds: median,
    p90Seconds: p90,
    excluded,
    smallSample: n > 0 && n < 10,
  });
  const handlingTimes = {
    detection: stat(12, 3600, 7500, 1),
    acknowledge: stat(3, 600, 1800, 2),
    resolve: {
      all: stat(0, null, null),
      byResolution: [
        { resolution: 'true_positive', stat: stat(0, null, null) },
        { resolution: 'false_positive', stat: stat(0, null, null) },
        { resolution: 'benign', stat: stat(0, null, null) },
        { resolution: 'none', stat: stat(0, null, null) },
      ],
    },
  };
  const workload = {
    unclosed: 5,
    assigned: 3,
    unassigned: 2,
    ackOverdue: 1,
    byAssignee: [
      { username: 'analyst2', displayName: '김분석', enabled: true, open: 1, investigating: 1 },
      { username: 'old1', displayName: '퇴사자', enabled: false, open: 1, investigating: 0 },
    ],
  };
  const withBlocks = (extra: Record<string, unknown>) => (url: string) =>
    json({ ...fakeOperations(url), ...extra });

  it('처리 시간: 지표 셋과 판정별 하위 행, 건수·중앙값·p90·제외·표본 부족, 0건은 "-"', async () => {
    renderAt('/operations', { operations: withBlocks({ handlingTimes, workload }) });
    const panel = await screen.findByRole('region', { name: '처리 시간' });
    const det = panel.querySelector('[data-metric="detection"]') as HTMLElement;
    expect(det).toHaveTextContent('탐지 지연(MTTD)');
    expect(det).toHaveTextContent('실습망만');
    expect(det).toHaveTextContent('1시간');
    expect(det).toHaveTextContent('2시간 5분');
    expect(within(det).queryByText('표본 부족')).toBeNull();
    const ack = panel.querySelector('[data-metric="acknowledge"]') as HTMLElement;
    expect(within(ack).getByText('10분')).toBeInTheDocument();
    expect(within(ack).getByText('30분')).toBeInTheDocument();
    expect(within(ack).getByText('표본 부족')).toBeInTheDocument();
    expect(within(ack).getAllByRole('cell')[3]).toHaveTextContent('2');
    const res = panel.querySelector('[data-metric="resolve"]') as HTMLElement;
    expect(within(res).getAllByText('-')).toHaveLength(2);
    expect(Array.from(panel.querySelectorAll('[data-resolution]')).map((r) => r.querySelector('th')?.textContent)).toEqual([
      '정탐',
      '오탐',
      '정상',
      '판정 없음',
    ]);
    expect(panel).toHaveTextContent('최근 7일');
    expectAllTablesInScrollBox();
  });

  it('담당 현황: 미종결·배정·미배정·착수 지연(큐 링크), 담당자별 표(비활성 표지)', async () => {
    renderAt('/operations?source=live', { operations: withBlocks({ handlingTimes, workload }) });
    const panel = await screen.findByRole('region', { name: '담당 현황' });
    expect(panel).toHaveTextContent('미종결5');
    expect(panel).toHaveTextContent('배정3');
    expect(panel).toHaveTextContent('미배정2');
    const link = within(panel).getByRole('link', { name: '착수 지연 1건 인시던트 큐에서 보기' });
    expect(Object.fromEntries(new URLSearchParams((link.getAttribute('href') ?? '').split('?')[1]))).toEqual({
      period: 'all',
      overdue: 'true',
      source: 'live',
    });
    const table = within(panel).getByRole('table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('김분석');
    expect(rows[0]).toHaveTextContent('2');
    expect(within(rows[1]).getByText('비활성')).toBeInTheDocument();
    expectAllTablesInScrollBox();
  });

  it('담당이 없으면 "담당 중인 인시던트 없음", period 없는 응답(handlingTimes 없음)이면 처리 시간 패널이 없다', async () => {
    renderAt('/operations', {
      operations: withBlocks({ workload: { unclosed: 4, assigned: 0, unassigned: 4, ackOverdue: 0, byAssignee: [] } }),
    });
    const panel = await screen.findByRole('region', { name: '담당 현황' });
    expect(within(panel).getByText('담당 중인 인시던트 없음')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: '처리 시간' })).toBeNull();
  });
});

describe('T25 현황판·운영 현황 후속(T24 뒤에 정한 것)', () => {
  it('T27 최근 인시던트 링크는 번호가 있으면 번호 주소(from= 유지), 없으면 옛 주소다', async () => {
    const numbered = ITEMS.map((it, i) => ({ ...it, incidentNo: i % 2 === 0 ? 900 + i : null }));
    renderAt('/', { queue: (url) => json(fakeQueue(url, { items: numbered, anchor: ANCHOR, periodFilter })) });
    const panel = await screen.findByRole('region', { name: '최근 인시던트' });
    await waitFor(() => expect(panel.querySelectorAll('[data-recent-row]').length).toBeGreaterThan(1));
    const hrefs = Array.from(panel.querySelectorAll('[data-recent-row]')).map((a) => a.getAttribute('href') ?? '');
    expect(hrefs.some((h) => /^\/incidents\/9\d\d\?from=/.test(h))).toBe(true);
    expect(hrefs.some((h) => /^\/incidents\/\d+\/rank\/\d+\?from=/.test(h))).toBe(true);
    expect(hrefs.every((h) => /^\/incidents\/(9\d\d|\d+\/rank\/\d+)\?from=/.test(h))).toBe(true);
  });

  it('최근 인시던트 행의 탐지 모델 이름은 640px 미만에서도 보인다(숨김 클래스 없음)', async () => {
    renderAt('/');
    const panel = await screen.findByRole('region', { name: '최근 인시던트' });
    await waitFor(() => expect(panel.querySelectorAll('[data-recent-row]').length).toBeGreaterThan(0));
    for (const row of Array.from(panel.querySelectorAll('[data-recent-row]'))) {
      expect(row.querySelector('.hidden')).toBeNull();
    }
  });

  it('경보 발송 상태의 최근 일일 요약은 짧은 수집원 이름이고, 전체 이름은 툴팁·판독기 글자다', async () => {
    renderAt('/');
    const panel = await screen.findByRole('region', { name: '경보 발송 상태' });
    const cap = await waitFor(() => panel.querySelector('[data-alerting-capture]') as HTMLElement);
    expect(cap).toHaveTextContent('실습 11-20');
    expect(cap.querySelector('[aria-hidden="true"]')).toHaveTextContent(/^실습 11-20$/);
    expect(cap).toHaveAttribute('title', '실습망 2026-11-20 · 캡처 ID: lab-20261120');
    expect(within(cap).getByText('수집원: 실습망 2026-11-20 · 캡처 ID: lab-20261120')).toHaveClass('sr-only');
  });

  it('수집원 상태 표의 오류 칸은 한 줄 말줄임이고 전체 글은 툴팁이다(VIEWER면 서버가 가린 글)', async () => {
    renderAt('/operations');
    const section = await screen.findByRole('region', { name: '수집원 상태 표' });
    const table = await within(section).findByRole('table');
    const cell = (table.querySelector('[data-capture-row="syn1-thu"]') as HTMLElement).querySelector('[data-error-cell]') as HTMLElement;
    expect(cell).toHaveAttribute('title', '근거 API 시간 초과 10.0.0.*');
    expect(cell.querySelector('span')).toHaveClass('block', 'truncate');
    expect(cell).not.toHaveClass('break-all');
  });
});

describe('현황판 기간 밖 안내(T29)', () => {
  it('기간 밖에 더 있으면 핵심 지표 위에 "선택한 기간 밖 인시던트 N건 · 전체 기간 보기", 누르면 기간 전체', async () => {
    const user = userEvent.setup();
    renderAt('/?period=1h');
    const notice = await screen.findByTestId('outside-period');
    const inPeriod = fakeQueue('/api/incidents/queue?period=1h', { items: ITEMS, anchor: ANCHOR, periodFilter });
    expect(inPeriod.total).toBeGreaterThan(0);
    expect(notice).toHaveTextContent(`선택한 기간 밖 인시던트 ${ITEMS.length - inPeriod.total}건`);
    // 핵심 지표 앞에 있다
    const kpi = screen.getByRole('region', { name: '핵심 지표' });
    expect(notice.compareDocumentPosition(kpi) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await user.click(within(notice).getByRole('button', { name: '전체 기간 보기' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/?period=all');
    await waitFor(() => expect(screen.queryByTestId('outside-period')).toBeNull());
  });

  it('0건이면 한 줄 안내 없이 탐지 추이 빈 안내가 기간 밖 수와 함께 보인다', async () => {
    const all = (url: string) =>
      fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter: (_i, p) => p === 'all', newestOutsidePeriod: '2026-11-12T03:00:00Z' });
    renderAt('/?period=1h', {
      queue: (url) => json(all(url)),
      overview: (url) => json({ ...fakeOverview(url), trend: { bucket: '5m', buckets: buckets('1h', 0), unbucketed: { noDetectedAt: 0, afterAnchor: 0 } } }),
    });
    const trend = await screen.findByRole('region', { name: '탐지 추이' });
    expect(await within(trend).findByText(/이 기간에 탐지된 인시던트가 없습니다/)).toHaveTextContent(
      `선택한 기간 밖 인시던트 ${ITEMS.length}건 · 가장 최근 탐지: 2026-11-12 12:00:00`,
    );
    expect(screen.queryByTestId('outside-period')).toBeNull();
    expect(screen.queryByRole('button', { name: '전체 기간 보기' })).toBeNull();
  });

  it('수집원 목록에 마지막 탐지가 붙는다(큐 sources)', async () => {
    renderAt('/', {
      snapshot: true,
      queue: (url) =>
        json(fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter, snapshot: true, lastDetected: { 'cic17-wed': '2026-11-12T03:00:00Z' } })),
    });
    await screen.findByRole('region', { name: '핵심 지표' });
    const select = screen.getByLabelText('수집원') as HTMLSelectElement;
    expect(select.querySelector('option[value="cap:cic17-wed"]')?.textContent).toBe(
      'CIC-IDS2017 수요일 · 마지막 탐지 11-12 12:00(기준 시각 8일 전)',
    );
  });
});

/* ───────────────────────── T41 갱신 실패 ───────────────────────── */

/** WAF(nginx limit_req)의 429는 본문이 JSON이 아니다 */
const wafRateLimited = () =>
  new Response('<html><body>429 Too Many Requests</body></html>', { status: 429, headers: { 'Content-Type': 'text/html' } });

type Mode = 'ok' | '429' | '500' | '503' | 'network' | '401' | '403' | '404';

function failWith(mode: Mode): Response {
  if (mode === '429') return wafRateLimited();
  if (mode === 'network') throw new TypeError('Failed to fetch');
  const status = Number(mode);
  return json({ status, code: status === 401 ? 'SESSION_EXPIRED' : `E${status}`, message: `서버 문구 ${status}` }, status);
}

/** overview·큐 응답을 시험 안에서 바꾼다. 셋째 요청(전체 기간 큐)은 따로 다룬다 */
function switchable(opts: { snapshot?: boolean } = {}) {
  const state = { overview: 'ok' as Mode, queue: 'ok' as Mode, overviewBody: null as ((url: string) => DashboardOverviewResponse) | null };
  const options: RenderOptions = {
    snapshot: opts.snapshot,
    overview: (url) =>
      state.overview === 'ok' ? json((state.overviewBody ?? ((u: string) => fakeOverview(u, { snapshot: opts.snapshot })))(url)) : failWith(state.overview),
    queue: (url) =>
      state.queue === 'ok'
        ? json(fakeQueue(url, { items: ITEMS, anchor: ANCHOR, periodFilter, snapshot: opts.snapshot, newestOutsidePeriod: minutesAgo(10) }))
        : failWith(state.queue),
  };
  const set = (m: Mode) => {
    state.overview = m;
    state.queue = m;
  };
  return { state, options, set };
}

const overviewCount = (calls: string[]) => calls.filter((c) => c.startsWith('/api/dashboard/overview')).length;
const loadedAtText = () => {
  const bar = screen.getByRole('region', { name: '보기 조건' });
  return within(bar).getByText('불러온 시각').textContent;
};

async function tick(ms: number) {
  await act(async () => {
    vi.advanceTimersByTime(ms);
  });
}

describe('T41 현황판 갱신 실패: 값 남기기와 자동 갱신 잇기', () => {
  it('성공 → 429(값 남음, 표시, 불러온 시각 그대로) → 60초 뒤 자동으로 다시 부름 → 성공(표시 사라짐)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const sw = switchable();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const { calls } = renderAt('/', sw.options);
    const kpi = await kpiRegion();
    const before = loadedAtText();
    expect(overviewCount(calls)).toBe(1);

    sw.set('429');
    await tick(1000);
    await user.click(screen.getByRole('button', { name: '새로 고침' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('최신 값이 아닙니다');
    expect(notice).toHaveTextContent('요청이 많아 잠시 제한됐습니다. 잠시 뒤 다시 시도하세요.');
    expect(notice).toHaveTextContent('마지막 성공');
    expect(within(notice).getByTestId('stale-auto-retry')).toHaveTextContent('60초마다 다시 시도합니다');
    expect(within(notice).getByRole('button', { name: '다시 시도' })).toBeInTheDocument();
    // 값은 남고(배너 없이) 불러온 시각은 마지막 성공 시각 그대로
    expect(screen.queryByRole('alert')).toBeNull();
    expect(kpi).toBeInTheDocument();
    expect(kpiValue(within(screen.getByRole('region', { name: '핵심 지표' })).getByRole('link', { name: /탐지된 인시던트/ }))).toBe(5);
    expect(loadedAtText()).toBe(before);
    expect(overviewCount(calls)).toBe(2);

    // 실패 직후 연달아 부르지 않는다
    await tick(DASHBOARD_REFRESH_MS / 2);
    expect(overviewCount(calls)).toBe(2);

    sw.set('ok');
    await tick(DASHBOARD_REFRESH_MS);
    await waitFor(() => expect(overviewCount(calls)).toBe(3));
    await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
    expect(loadedAtText()).not.toBe(before);
  });

  it('overview만 성공하고 큐가 실패하면 둘 다 옛 값 그대로다(새 overview와 옛 큐가 섞이지 않는다)', async () => {
    const sw = switchable();
    const user = userEvent.setup();
    renderAt('/', sw.options);
    await kpiRegion();
    const trend = screen.getByRole('region', { name: '탐지 추이' });
    await waitFor(() => expect(trend.querySelectorAll('[data-bucket]')).toHaveLength(24));

    // 다음 overview는 구간 3개로 다르게, 큐는 실패
    sw.state.overviewBody = (u) => {
      const o = fakeOverview(u);
      return { ...o, trend: { ...o.trend, buckets: o.trend.buckets.slice(0, 3) } };
    };
    sw.state.queue = '500';
    await user.click(screen.getByRole('button', { name: '새로 고침' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(notice).toHaveTextContent('서버 문구 500');
    expect(screen.getByRole('region', { name: '탐지 추이' }).querySelectorAll('[data-bucket]')).toHaveLength(24);

    // 반대로 큐만 성공하고 overview가 실패해도 그대로
    sw.state.overviewBody = null;
    sw.state.queue = 'ok';
    sw.state.overview = '503';
    await user.click(screen.getByRole('button', { name: '새로 고침' }));
    await waitFor(() => expect(screen.getByTestId('stale-notice')).toHaveTextContent('서버 문구 503'));
    expect(screen.getByRole('region', { name: '탐지 추이' }).querySelectorAll('[data-bucket]')).toHaveLength(24);
  });

  it('조건을 바꾼 뒤 실패하면 이전 값이 보이지 않고 오류 배너가 보인다', async () => {
    const sw = switchable();
    const user = userEvent.setup();
    renderAt('/', sw.options);
    await kpiRegion();
    sw.set('429');
    const bar = screen.getByRole('region', { name: '보기 조건' });
    await user.click(within(bar).getByRole('button', { name: '7일' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(alert).not.toHaveTextContent('관리자에게');
    expect(screen.queryByRole('region', { name: '핵심 지표' })).toBeNull();
    expect(screen.queryByRole('region', { name: '탐지 추이' })).toBeNull();
    expect(screen.queryByTestId('stale-notice')).toBeNull();
    // 다른 조건으로 성공한 시각을 지금 조건의 "불러온 시각"으로 보이지 않는다
    expect(loadedAtText()).not.toMatch(/\d{4}-\d{2}-\d{2}/);

    // 다시 시도로 돌아온다
    sw.set('ok');
    await user.click(within(alert).getByRole('button', { name: '다시 시도' }));
    await kpiRegion();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('처음 불러오기가 429·5xx·네트워크로 실패해도 60초마다 다시 부른다', async () => {
    for (const mode of ['429', '500', 'network'] as Mode[]) {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      setVisibility('visible');
      const sw = switchable();
      sw.set(mode);
      const view = renderAt('/', sw.options);
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(overviewCount(view.calls)).toBe(1);
      await tick(DASHBOARD_REFRESH_MS / 2);
      expect(overviewCount(view.calls), mode).toBe(1);
      await tick(DASHBOARD_REFRESH_MS / 2);
      await waitFor(() => expect(overviewCount(view.calls), mode).toBe(2));
      sw.set('ok');
      await tick(DASHBOARD_REFRESH_MS);
      await waitFor(() => expect(overviewCount(view.calls), mode).toBe(3));
      await kpiRegion();
      expect(screen.queryByRole('alert')).toBeNull();
      view.unmount();
      vi.useRealTimers();
    }
  });

  it('401·403(과 그 밖의 4xx) 실패 뒤에는 60초가 지나도 부르지 않는다. 표시에 "다시 시도합니다" 말이 없다', async () => {
    for (const mode of ['403', '404', '401'] as Mode[]) {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      setVisibility('visible');
      const sw = switchable();
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      const view = renderAt('/', sw.options);
      await kpiRegion();
      sw.set(mode);
      await user.click(screen.getByRole('button', { name: '새로 고침' }));
      await waitFor(() => expect(overviewCount(view.calls)).toBe(2));
      if (mode !== '401') {
        const notice = await screen.findByTestId('stale-notice');
        expect(within(notice).queryByTestId('stale-auto-retry')).toBeNull();
      }
      await tick(DASHBOARD_REFRESH_MS * 3);
      expect(overviewCount(view.calls), mode).toBe(2);
      if (mode !== '401') {
        // 사람이 다시 시도해 성공하면 다시 켜진다
        sw.set('ok');
        await user.click(within(screen.getByTestId('stale-notice')).getByRole('button', { name: '다시 시도' }));
        await waitFor(() => expect(screen.queryByTestId('stale-notice')).toBeNull());
        expect(overviewCount(view.calls)).toBe(3);
        await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
        await tick(DASHBOARD_REFRESH_MS);
        await waitFor(() => expect(overviewCount(view.calls), mode).toBe(4));
      }
      view.unmount();
      vi.useRealTimers();
    }
  });

  it('고정 스냅샷이면 조건을 바꾼 뒤 실패해 값이 비어도 자동 갱신이 없다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const sw = switchable({ snapshot: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const { calls } = renderAt('/', sw.options);
    await kpiRegion();
    sw.set('429');
    await user.click(within(screen.getByRole('region', { name: '보기 조건' })).getByRole('button', { name: '7일' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(screen.queryByRole('region', { name: '핵심 지표' })).toBeNull();
    const n = overviewCount(calls);
    await tick(DASHBOARD_REFRESH_MS * 3);
    expect(overviewCount(calls)).toBe(n);
  });

  it('고정 스냅샷에서 같은 조건 실패: 값이 남고 표시에 "다시 시도합니다" 말이 없다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const sw = switchable({ snapshot: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const { calls } = renderAt('/', sw.options);
    await kpiRegion();
    sw.set('429');
    await user.click(screen.getByRole('button', { name: '새로 고침' }));
    const notice = await screen.findByTestId('stale-notice');
    expect(within(notice).queryByTestId('stale-auto-retry')).toBeNull();
    expect(screen.getByRole('region', { name: '핵심 지표' })).toBeInTheDocument();
    await tick(DASHBOARD_REFRESH_MS * 3);
    expect(overviewCount(calls)).toBe(2);
  });

  it('지정 기간에서는 실패해도 자동 갱신이 없다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const sw = switchable();
    sw.set('500');
    const { calls } = renderAt(`/?period=custom&start=${encodeURIComponent('2026-11-19T00:30:00Z')}&end=${encodeURIComponent('2026-11-19T03:00:00Z')}`, sw.options);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await tick(DASHBOARD_REFRESH_MS * 3);
    expect(overviewCount(calls)).toBe(1);
  });
});
