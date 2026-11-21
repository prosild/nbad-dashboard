import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

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
  allowedCapturePatterns: ['cic17-*', 'syn1-*'],
};

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
const operationsResponse = {
  maskedView: false,
  allowedCaptures: ['cic17-wed', 'syn1-thu'],
  selectedCaptureId: null,
  jobs: [
    { jobId: 9, captureId: 'syn1-thu', bundleId: 'zeekad-fusion/3', status: 'failed', startedAt: null, finishedAt: '2026-11-20T05:00:00Z', error: '근거 API 시간 초과', incidentCount: null },
    { jobId: 8, captureId: 'syn1-thu', bundleId: 'zeekad-fusion/3', status: 'succeeded', startedAt: null, finishedAt: '2026-11-19T15:30:00Z', error: null, incidentCount: 21 },
    { jobId: 2, captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', status: 'succeeded', startedAt: null, finishedAt: '2026-11-12T02:27:00Z', error: null, incidentCount: 79 },
  ],
  bundles: [],
  feedbackSummaries: [
    { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'all', allModel: true, incidents: 79, alerted: 9, resolved: 9, truePositive: 8, zeekadPrecision: 0.889, alertedResolved: 1, zeekadAlertPrecision: 1, zeekadAlertResolvedRate: 0.111 },
    { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'tgn_recon', allModel: false, incidents: 30, resolved: 9, truePositive: 8, zeekadPrecision: 0.889 },
    { ...baseRow, captureId: 'cic17-wed', zeekadPickedBy: 'transformer_v2', allModel: false, incidents: 49, alerted: 0, resolved: 0 },
    { ...baseRow, captureId: 'syn1-thu', zeekadPickedBy: 'all', allModel: true, incidents: 21, alerted: 3, resolved: 10, truePositive: 6, zeekadPrecision: 0.6, alertedResolved: 3, zeekadAlertPrecision: 0.667, zeekadAlertResolvedRate: 1 },
    { ...baseRow, captureId: 'syn1-thu', zeekadPickedBy: 'tail_rarity_v2', allModel: false, incidents: 21, resolved: 10, truePositive: 6, zeekadPrecision: 0.6 },
  ],
  slackSummaries: [
    { jobId: 8, captureId: 'syn1-thu', zeekadMessageVersion: 'daily-summary.v1', zeekadDeliveryMode: 'dry_run', zeekadDeliveryStatus: 'recorded', slackPayload: null, slackTs: null, deliveredAt: null, createdAt: '2026-11-19T15:40:00Z', dryRunOrRecorded: true, payloadTextPreview: '요약', payloadChannel: '#sec' },
    { jobId: 2, captureId: 'cic17-wed', zeekadMessageVersion: 'daily-summary.v1', zeekadDeliveryMode: 'dry_run', zeekadDeliveryStatus: 'recorded', slackPayload: null, slackTs: null, deliveredAt: null, createdAt: '2026-11-12T02:40:00Z', dryRunOrRecorded: true, payloadTextPreview: '요약', payloadChannel: '#sec' },
  ],
};

const reviewsResponse = {
  maskedView: false,
  canDecideReview: true,
  allowedCaptures: ['cic17-wed', 'syn1-thu'],
  selectedCaptureId: null,
  pendingOnly: true,
  reviews: [
    { jobId: 2, reviewJobId: 5, captureId: 'cic17-wed', incidentId: 'a|1', queueRank: 1, hostIp: '10.0.0.1', zeekadRole: 'responder', zeekadReviewReason: null, requestedAt: null, zeekadReviewAction: null, analyst: null, analystDisplay: null, decidedAt: null, zeekadReviewResumedAt: null, zeekadReviewResumeFailed: null, pending: true },
    { jobId: 8, reviewJobId: 6, captureId: 'syn1-thu', incidentId: 'b|1', queueRank: 1, hostIp: '10.0.0.2', zeekadRole: 'originator', zeekadReviewReason: null, requestedAt: null, zeekadReviewAction: null, analyst: null, analystDisplay: null, decidedAt: null, zeekadReviewResumedAt: null, zeekadReviewResumeFailed: null, pending: true },
  ],
};

/** T23 통합 큐 빈 응답 */
const emptyQueue = {
  items: [],
  total: 0,
  page: 1,
  size: 50,
  pageCount: 1,
  summary: { total: 0, high: 0, medium: 0, low: 0, reviewPending: 0, alerted: 0, byStatus: {} },
  anchor: '2026-11-21T00:00:00Z',
  anchorMode: 'now',
  snapshot: false,
  period: 'all',
  latestDetectedAt: null,
  newestOutsidePeriod: null,
  sources: [
    { captureId: 'cic17-wed', sourceType: 'imported', latestJobId: 1 },
    { captureId: 'syn1-thu', sourceType: 'imported', latestJobId: 2 },
  ],
  maskedView: false,
  availableModels: [],
  availableRoles: [],
};

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderAt(
  path: string,
  options: { operations?: () => Response; reviews?: () => Response } = {},
) {
  document.cookie = 'XSRF-TOKEN=dashboard-test-token; path=/';
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: analystUser });
    if (url.startsWith('/api/operations')) return options.operations ? options.operations() : json(operationsResponse);
    if (url.startsWith('/api/reviews')) return options.reviews ? options.reviews() : json(reviewsResponse);
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    if (url.startsWith('/api/incidents')) return json(emptyQueue);
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
  return { ...utils, fetchMock };
}

/** 화면이 부른 API(로그인 확인과 T23 기준 시각은 화면마다가 아니라 로그인한 사용자마다 한 번 부르므로 뺀다) */
const apiCalls = (fetchMock: ReturnType<typeof vi.fn>) =>
  fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => u !== '/api/auth/me' && u !== '/api/time-context');

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

describe('관제 현황판', () => {
  it('API 두 번(운영 현황·에스컬레이션 대기)으로 그리고 KPI는 캡처별 모든 모델 합계의 합이다', async () => {
    const { fetchMock } = renderAt('/');
    const kpi = await screen.findByRole('region', { name: '핵심 지표' });
    await waitFor(() => expect(within(kpi).getByRole('link', { name: /에스컬레이션 대기/ })).toHaveTextContent('2'));
    expect(apiCalls(fetchMock).sort()).toEqual(['/api/operations', '/api/reviews?pendingOnly=true']);

    expect(within(kpi).getByRole('link', { name: /전체 인시던트/ })).toHaveTextContent('100');
    expect(within(kpi).getByRole('link', { name: /경보 발송/ })).toHaveTextContent('12');
    const resolved = within(kpi).getByRole('link', { name: /판정 완료/ });
    expect(resolved).toHaveTextContent('19');
    expect(resolved).toHaveTextContent('미판정 81건');
  });

  it('기준 띠: 데이터 기준은 최근 성공 탐지 작업 완료 시각(KST), 실패 작업 수, 새로 고침', async () => {
    const { fetchMock } = renderAt('/');
    const strip = await screen.findByRole('region', { name: '기준 시각' });
    // 2026-11-19T15:30:00Z → KST 2026-11-20 00:30:00 (실패한 작업 9의 시각은 쓰지 않는다)
    await waitFor(() => expect(within(strip).getByTestId('data-as-of')).toHaveTextContent('2026-11-20 00:30:00'));
    expect(strip).toHaveTextContent('KST');
    expect(strip).toHaveTextContent('실패한 탐지 작업 1건');
    const before = apiCalls(fetchMock).length;
    await userEvent.setup().click(within(strip).getByRole('button', { name: '새로 고침' }));
    await waitFor(() => expect(apiCalls(fetchMock).length).toBe(before + 2));
  });

  it('탐지 모델 상태: 판정 9건은 표본 부족(값은 툴팁), 10건은 정탐률', async () => {
    renderAt('/');
    const panel = await screen.findByRole('region', { name: '탐지 모델 상태' });
    const rowOf = (name: string) => within(panel).getByText(name).closest('tr') as HTMLElement;
    await waitFor(() => expect(within(panel).getByText('통신 관계 이상')).toBeInTheDocument());
    const short = within(rowOf('통신 관계 이상')).getByText('표본 부족');
    expect(short).toHaveAttribute('title', expect.stringContaining('정탐률 88.9%(판정 9건)'));
    expect(within(rowOf('기준선 이탈')).getByText('60.0%')).toBeInTheDocument();
    expect(within(rowOf('행위 패턴 이탈')).getByText('판정 없음')).toBeInTheDocument();
    expect(within(panel).getByText('주 탐지 기준 인시던트 수')).toBeInTheDocument();
  });

  it('KPI와 캡처를 누르면 인시던트 목록·에스컬레이션으로 간다', async () => {
    const user = userEvent.setup();
    renderAt('/');
    const kpi = await screen.findByRole('region', { name: '핵심 지표' });
    await user.click(within(kpi).getByRole('link', { name: /에스컬레이션 대기/ }));
    expect(screen.getByTestId('location')).toHaveTextContent('/reviews?pendingOnly=true');
  });

  it('KPI 경보 발송은 경보 발송 필터, 캡처 행은 그 캡처의 인시던트 목록. 목록 링크는 모두 기간 전체(T23: KPI는 기간 없는 수)', async () => {
    const user = userEvent.setup();
    const first = renderAt('/');
    const kpi = await screen.findByRole('region', { name: '핵심 지표' });
    const total = within(kpi).getByRole('link', { name: /전체 인시던트/ });
    expect(total).toHaveAttribute('href', '/incidents?period=all');
    expect(total.getAttribute('title')).not.toContain('캡처 하나씩');
    expect(within(kpi).getByRole('link', { name: /경보 발송/ }).getAttribute('title')).not.toContain('캡처 하나씩');
    await user.click(within(kpi).getByRole('link', { name: /경보 발송/ }));
    expect(screen.getByTestId('location')).toHaveTextContent('/incidents?period=all&alerted=true');
    first.unmount();

    // 현황판·운영 현황의 /incidents 링크는 모두 period=all을 붙인다(KPI 수와 목록 수가 어긋나지 않게)
    const again = renderAt('/');
    await screen.findByRole('region', { name: '캡처별 현황' });
    await waitFor(() => expect(again.container.querySelectorAll('a[href^="/incidents"]').length).toBeGreaterThan(2));
    const hrefs = [...again.container.querySelectorAll('a[href^="/incidents"]')].map((a) => a.getAttribute('href') ?? '');
    for (const href of hrefs) {
      if (href === '/incidents') continue; // 사이드바 메뉴(기본 큐)
      expect(new URLSearchParams(href.split('?')[1] ?? '').get('period'), href).toBe('all');
    }
    again.unmount();

    const ops = renderAt('/operations');
    await screen.findByRole('heading', { name: '운영 현황' });
    for (const a of ops.container.querySelectorAll('a[href^="/incidents"]')) {
      const href = a.getAttribute('href') ?? '';
      if (href === '/incidents') continue;
      expect(new URLSearchParams(href.split('?')[1] ?? '').get('period'), href).toBe('all');
    }
    ops.unmount();

    renderAt('/');
    const captures = await screen.findByRole('region', { name: '캡처별 현황' });
    const link = await within(captures).findByRole('link', { name: 'CIC 목요일 + 합성 APT 인시던트 목록' });
    // 캡처는 표시 이름, 원래 ID는 툴팁
    expect(within(link).getByText('CIC 목요일 + 합성 APT')).toHaveAttribute('title', expect.stringContaining('캡처 ID: syn1-thu'));
    await user.click(link);
    expect(screen.getByTestId('location')).toHaveTextContent('/incidents?period=all&captureId=syn1-thu');
  });

  it('파이프라인·경보 패널: 캡처마다 최근 작업, 최근 일일 요약과 Dry-run', async () => {
    renderAt('/');
    const pipeline = await screen.findByRole('region', { name: '파이프라인' });
    await waitFor(() => expect(within(pipeline).getAllByRole('row')).toHaveLength(3));
    const synRow = within(pipeline).getByText('CIC 목요일 + 합성 APT').closest('tr') as HTMLElement;
    expect(within(synRow).getByText('실패')).toBeInTheDocument();
    const alertPanel = screen.getByRole('region', { name: '경보' });
    expect(alertPanel).toHaveTextContent('2026-11-20 00:40:00');
    expect(within(alertPanel).getByText('Dry-run')).toBeInTheDocument();
    expect(alertPanel).toHaveTextContent('일일 요약 기록2건');
  });

  it('데이터가 없으면 빈 상태를 보인다', async () => {
    renderAt('/', {
      operations: () => json({ ...operationsResponse, jobs: [], feedbackSummaries: [], slackSummaries: [] }),
      reviews: () => json({ ...reviewsResponse, reviews: [] }),
    });
    expect(await screen.findByText('표시할 캡처 집계가 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('탐지 모델별 집계가 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('탐지 작업 기록이 없습니다.')).toBeInTheDocument();
    expect(screen.getByTestId('data-as-of')).toHaveTextContent('-');
  });

  it('운영 현황 API가 실패하면 오류와 다시 시도를 보이고, 에스컬레이션만 실패하면 그 KPI만 비운다', async () => {
    const first = renderAt('/', { operations: () => json({ message: '서버 오류' }, 500) });
    expect(await screen.findByRole('button', { name: /다시 시도/ })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: '핵심 지표' })).not.toBeInTheDocument();
    first.unmount();

    renderAt('/', { reviews: () => json({ message: '서버 오류' }, 500) });
    const kpi = await screen.findByRole('region', { name: '핵심 지표' });
    const pending = within(kpi).getByRole('link', { name: /에스컬레이션 대기/ });
    await waitFor(() => expect(pending).toHaveTextContent('불러오지 못했습니다'));
    expect(within(kpi).getByRole('link', { name: /전체 인시던트/ })).toHaveTextContent('100');
  });
});

describe('운영 현황 재구성(T20)', () => {
  it('상태 카드 3개와 합계 문장', async () => {
    renderAt('/operations');
    const cards = await screen.findByRole('region', { name: '상태 요약' });
    expect(within(cards).getByRole('region', { name: '파이프라인 상태' })).toHaveTextContent('최근 작업 실패 1개 캡처');
    expect(within(cards).getByRole('region', { name: '파이프라인 상태' })).toHaveTextContent('데이터 기준 2026-11-20 00:30:00');
    // 판정 19/100, 정탐 14 → 73.7%
    expect(within(cards).getByRole('region', { name: '모델 판정 상태' })).toHaveTextContent('정탐률 73.7% · 판정 19/100건(19.0%)');
    // 경보 판정 1 + 3 = 4건(10건 미만)
    const alert = within(cards).getByRole('region', { name: '경보 상태' });
    expect(alert).toHaveTextContent('경보 발송 12건');
    expect(alert).toHaveTextContent('표본 부족 · 경보 판정 4/12건(33.3%)');
  });

  it('판정 집계는 모든 모델 합계 행만 기본 표시하고, 펼치면 탐지 모델별 행과 판정 없음 한 줄이 보인다', async () => {
    const user = userEvent.setup();
    renderAt('/operations');
    const table = (await screen.findAllByText('모든 모델 합계'))[0].closest('table') as HTMLElement;
    expect(within(table).getAllByText('모든 모델 합계')).toHaveLength(2);
    expect(within(table).queryByText('통신 관계 이상')).not.toBeInTheDocument();
    // 정탐률 문장: 판정 9건은 표본 부족, 10건은 정탐률
    expect(within(table).getByText('표본 부족 · 판정 9/79건(11.4%)')).toHaveAttribute(
      'title',
      expect.stringContaining('정탐률 88.9%'),
    );
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

  it('탐지 작업·모델 버전·Slack 일일 요약은 접힌 영역이고 캡처 선택은 표시 이름', async () => {
    renderAt('/operations');
    await screen.findByRole('region', { name: '상태 요약' });
    for (const title of ['탐지 작업 기록', '모델 버전', 'Slack 일일 요약']) {
      const summary = screen.getByText(new RegExp(`^${title}`), { selector: 'summary' });
      expect(summary.closest('details')).not.toHaveAttribute('open');
    }
    const select = screen.getByLabelText('캡처');
    expect(within(select).getByRole('option', { name: 'CIC-IDS2017 수요일' })).toHaveAttribute('value', 'cic17-wed');
    expect(within(select).getByRole('option', { name: 'CIC 목요일 + 합성 APT' })).toHaveAttribute(
      'title',
      expect.stringContaining('캡처 ID: syn1-thu'),
    );
  });
});
