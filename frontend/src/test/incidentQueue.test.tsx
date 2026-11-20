import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentQueueItem } from '../types/api';

/**
 * T18 탐지 사건(조사 큐) 분류 화면: 기본 정렬·열 정렬·페이지 나눔·필터 칩·URL 복원·행 키보드 이동·요약 띠 필터·휴대폰 목록.
 *
 * 시험 데이터 60건(순위 i = 1..60):
 * - i % 10 == 1 → 알림 보냄(높음), i % 10 == 2 → 판단 대기(높음) → 높음 12건(알림 보냄 6, 판단 대기 6)
 * - i % 10 == 3, 4 → 보고서 있음(중간), i % 10 == 5 → 함께 탐지 1개(중간) → 중간 18건
 * - i % 10 == 0 → 종료(우선순위 없음) 6건, 나머지(6~9) → 낮음 24건
 */
function makeItem(i: number): IncidentQueueItem {
  const m = i % 10;
  return {
    jobId: 42,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    queueRank: i,
    incidentId: `cic17-wed|10.0.${i}.1|originator|${i}`,
    hostIp: `10.0.${i}.1`,
    zeekadRole: i % 2 === 0 ? 'responder' : 'originator',
    eventStart: new Date(Date.UTC(2026, 10, 18, 0, i)).toISOString(),
    eventEnd: new Date(Date.UTC(2026, 10, 18, 0, i + 30)).toISOString(),
    zeekadPickedBy: 'ae_v2',
    zeekadAlsoFlaggedBy: m === 5 ? ['iforest_v1'] : [],
    connectionCount: i === 7 ? null : i * 10,
    hostName: i === 1 ? ['ws-01.lab', 'WS-01$'] : [],
    zeekadStatus: m === 0 ? 'closed' : 'open',
    zeekadResolution: m === 0 ? 'benign' : null,
    statusUpdatedAt: null,
    zeekadReportJobId: m === 3 || m === 4 ? 40 : null,
    hasReport: m === 3 || m === 4,
    zeekadReportKind: m === 3 || m === 4 ? 'llm' : null,
    zeekadVerificationPassed: m === 3 ? true : m === 4 ? false : null,
    zeekadWouldSend: m === 1,
    zeekadReviewAction: null,
    zeekadReviewPending: m === 2,
  };
}

const INCIDENTS = Array.from({ length: 60 }, (_, idx) => makeItem(idx + 1));

const queueResponse = {
  maskedView: false,
  allowedCaptures: ['cic17-wed', 'cic17-thu'],
  selectedCaptureId: 'cic17-wed',
  selectedJob: {
    jobId: 42,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    status: 'succeeded',
    startedAt: '2026-11-18T00:00:00Z',
    finishedAt: '2026-11-18T00:02:00Z',
    error: null,
    incidentCount: 60,
  },
  captureJobs: [
    {
      jobId: 42,
      captureId: 'cic17-wed',
      bundleId: 'zeekad-fusion/3',
      status: 'succeeded',
      startedAt: null,
      finishedAt: '2026-11-18T00:02:00Z',
      error: null,
      incidentCount: 60,
    },
  ],
  incidents: INCIDENTS,
  availableModels: ['ae_v2', 'iforest_v1'],
  availableRoles: ['originator', 'responder'],
};

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
    allowedCapturePatterns: ['cic17-*'],
  },
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

function renderQueue(path = '/incidents') {
  document.cookie = 'XSRF-TOKEN=xsrf-test-token; path=/';
  const incidentCalls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json(meResponse);
    if (url.startsWith('/api/incidents?') || url === '/api/incidents') {
      incidentCalls.push(url);
      return json(queueResponse);
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
  return { ...utils, incidentCalls };
}

const loc = () => screen.getByTestId('loc').textContent ?? '';
const params = () => new URLSearchParams(loc().split('?')[1] ?? '');

/** 표 본문 행의 순위(두 번째 칸) */
function tableRanks(): number[] {
  const table = screen.getByRole('table');
  const bodyRows = within(table).getAllByRole('row').slice(1);
  return bodyRows.map((r) => Number(within(r).getAllByRole('cell')[1].textContent));
}

async function ready() {
  await screen.findByRole('table');
}

function header(name: RegExp) {
  return screen.getByRole('button', { name }).closest('th') as HTMLElement;
}

describe('탐지 사건 분류 화면(T18)', () => {
  it('기본 정렬은 우선순위 → 순위이고 우선순위 열에 aria-sort가 있다. 첫 쪽은 50건', async () => {
    renderQueue();
    await ready();
    expect(tableRanks().slice(0, 14)).toEqual([1, 2, 11, 12, 21, 22, 31, 32, 41, 42, 51, 52, 3, 4]);
    expect(tableRanks()).toHaveLength(50);
    expect(header(/우선순위 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');
    expect(header(/^순위 기준 정렬/)).toHaveAttribute('aria-sort', 'none');
    expect(screen.getByText('전체 60건 중 1–50')).toBeInTheDocument();
    // 종료 사건(순위 10)은 우선순위 없음으로 맨 뒤(2쪽)
    expect(tableRanks()).not.toContain(10);
  });

  it('열 머리를 누르면 정렬이 바뀌고 다시 누르면 방향이 바뀐다(URL에 남음). 처음 방향은 열마다 정해져 있다', async () => {
    const user = userEvent.setup();
    renderQueue('/incidents?page=2');
    await ready();
    await user.click(screen.getByRole('button', { name: /연결 수 기준 정렬/ }));
    expect(header(/연결 수 기준 정렬/)).toHaveAttribute('aria-sort', 'descending');
    expect(header(/우선순위 기준 정렬/)).toHaveAttribute('aria-sort', 'none');
    expect(params().get('sort')).toBe('connections');
    expect(params().get('dir')).toBe('desc');
    expect(params().get('page')).toBeNull();
    expect(tableRanks().slice(0, 3)).toEqual([60, 59, 58]);

    await user.click(screen.getByRole('button', { name: /연결 수 기준 정렬/ }));
    expect(header(/연결 수 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');
    expect(params().get('dir')).toBe('asc');
    expect(tableRanks().slice(0, 3)).toEqual([1, 2, 3]);

    await user.click(screen.getByRole('button', { name: /^순위 기준 정렬/ }));
    expect(params().get('sort')).toBe('rank');
    expect(params().get('dir')).toBe('asc');
    expect(header(/^순위 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');

    await user.click(screen.getByRole('button', { name: /관측 시작 기준 정렬/ }));
    expect(params().get('dir')).toBe('desc');
    expect(tableRanks()[0]).toBe(60);

    await user.click(screen.getByRole('button', { name: /상태 기준 정렬/ }));
    expect(params().get('dir')).toBe('asc');
    // 신규 → 조사 중 → 종료: 종료 6건은 2쪽 끝에 있다
    expect(tableRanks().slice(0, 3)).toEqual([1, 2, 3]);
    expect(tableRanks()).not.toContain(10);
    await user.click(screen.getByRole('button', { name: '다음 쪽' }));
    expect(tableRanks().slice(-6)).toEqual([10, 20, 30, 40, 50, 60]);
  });

  it('연결 수 없음(null)은 내림·오름 모두 맨 뒤', async () => {
    renderQueue('/incidents?sort=connections&dir=asc&size=100');
    await ready();
    const ranks = tableRanks();
    expect(ranks).toHaveLength(60);
    expect(ranks[ranks.length - 1]).toBe(7);
  });

  it('페이지 나눔: 다음 쪽·쪽 번호·쪽당 건수, 필터를 바꾸면 1쪽으로 돌아간다', async () => {
    const user = userEvent.setup();
    renderQueue();
    await ready();
    expect(screen.getByRole('button', { name: '이전 쪽' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: '다음 쪽' }));
    expect(params().get('page')).toBe('2');
    expect(screen.getByText('전체 60건 중 51–60')).toBeInTheDocument();
    expect(tableRanks()).toHaveLength(10);
    expect(screen.getByRole('button', { name: '2쪽' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('button', { name: '다음 쪽' })).toBeDisabled();

    // 요약 띠 필터를 누르면 1쪽
    await user.click(screen.getByRole('button', { name: /우선순위 낮음 24건만 보기/ }));
    expect(params().get('page')).toBeNull();
    expect(params().get('priority')).toBe('low');
    expect(screen.getByText('전체 24건 중 1–24')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /우선순위 낮음 24건만 보기/ }));
    expect(params().get('priority')).toBeNull();

    // 쪽당 25건
    await user.click(screen.getByRole('button', { name: '2쪽' }));
    expect(params().get('page')).toBe('2');
    await user.selectOptions(screen.getByLabelText('쪽당 건수'), '25');
    expect(params().get('size')).toBe('25');
    expect(params().get('page')).toBeNull();
    expect(screen.getByText('전체 60건 중 1–25')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '3쪽' })).toBeInTheDocument();
  });

  it('범위 밖 page는 마지막 쪽으로, 허용 밖 size는 50으로 고친다', async () => {
    renderQueue('/incidents?page=9&size=30');
    await ready();
    await waitFor(() => expect(params().get('page')).toBe('2'));
    expect(params().get('size')).toBeNull();
    expect(screen.getByText('전체 60건 중 51–60')).toBeInTheDocument();
  });

  it('URL 쿼리로 필터·정렬·페이지를 복원한다', async () => {
    renderQueue('/incidents?sort=rank&dir=desc&page=2&size=25&priority=low');
    await ready();
    // 낮음 24건 → 25건씩이면 1쪽뿐이므로 page=2는 1쪽으로 고친다
    await waitFor(() => expect(params().get('page')).toBeNull());
    expect(header(/^순위 기준 정렬/)).toHaveAttribute('aria-sort', 'descending');
    expect(tableRanks().slice(0, 3)).toEqual([59, 58, 57]);
    expect(screen.getByRole('button', { name: /우선순위 낮음 24건만 보기/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('쪽당 건수')).toHaveValue('25');
    expect(screen.getByRole('button', { name: '우선순위: 낮음 필터 지우기' })).toBeInTheDocument();
  });

  it('필터 영역은 접혀 있고, 적용 중인 필터는 칩으로 보이며 하나씩 지울 수 있다. 필터 초기화는 수집 구간·분석 실행만 남긴다', async () => {
    const user = userEvent.setup();
    const { incidentCalls } = renderQueue(
      '/incidents?captureId=cic17-wed&jobId=42&status=open&pickedBy=ae_v2&reviewPending=true&sort=rank&page=1',
    );
    await ready();
    expect(screen.queryByLabelText('주 탐지 모델')).toBeNull();
    const toggle = screen.getByRole('button', { name: /^필터(\s\d+)?$/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    const chips = screen.getByRole('list', { name: '적용 중인 필터' });
    expect(within(chips).getByRole('button', { name: '사건 상태: 신규 필터 지우기' })).toBeInTheDocument();
    expect(within(chips).getByRole('button', { name: '주 탐지 모델 ae_v2 필터 지우기' })).toBeInTheDocument();
    expect(within(chips).getByRole('button', { name: '판단 대기만 필터 지우기' })).toBeInTheDocument();
    // 수집 구간·분석 실행은 칩에 넣지 않는다
    expect(within(chips).queryByText(/cic17-wed/)).toBeNull();
    expect(incidentCalls.some((u) => u.includes('status=open'))).toBe(true);

    await user.click(within(chips).getByRole('button', { name: '사건 상태: 신규 필터 지우기' }));
    expect(params().get('status')).toBeNull();
    expect(params().get('pickedBy')).toBe('ae_v2');
    await waitFor(() => expect(incidentCalls[incidentCalls.length - 1]).not.toContain('status='));

    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByLabelText('주 탐지 모델')).toHaveValue('ae_v2');

    await user.click(screen.getByRole('button', { name: '필터 초기화' }));
    expect(params().get('captureId')).toBe('cic17-wed');
    expect(params().get('jobId')).toBe('42');
    expect([...params().keys()].sort()).toEqual(['captureId', 'jobId']);
    expect(screen.queryByRole('list', { name: '적용 중인 필터' })).toBeNull();
  });

  it('수집 구간을 바꾸면 분석 실행과 쪽 번호를 지운다', async () => {
    const user = userEvent.setup();
    renderQueue('/incidents?captureId=cic17-wed&jobId=42&page=2');
    await ready();
    await user.selectOptions(screen.getByLabelText('수집 구간'), 'cic17-thu');
    expect(params().get('captureId')).toBe('cic17-thu');
    expect(params().get('jobId')).toBeNull();
    expect(params().get('page')).toBeNull();
  });

  it('요약 띠: 건수는 서버 응답 기준이고 눌러도 바뀌지 않는다. 판단 대기·알림 보냄도 누르면 필터된다', async () => {
    const user = userEvent.setup();
    renderQueue();
    await ready();
    const strip = screen.getByRole('region', { name: '사건 요약' });
    expect(within(strip).getByText('전체 사건 수')).toBeInTheDocument();
    const high = within(strip).getByRole('button', { name: '우선순위 높음 12건만 보기' });
    expect(within(strip).getByRole('button', { name: '우선순위 중간 18건만 보기' })).toBeInTheDocument();
    expect(high).toHaveAttribute('aria-pressed', 'false');

    await user.click(high);
    expect(high).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('전체 12건 중 1–12')).toBeInTheDocument();
    expect(within(strip).getByRole('button', { name: '우선순위 중간 18건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByText('60')).toBeInTheDocument();

    await user.click(within(strip).getByRole('button', { name: '판단 대기 6건만 보기' }));
    expect(params().get('reviewPending')).toBe('true');
    expect(tableRanks()).toEqual([2, 12, 22, 32, 42, 52]);

    await user.click(high);
    await user.click(within(strip).getByRole('button', { name: '판단 대기 6건만 보기' }));
    await user.click(within(strip).getByRole('button', { name: '알림 보냄 6건만 보기' }));
    expect(params().get('alerted')).toBe('true');
    expect(tableRanks()).toEqual([1, 11, 21, 31, 41, 51]);
    // 알림 보냄은 화면 필터라 서버 파라미터(wouldSend)를 보내지 않는다
    expect(params().get('wouldSend')).toBeNull();

    expect(within(strip).getByRole('link', { name: '판단 요청 화면' })).toHaveAttribute('href', '/reviews?pendingOnly=true');
    expect(within(strip).getByText('자동 분류 기준')).toBeInTheDocument();
    expect(within(strip).getByText(/분석가 판정이 아닙니다/)).toBeInTheDocument();
  });

  it('행 전체를 누르거나 행에서 Enter를 누르면 상세로 간다', async () => {
    const user = userEvent.setup();
    const first = renderQueue();
    await ready();
    const table = screen.getByRole('table');
    const row = within(table).getByText('10.0.11.1').closest('tr') as HTMLElement;
    expect(row).toHaveAttribute('tabindex', '0');
    row.focus();
    expect(row).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(loc()).toBe('/incidents/42/rank/11');
    first.unmount();

    renderQueue();
    await ready();
    const row2 = within(screen.getByRole('table')).getByText('10.0.21.1').closest('tr') as HTMLElement;
    fireEvent.click(within(row2).getAllByRole('cell')[4]);
    expect(loc()).toBe('/incidents/42/rank/21');
  });

  it('행에 우선순위·숨기는 열의 정보(툴팁)·여러 호스트 이름 말줄임이 있다', async () => {
    renderQueue();
    await ready();
    const table = screen.getByRole('table');
    const row1 = within(table).getByText('10.0.1.1').closest('tr') as HTMLElement;
    expect(within(row1).getByText('높음')).toBeInTheDocument();
    expect(within(row1).getByText('ws-01.lab')).toHaveAttribute('title', 'ws-01.lab, WS-01$');
    expect(within(row1).getByText('외 1')).toBeInTheDocument();
    expect(row1).toHaveAttribute('title', '통신 방향 연결 시작 측 · 연결 10건 · 분석가 판단 -');
    expect(within(row1).getByRole('img', { name: '알림 보냄' })).toBeInTheDocument();
    const row3 = within(table).getByText('10.0.3.1').closest('tr') as HTMLElement;
    expect(within(row3).getByText('중간')).toBeInTheDocument();
    expect(within(row3).getByRole('img', { name: '사실 검증 통과' })).toBeInTheDocument();
    const row4 = within(table).getByText('10.0.4.1').closest('tr') as HTMLElement;
    expect(within(row4).getByRole('img', { name: '사실 검증 실패' })).toBeInTheDocument();
    const row6 = within(table).getByText('10.0.6.1').closest('tr') as HTMLElement;
    expect(within(row6).getByText('낮음')).toBeInTheDocument();
    expect(within(row6).getByRole('img', { name: '알림 보류' })).toBeInTheDocument();
  });

  it('종료 사건은 우선순위 없음으로 표시한다', async () => {
    renderQueue('/incidents?sort=rank&dir=desc');
    await ready();
    const row60 = within(screen.getByRole('table')).getByText('10.0.60.1').closest('tr') as HTMLElement;
    expect(within(row60).getByText('우선순위 없음')).toBeInTheDocument();
    expect(within(row60).queryByText('낮음')).toBeNull();
  });

  it('휴대폰 목록: 사건마다 우선순위·호스트·시각·상태가 있는 한 장짜리 항목', async () => {
    renderQueue();
    await ready();
    const list = screen.getByRole('list', { name: '탐지 사건 목록' });
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(50);
    const firstItem = items[0];
    const link = within(firstItem).getByRole('link');
    expect(link).toHaveAttribute('href', '/incidents/42/rank/1');
    expect(within(firstItem).getByText('높음')).toBeInTheDocument();
    expect(within(firstItem).getByText('10.0.1.1')).toBeInTheDocument();
    expect(within(firstItem).getByText('2026-11-18 09:01:00')).toBeInTheDocument();
    expect(within(firstItem).getByText('신규')).toBeInTheDocument();
  });
});
