import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { NEW_INCIDENT_POLL_MS } from '../pages/IncidentQueuePage';
import type { IncidentQueueItem, QueuePriority, UnifiedQueueItem } from '../types/api';
import { fakeNewCount, fakeQueue, unified, type FakeQueueOptions } from './fakeQueueServer';

/**
 * T23 통합 인시던트 큐 화면(T18 분류 화면을 이어받음): 서버 정렬·쪽 나눔·요약, 기간·수집원 조건, URL 동기화,
 * 옛 주소(captureId·jobId·sort=rank), 빈 결과 두 종류, 새 인시던트 띠(자동 갱신), 고정 스냅샷, 휴대폰 목록.
 *
 * 시험 데이터 60건(i = 1..60, 호스트 10.0.i.1). 1~30은 cic17-wed(가져온 데이터, 작업 42), 31~60은 lab-20261119(실습망 센서, 작업 50).
 * - 우선순위는 서버가 준 값: i % 10 == 1·2 → High 12건, 3·4·5 → Medium 18건, 0 → 종결(없음) 6건, 나머지 → Low 24건
 * - 탐지 시각은 i가 클수록 최근(2026-11-20 00:00 + i분)
 */
function base(i: number): IncidentQueueItem {
  const m = i % 10;
  const live = i > 30;
  return {
    jobId: live ? 50 : 42,
    captureId: live ? 'lab-20261119' : 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    queueRank: live ? i - 30 : i,
    incidentId: `${live ? 'lab-20261119' : 'cic17-wed'}|10.0.${i}.1|originator|${i}`,
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
    // T21 경보 발송(사건 알림 Slack 기록)은 발송 판단과 다른 집합: 끝자리 1·6 → 12건
    alerted: m === 1 || m === 6,
  };
}

function priorityOf(i: number): QueuePriority | null {
  const m = i % 10;
  if (m === 0) return null;
  if (m === 1 || m === 2) return 'high';
  if (m === 3 || m === 4 || m === 5) return 'medium';
  return 'low';
}

function makeItem(i: number): UnifiedQueueItem {
  return unified(base(i), {
    detectedAt: new Date(Date.UTC(2026, 10, 20, 0, i)).toISOString(),
    priority: priorityOf(i),
    ongoing: i === 59,
  });
}

/** lab-20261119 표시 이름(사전 labels.ts의 메모 포함) */
const LAB_NAME = '실습망 2026-11-19 · Kali 공격 + 정상 배경';

const ITEMS = Array.from({ length: 60 }, (_, idx) => makeItem(idx + 1));

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
    allowedCapturePatterns: ['cic17-*', 'lab-*'],
  },
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

function renderQueue(path = '/incidents', options: Partial<FakeQueueOptions> & { newItems?: () => UnifiedQueueItem[] } = {}) {
  document.cookie = 'XSRF-TOKEN=xsrf-test-token; path=/';
  const queueCalls: string[] = [];
  const newCountCalls: string[] = [];
  const state = { items: ITEMS };
  const opts = (): FakeQueueOptions => ({
    availableModels: ['ae_v2', 'iforest_v1'],
    anchor: '2026-11-20T01:30:00Z',
    ...options,
    items: options.newItems ? options.newItems() : (options.items ?? state.items),
  });
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json(meResponse);
    if (url === '/api/time-context')
      return json({ anchor: opts().anchor, anchorMode: opts().snapshot ? 'latest-data' : 'now', snapshot: Boolean(opts().snapshot) });
    if (url.startsWith('/api/incidents/queue/new-count')) {
      newCountCalls.push(url);
      return json(fakeNewCount(url, opts()));
    }
    if (url.startsWith('/api/incidents/queue')) {
      queueCalls.push(url);
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
  return { ...utils, queueCalls, newCountCalls, fetchMock };
}

const loc = () => screen.getByTestId('loc').textContent ?? '';
const params = () => new URLSearchParams(loc().split('?')[1] ?? '');
const lastCall = (calls: string[]) => new URLSearchParams(calls[calls.length - 1].split('?')[1] ?? '');

/** 표 본문 행의 시험 번호 i(호스트 10.0.i.1) */
function tableIds(): number[] {
  const table = screen.getByRole('table');
  const bodyRows = within(table).getAllByRole('row').slice(1);
  return bodyRows.map((r) => {
    const host = within(r).getAllByRole('link')[0].textContent ?? '';
    return Number(host.split('.')[2]);
  });
}

async function ready() {
  await screen.findByRole('table');
}

function header(name: RegExp) {
  return screen.getByRole('button', { name }).closest('th') as HTMLElement;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('통합 인시던트 큐(T23)', () => {
  it('기본: 기간 24시간·우선순위 오름으로 서버에 묻고, 서버 순서(우선순위 → 탐지 시각 최근)를 그대로 그린다. 첫 쪽은 50건', async () => {
    const { queueCalls } = renderQueue();
    await ready();
    const sent = lastCall(queueCalls);
    expect(sent.get('period')).toBe('24h');
    expect(sent.get('sort')).toBe('priority');
    expect(sent.get('dir')).toBe('asc');
    expect(sent.get('page')).toBe('1');
    expect(sent.get('size')).toBe('50');
    // 캡처·작업 파라미터는 보내지 않는다
    expect(sent.get('captureId')).toBeNull();
    expect(sent.get('jobId')).toBeNull();
    expect(queueCalls.every((u) => u.startsWith('/api/incidents/queue?'))).toBe(true);
    expect(tableIds().slice(0, 12)).toEqual([52, 51, 42, 41, 32, 31, 22, 21, 12, 11, 2, 1]);
    expect(tableIds()).toHaveLength(50);
    expect(header(/우선순위 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');
    expect(header(/탐지 시각 기준 정렬/)).toHaveAttribute('aria-sort', 'none');
    expect(screen.getByText('전체 60건 중 1–50')).toBeInTheDocument();
    // 종결(우선순위 없음)은 서버가 맨 뒤로 보낸다
    expect(tableIds()).not.toContain(10);
    // 기본 기간은 URL에 남기지 않는다
    expect(params().get('period')).toBeNull();
    expect(screen.getByRole('button', { name: '24시간' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('열: 우선순위·탐지 시각·호스트·수집원·발생 시각·탐지 모델·리포트·상태·에스컬레이션·세션 수. 캡처 안 순위 열은 없다', async () => {
    renderQueue();
    await ready();
    const headers = within(screen.getByRole('table')).getAllByRole('columnheader').map((h) => h.textContent?.trim());
    expect(headers).toEqual([
      '우선순위',
      '탐지 시각',
      '호스트',
      '수집원',
      '통신 방향',
      '발생 시각 · 지속',
      '탐지 모델',
      '리포트·판단',
      '상태 · 판정',
      '에스컬레이션',
      '세션 수',
    ]);
    expect(screen.queryByRole('button', { name: /^순위 기준 정렬/ })).toBeNull();
  });

  it('열 머리를 누르면 서버 정렬 파라미터가 바뀌고 다시 누르면 방향이 바뀐다(URL에 남음). 처음 방향은 열마다 정해져 있다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue('/incidents?page=2');
    await ready();
    await user.click(screen.getByRole('button', { name: /세션 수 기준 정렬/ }));
    expect(header(/세션 수 기준 정렬/)).toHaveAttribute('aria-sort', 'descending');
    expect(header(/우선순위 기준 정렬/)).toHaveAttribute('aria-sort', 'none');
    expect(params().get('sort')).toBe('connections');
    expect(params().get('dir')).toBe('desc');
    expect(params().get('page')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('sort')).toBe('connections'));
    expect(lastCall(queueCalls).get('page')).toBe('1');
    await waitFor(() => expect(tableIds().slice(0, 3)).toEqual([60, 59, 58]));

    await user.click(screen.getByRole('button', { name: /세션 수 기준 정렬/ }));
    expect(params().get('dir')).toBe('asc');
    await waitFor(() => expect(tableIds().slice(0, 3)).toEqual([1, 2, 3]));

    await user.click(screen.getByRole('button', { name: /탐지 시각 기준 정렬/ }));
    expect(params().get('sort')).toBe('detected');
    expect(params().get('dir')).toBe('desc');
    await waitFor(() => expect(tableIds()[0]).toBe(60));

    await user.click(screen.getByRole('button', { name: /발생 시각 기준 정렬/ }));
    expect(params().get('sort')).toBe('start');
    expect(params().get('dir')).toBe('desc');

    await user.click(screen.getByRole('button', { name: /상태 기준 정렬/ }));
    expect(params().get('dir')).toBe('asc');
    await waitFor(() => expect(lastCall(queueCalls).get('sort')).toBe('status'));
    expect(tableIds()).not.toContain(10);
  });

  it('세션 수 없음(null)은 서버가 내림·오름 모두 맨 뒤로 보내고 화면은 그 순서를 그대로 그린다', async () => {
    renderQueue('/incidents?sort=connections&dir=asc&size=100');
    await ready();
    const ids = tableIds();
    expect(ids).toHaveLength(60);
    expect(ids[ids.length - 1]).toBe(7);
  });

  it('쪽 나눔은 서버 값: 다음 쪽·쪽 번호·쪽당 건수, 거르기를 바꾸면 1쪽으로 돌아간다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue();
    await ready();
    expect(screen.getByRole('button', { name: '이전 쪽' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: '다음 쪽' }));
    expect(params().get('page')).toBe('2');
    await waitFor(() => expect(screen.getByText('전체 60건 중 51–60')).toBeInTheDocument());
    expect(lastCall(queueCalls).get('page')).toBe('2');
    expect(tableIds()).toHaveLength(10);
    expect(screen.getByRole('button', { name: '2쪽' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('button', { name: '다음 쪽' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /우선순위 Low 24건만 보기/ }));
    expect(params().get('page')).toBeNull();
    expect(params().get('priority')).toBe('low');
    await waitFor(() => expect(screen.getByText('전체 24건 중 1–24')).toBeInTheDocument());
    expect(lastCall(queueCalls).get('priority')).toBe('low');
    await user.click(screen.getByRole('button', { name: /우선순위 Low 24건만 보기/ }));
    expect(params().get('priority')).toBeNull();

    await waitFor(() => expect(screen.getByRole('button', { name: '2쪽' })).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: '2쪽' }));
    expect(params().get('page')).toBe('2');
    await user.selectOptions(screen.getByLabelText('쪽당 건수'), '25');
    expect(params().get('size')).toBe('25');
    expect(params().get('page')).toBeNull();
    await waitFor(() => expect(screen.getByText('전체 60건 중 1–25')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: '3쪽' })).toBeInTheDocument();
  });

  it('범위 밖 page는 서버가 고친 마지막 쪽으로, 허용 밖 size는 50으로 URL을 고친다', async () => {
    renderQueue('/incidents?page=9&size=30');
    await ready();
    await waitFor(() => expect(params().get('page')).toBe('2'));
    expect(params().get('size')).toBeNull();
    await waitFor(() => expect(screen.getByText('전체 60건 중 51–60')).toBeInTheDocument());
  });

  it('URL 쿼리로 기간·수집원·거르기·정렬·쪽을 복원한다', async () => {
    const { queueCalls } = renderQueue('/incidents?period=7d&source=imported&sort=start&dir=asc&page=2&size=25&priority=low');
    await ready();
    // 가져온 데이터의 Low는 12건 → 25건씩이면 1쪽뿐이라 서버가 1쪽으로 고친다
    await waitFor(() => expect(params().get('page')).toBeNull());
    const sent = lastCall(queueCalls);
    expect(sent.get('period')).toBe('7d');
    expect(sent.get('source')).toBe('imported');
    expect(header(/발생 시각 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');
    expect(screen.getByRole('button', { name: '7일' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('수집원')).toHaveValue('src:imported');
    expect(screen.getByRole('button', { name: /우선순위 Low 12건만 보기/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('쪽당 건수')).toHaveValue('25');
    expect(screen.getByRole('button', { name: '우선순위: Low 필터 지우기' })).toBeInTheDocument();
    expect(tableIds().every((i) => i <= 30)).toBe(true);
  });

  it('기간 버튼은 URL과 서버 파라미터를 바꾼다(24시간은 기본이라 URL에서 지운다)', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue('/incidents?page=2');
    await ready();
    await user.click(screen.getByRole('button', { name: '전체' }));
    expect(params().get('period')).toBe('all');
    expect(params().get('page')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('period')).toBe('all'));
    await user.click(screen.getByRole('button', { name: '1시간' }));
    expect(params().get('period')).toBe('1h');
    await user.click(screen.getByRole('button', { name: '24시간' }));
    expect(params().get('period')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('period')).toBe('24h'));
  });

  it('수집원: 전체·실습망 센서·가져온 데이터와 그 안의 캡처 표시 이름을 고른다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue();
    await ready();
    const select = screen.getByLabelText('수집원');
    expect(select).toHaveValue('');
    const options = within(select).getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual([
      '전체 수집원',
      '실습망 센서 전체',
      LAB_NAME,
      '가져온 데이터 전체',
      'CIC-IDS2017 수요일',
    ]);
    await user.selectOptions(select, 'src:live');
    expect(params().get('source')).toBe('live');
    expect(params().get('captureId')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('source')).toBe('live'));
    await waitFor(() => expect(tableIds().every((i) => i > 30)).toBe(true));

    await user.selectOptions(screen.getByLabelText('수집원'), 'cap:cic17-wed');
    expect(params().get('captureId')).toBe('cic17-wed');
    expect(params().get('source')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('captureId')).toBe('cic17-wed'));

    await user.selectOptions(screen.getByLabelText('수집원'), '');
    expect(params().get('captureId')).toBeNull();
    expect(params().get('source')).toBeNull();
  });

  it('옛 주소: captureId는 수집원 안의 캡처 선택으로 읽고, jobId는 지우고(replace) 안내를 한 번 보인다(닫을 수 있음). sort=rank는 기본 정렬', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue('/incidents?captureId=cic17-wed&jobId=42&sort=rank&dir=desc&status=open');
    await ready();
    await waitFor(() => expect(params().get('jobId')).toBeNull());
    expect(params().get('captureId')).toBe('cic17-wed');
    expect(params().get('sort')).toBeNull();
    expect(params().get('dir')).toBeNull();
    expect(params().get('status')).toBe('open');
    // jobId·rank는 서버로 보내지 않는다
    expect(queueCalls.some((u) => u.includes('jobId'))).toBe(false);
    expect(queueCalls.some((u) => u.includes('sort=rank'))).toBe(false);
    expect(lastCall(queueCalls).get('captureId')).toBe('cic17-wed');
    expect(lastCall(queueCalls).get('sort')).toBe('priority');
    expect(screen.getByLabelText('수집원')).toHaveValue('cap:cic17-wed');
    expect(header(/우선순위 기준 정렬/)).toHaveAttribute('aria-sort', 'ascending');
    const notice = screen.getByText('이전 주소의 탐지 작업 선택은 더 쓰지 않습니다. 최신 결과를 보여 줍니다.');
    expect(notice).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '안내 닫기' }));
    expect(screen.queryByText(/이전 주소의 탐지 작업 선택/)).toBeNull();

    // jobId 없는 옛 sort=rank 링크는 안내 없이 기본 정렬
    const other = renderQueue('/incidents?sort=rank');
    await waitFor(() => expect(within(other.container).queryByText(/이전 주소의 탐지 작업 선택/)).toBeNull());
  });

  it('필터 영역은 접혀 있고, 적용 중인 필터는 칩으로 보이며 하나씩 지울 수 있다. 필터 초기화는 기간·쪽 크기만 남긴다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue(
      '/incidents?period=all&size=25&captureId=cic17-wed&status=open&pickedBy=ae_v2&reviewPending=true&page=1',
    );
    await ready();
    expect(screen.queryByLabelText('탐지 모델')).toBeNull();
    const toggle = screen.getByRole('button', { name: /^필터(\s\d+)?$/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    const chips = screen.getByRole('list', { name: '적용 중인 필터' });
    expect(within(chips).getByRole('button', { name: '인시던트 상태: 신규 필터 지우기' })).toBeInTheDocument();
    expect(within(chips).getByRole('button', { name: '탐지 모델 ae_v2 필터 지우기' })).toBeInTheDocument();
    expect(within(chips).getByRole('button', { name: '에스컬레이션 대기만 필터 지우기' })).toBeInTheDocument();
    // 수집원은 칩에 넣지 않는다(조건 줄의 수집원 선택에 보인다)
    expect(within(chips).queryByText(/cic17-wed/)).toBeNull();
    expect(queueCalls.some((u) => u.includes('status=open'))).toBe(true);

    await user.click(within(chips).getByRole('button', { name: '인시던트 상태: 신규 필터 지우기' }));
    expect(params().get('status')).toBeNull();
    expect(params().get('pickedBy')).toBe('ae_v2');
    await waitFor(() => expect(queueCalls[queueCalls.length - 1]).not.toContain('status='));

    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByLabelText('탐지 모델')).toHaveValue('ae_v2');

    await user.click(screen.getByRole('button', { name: '필터 초기화' }));
    expect([...params().keys()].sort()).toEqual(['period', 'size']);
    expect(params().get('period')).toBe('all');
    expect(screen.queryByRole('list', { name: '적용 중인 필터' })).toBeNull();
    expect(screen.getByLabelText('수집원')).toHaveValue('');
  });

  it('요약 띠: 건수는 서버 summary이고 띠를 눌러 걸러도 띠의 수는 그대로다. 에스컬레이션 대기·경보 발송도 서버로 거른다', async () => {
    const user = userEvent.setup();
    const { queueCalls } = renderQueue();
    await ready();
    const strip = screen.getByRole('region', { name: '인시던트 요약' });
    expect(within(strip).getByText('전체 인시던트')).toBeInTheDocument();
    const high = within(strip).getByRole('button', { name: '우선순위 High 12건만 보기' });
    expect(within(strip).getByRole('button', { name: '우선순위 Medium 18건만 보기' })).toBeInTheDocument();
    expect(high).toHaveAttribute('aria-pressed', 'false');

    await user.click(high);
    expect(high).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(screen.getByText('전체 12건 중 1–12')).toBeInTheDocument());
    expect(within(strip).getByRole('button', { name: '우선순위 Medium 18건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByText('60')).toBeInTheDocument();

    await user.click(within(strip).getByRole('button', { name: '에스컬레이션 대기 6건만 보기' }));
    expect(params().get('reviewPending')).toBe('true');
    await waitFor(() => expect(lastCall(queueCalls).get('reviewPending')).toBe('true'));
    await waitFor(() => expect([...tableIds()].sort((a, b) => a - b)).toEqual([2, 12, 22, 32, 42, 52]));

    await user.click(high);
    await user.click(within(strip).getByRole('button', { name: '에스컬레이션 대기 6건만 보기' }));
    await user.click(within(strip).getByRole('button', { name: '경보 발송 12건만 보기' }));
    expect(params().get('alerted')).toBe('true');
    await waitFor(() => expect(screen.getByText('전체 12건 중 1–12')).toBeInTheDocument());
    expect([...tableIds()].sort((x, y) => x - y)).toEqual([1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56]);
    // 경보 발송(alerted)은 발송 판단(wouldSend)과 다른 파라미터다
    expect(lastCall(queueCalls).get('alerted')).toBe('true');
    expect(lastCall(queueCalls).get('wouldSend')).toBeNull();

    expect(within(strip).getByRole('link', { name: '에스컬레이션으로 이동' })).toHaveAttribute('href', '/reviews?pendingOnly=true');
    expect(within(strip).getByText('자동 분류 기준')).toBeInTheDocument();
    expect(within(strip).getByText(/분석가 판정이 아닙니다/)).toBeInTheDocument();
  });

  it('행 전체를 누르거나 행에서 Enter를 누르면 상세로 가고, 목록 쿼리를 그대로 from=으로 넘긴다(캡처를 덧붙이지 않는다)', async () => {
    const user = userEvent.setup();
    const first = renderQueue();
    await ready();
    const table = screen.getByRole('table');
    const row = within(table).getByText('10.0.11.1').closest('tr') as HTMLElement;
    expect(row).toHaveAttribute('tabindex', '0');
    row.focus();
    expect(row).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(loc()).toBe('/incidents/42/rank/11?from=');
    first.unmount();

    renderQueue('/incidents?priority=high&sort=detected&dir=desc&period=all');
    await ready();
    const row2 = within(screen.getByRole('table')).getByText('10.0.41.1').closest('tr') as HTMLElement;
    fireEvent.click(within(row2).getAllByRole('cell')[5]);
    expect(loc().split('?')[0]).toBe('/incidents/50/rank/11');
    expect(new URLSearchParams(params().get('from') ?? '').toString()).toBe(
      'priority=high&sort=detected&dir=desc&period=all',
    );
  });

  it('행 안에 상세로 가는 실제 링크가 있어 화면 판독기가 링크로 인식한다(T18 L3). 링크를 누르면 상세로 간다', async () => {
    const user = userEvent.setup();
    renderQueue('/incidents?status=open');
    await ready();
    const table = screen.getByRole('table');
    const row = within(table).getByText('10.0.11.1').closest('tr') as HTMLElement;
    const link = within(row).getByRole('link', { name: '인시던트 상세: 10.0.11.1 · CIC-IDS2017 수요일' });
    expect(link).toHaveAttribute('href', '/incidents/42/rank/11?from=status%3Dopen');
    expect(row).toHaveAttribute('tabindex', '0');
    await user.click(link);
    expect(loc()).toBe('/incidents/42/rank/11?from=status%3Dopen');
  });

  it('행: 서버 우선순위·탐지 시각(상대 + 절대)·수집원(종류 + 표시 이름)·진행 중·툴팁·호스트 이름 말줄임', async () => {
    renderQueue();
    await ready();
    const table = screen.getByRole('table');
    const row1 = within(table).getByText('10.0.1.1').closest('tr') as HTMLElement;
    expect(within(row1).getByText('High')).toBeInTheDocument();
    expect(within(row1).getByText('ws-01.lab')).toHaveAttribute('title', 'ws-01.lab, WS-01$');
    expect(within(row1).getByText('외 1')).toBeInTheDocument();
    expect(row1).toHaveAttribute('title', '통신 방향 출발지 · 세션 10건 · 에스컬레이션 -');
    // 탐지 시각: 기준 시각(01:30Z)에서 1시간 29분 전 → "1시간 전", 절대 시각은 툴팁(KST)
    expect(within(row1).getByText('1시간 전')).toBeInTheDocument();
    expect(within(row1).getByTitle('탐지 시각 2026-11-20 09:01:00')).toBeInTheDocument();
    // T23 7절: 수집원은 한 줄(아이콘 + 표시 이름). 종류 문구·표시 이름 전체·캡처 ID는 툴팁과 접근성 이름에 있다.
    const src1 = within(row1).getByLabelText('수집원: 가져온 데이터 · CIC-IDS2017 수요일 · 캡처 ID: cic17-wed');
    expect(src1).toHaveAttribute('title', '가져온 데이터 · CIC-IDS2017 수요일 · 캡처 ID: cic17-wed');
    expect(within(row1).getByText('CIC-IDS2017 수요일')).toBeInTheDocument();
    expect(within(row1).queryByText('가져온 데이터')).toBeNull();
    // 탐지 시각은 상대 표시만 글로, 발생 시각은 초 없이(기준 시각과 같은 해면 연도도 뺀다)
    expect(within(row1).queryByText('11-20 09:01')).toBeNull();
    expect(within(row1).getByText('11-18 09:01')).toBeInTheDocument();
    expect(within(row1).queryByText('진행 중')).toBeNull();
    // T21: 행 칩은 발송 판단(wouldSend)이다
    expect(within(row1).getByRole('img', { name: '발송 판단: 발송' })).toBeInTheDocument();
    expect(within(table).queryByRole('img', { name: '경보 발송' })).toBeNull();
    const row3 = within(table).getByText('10.0.3.1').closest('tr') as HTMLElement;
    expect(within(row3).getByText('Medium')).toBeInTheDocument();
    expect(within(row3).getByRole('img', { name: '검증 통과' })).toBeInTheDocument();
    const row4 = within(table).getByText('10.0.4.1').closest('tr') as HTMLElement;
    expect(within(row4).getByRole('img', { name: '검증 실패' })).toBeInTheDocument();
    const row36 = within(table).getByText('10.0.36.1').closest('tr') as HTMLElement;
    expect(within(row36).getByText('Low')).toBeInTheDocument();
    expect(within(row36).getByLabelText(`수집원: 실습망 센서 · ${LAB_NAME} · 캡처 ID: lab-20261119`)).toBeInTheDocument();
    expect(within(row36).getByText(LAB_NAME)).toBeInTheDocument();
    expect(within(row36).getByRole('img', { name: '발송 판단: 보류' })).toBeInTheDocument();
    const row59 = within(table).getByText('10.0.59.1').closest('tr') as HTMLElement;
    expect(within(row59).getByText('진행 중')).toBeInTheDocument();
    expect(within(row59).getByText('진행 중').closest('[title]')).not.toHaveAttribute('title', expect.stringContaining('기준 시각 기준'));
  });

  it('서버 우선순위가 없음(종결)이면 우선순위 없음으로 표시한다(화면이 다시 계산하지 않는다)', async () => {
    // 서버가 Low를 준 신규 인시던트가 발송 판단 "발송"이어도 화면은 서버 값을 그대로 보인다
    const items = [unified(base(1), { priority: 'low' }), unified(base(10), { priority: null })];
    renderQueue('/incidents', { items });
    await ready();
    const row1 = within(screen.getByRole('table')).getByText('10.0.1.1').closest('tr') as HTMLElement;
    expect(within(row1).getByText('Low')).toBeInTheDocument();
    const row10 = within(screen.getByRole('table')).getByText('10.0.10.1').closest('tr') as HTMLElement;
    expect(within(row10).getByText('우선순위 없음')).toBeInTheDocument();
    expect(within(row10).queryByText('Low')).toBeNull();
  });

  it('휴대폰 목록: 우선순위·호스트·탐지 시각·수집원·진행 중·발생 시각·상태가 있는 한 장짜리 항목', async () => {
    renderQueue();
    await ready();
    const list = screen.getByRole('list', { name: '인시던트 목록' });
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(50);
    const firstItem = items[0];
    const link = within(firstItem).getByRole('link');
    expect(link).toHaveAttribute('href', '/incidents/50/rank/22?from=');
    expect(within(firstItem).getByText('High')).toBeInTheDocument();
    expect(within(firstItem).getByText('10.0.52.1')).toBeInTheDocument();
    expect(within(firstItem).getByText('탐지 38분 전')).toBeInTheDocument();
    expect(within(firstItem).getByText('실습망 센서')).toBeInTheDocument();
    expect(within(firstItem).getByText(LAB_NAME)).toBeInTheDocument();
    expect(within(firstItem).getByText('2026-11-18 09:52:00')).toBeInTheDocument();
    expect(within(firstItem).getByText('신규')).toBeInTheDocument();
    const ongoingItem = items.find((li) => within(li).queryByText('10.0.59.1'));
    expect(ongoingItem && within(ongoingItem).getByText('진행 중')).toBeInTheDocument();
  });
});

describe('목록 밀도(T23 7절)', () => {
  const hidden2xl = (el: HTMLElement) => el.className.split(/\s+/).includes('hidden') && el.className.includes('2xl:table-cell');

  it('1536px 미만에서 통신 방향·세션 수는 숨김 클래스를 쓰지만, 지금 정렬 기준인 열(세션 수)에는 붙이지 않는다', async () => {
    const first = renderQueue();
    await ready();
    const conn = header(/세션 수 기준 정렬/);
    expect(hidden2xl(conn)).toBe(true);
    const roleTh = within(screen.getByRole('table')).getAllByRole('columnheader').find((h) => h.textContent?.trim() === '통신 방향') as HTMLElement;
    expect(hidden2xl(roleTh)).toBe(true);
    first.unmount();

    renderQueue('/incidents?sort=connections&dir=desc');
    await ready();
    const sortedTh = header(/세션 수 기준 정렬/);
    expect(sortedTh.className.split(/\s+/)).not.toContain('hidden');
    const firstRow = within(screen.getByRole('table')).getAllByRole('row')[1];
    const connCell = firstRow.querySelector('[data-col="connections"]') as HTMLElement;
    expect(connCell.className.split(/\s+/)).not.toContain('hidden');
  });

  it.each(['priority', 'detected', 'start', 'status'])('정렬 기준 %s 열에는 숨김 클래스가 없다', async (key) => {
    renderQueue(`/incidents?sort=${key}`);
    await ready();
    const th = within(screen.getByRole('table'))
      .getAllByRole('columnheader')
      .find((h) => h.getAttribute('aria-sort') !== 'none') as HTMLElement;
    expect(th).toBeDefined();
    expect(th.className.split(/\s+/)).not.toContain('hidden');
  });

  it('행의 칸은 한 줄(줄바꿈 없음)이고 긴 자산 이름은 말줄임·툴팁이다', async () => {
    const long = unified({ ...base(1), hostName: ['very-long-asset-name-for-t23-density-check.corp.example.local', 'second'] }, { priority: 'high' });
    renderQueue('/incidents', { items: [long] });
    await ready();
    const row = within(screen.getByRole('table')).getAllByRole('row')[1];
    for (const td of within(row).getAllByRole('cell')) {
      expect(td.className).toContain('soc-td-compact');
    }
    const name = within(row).getByText('very-long-asset-name-for-t23-density-check.corp.example.local');
    expect(name.className).toContain('truncate');
    expect(name).toHaveAttribute('title', 'very-long-asset-name-for-t23-density-check.corp.example.local, second');
    expect(within(row).getByLabelText(/^수집원: /).className).toMatch(/max-w-/);
  });
});

describe('빈 결과(T23)', () => {
  it('기간 안에 0건이고 기간 밖에 있으면 가장 최근 탐지 시각과 [기간: 전체로 보기]를 보인다', async () => {
    const user = userEvent.setup();
    renderQueue('/incidents', {
      periodFilter: (_i, period) => period === 'all',
      newestOutsidePeriod: '2026-11-19T02:05:00Z',
    });
    await screen.findByText(/이 기간에 탐지된 인시던트가 없습니다/);
    expect(screen.getByText(/가장 최근 탐지:/)).toHaveTextContent('가장 최근 탐지: 2026-11-19 11:05:00');
    expect(screen.queryByRole('button', { name: /필터 초기화/, hidden: false })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '기간: 전체로 보기' }));
    expect(params().get('period')).toBe('all');
    await ready();
    expect(tableIds()).toHaveLength(50);
  });

  it('거르기 때문에 0건이면 필터 초기화를 안내한다', async () => {
    renderQueue('/incidents?period=all&asset=nothing-matches');
    await screen.findByText('조건에 맞는 인시던트가 없습니다. 필터를 줄이거나 [필터 초기화]를 누르세요.');
    expect(screen.queryByText(/이 기간에 탐지된 인시던트가 없습니다/)).toBeNull();
  });
});

describe('새 인시던트 띠·자동 갱신(T23)', () => {
  /** 첫 응답 뒤 자동 갱신 타이머가 걸릴 때까지 기다린다(효과는 표가 그려진 뒤에 돈다). */
  async function pollArmed() {
    await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
  }

  function setVisibility(state: 'visible' | 'hidden') {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
    document.dispatchEvent(new Event('visibilitychange'));
  }

  it('60초마다 new-count를 since(마지막 응답의 최근 탐지 시각)로 부르고, 1건 이상이면 띠를 보인다. 목록 행은 스스로 바뀌지 않는다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    let items = ITEMS.slice(0, 40);
    const { newCountCalls } = renderQueue('/incidents', { newItems: () => items });
    await ready();
    await pollArmed();
    const before = tableIds();
    expect(newCountCalls).toHaveLength(0);

    items = ITEMS.slice(0, 43); // 41·42·43이 새로 탐지됨
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await waitFor(() => expect(newCountCalls).toHaveLength(1));
    const sent = new URLSearchParams(newCountCalls[0].split('?')[1]);
    // since = 처음 응답의 latestDetectedAt(40번 탐지 시각). 기간·정렬·쪽은 보내지 않는다
    expect(sent.get('since')).toBe(ITEMS[39].detectedAt);
    expect(sent.get('period')).toBeNull();
    expect(sent.get('sort')).toBeNull();
    expect(sent.get('page')).toBeNull();
    const banner = await screen.findByText('새 인시던트 3건');
    expect(banner).toBeInTheDocument();
    expect(tableIds()).toEqual(before);
  });

  it('화면이 숨겨지면 멈추고, 다시 보이면 곧바로 한 번 부른다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const { newCountCalls } = renderQueue();
    await ready();
    await pollArmed();
    act(() => setVisibility('hidden'));
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS * 3);
    });
    expect(newCountCalls).toHaveLength(0);
    act(() => setVisibility('visible'));
    await waitFor(() => expect(newCountCalls).toHaveLength(1));
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await waitFor(() => expect(newCountCalls).toHaveLength(2));
  });

  it('[불러오기]를 누르면 탐지 시각 최근순 1쪽을 다시 부르고, 새로 들어온 행에 "새" 표지를 다음 불러오기 전까지 붙인다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    let items = ITEMS.slice(0, 40);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const { queueCalls } = renderQueue('/incidents?page=1&period=all', { newItems: () => items });
    await ready();
    await pollArmed();
    items = ITEMS.slice(0, 42);
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await user.click(await screen.findByRole('button', { name: '불러오기' }));
    expect(params().get('sort')).toBe('detected');
    expect(params().get('dir')).toBe('desc');
    expect(params().get('page')).toBeNull();
    await waitFor(() => expect(lastCall(queueCalls).get('sort')).toBe('detected'));
    await waitFor(() => expect(tableIds().slice(0, 3)).toEqual([42, 41, 40]));
    const table = screen.getByRole('table');
    const newRows = within(table).getAllByText('새').map((el) => el.closest('tr'));
    expect(newRows).toHaveLength(2);
    expect(within(newRows[0] as HTMLElement).getByText('10.0.42.1')).toBeInTheDocument();
    expect(screen.queryByText(/새 인시던트 \d+건/)).toBeNull();
    // 다음 불러오기(정렬 변경)에서는 표지가 사라진다
    await user.click(screen.getByRole('button', { name: /세션 수 기준 정렬/ }));
    await waitFor(() => expect(lastCall(queueCalls).get('sort')).toBe('connections'));
    await waitFor(() => expect(within(screen.getByRole('table')).queryAllByText('새')).toHaveLength(0));
  });

  it('고정 스냅샷이면 부르지 않고 "고정 스냅샷 · 자동 갱신 꺼짐"을 보인다. 진행 중 툴팁은 기준 시각 기준이다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setVisibility('visible');
    const { newCountCalls } = renderQueue('/incidents', { snapshot: true });
    await ready();
    expect(screen.getByText('고정 스냅샷 · 자동 갱신 꺼짐')).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS * 2);
    });
    act(() => setVisibility('visible'));
    expect(newCountCalls).toHaveLength(0);
    const row59 = within(screen.getByRole('table')).getByText('10.0.59.1').closest('tr') as HTMLElement;
    expect(within(row59).getByText('진행 중').closest('[title]')).toHaveAttribute(
      'title',
      expect.stringContaining('기준 시각 기준'),
    );
  });

  it('now 모드에서는 조건 줄에 고정 스냅샷 표시가 없다', async () => {
    renderQueue();
    await ready();
    expect(screen.queryByText('고정 스냅샷 · 자동 갱신 꺼짐')).toBeNull();
  });
});

describe('옛 용어 회귀(T23)', () => {
  it('목록 화면에 캡처 선택·탐지 작업 선택·순위 열이 없다', async () => {
    renderQueue('/incidents?captureId=cic17-wed');
    await ready();
    expect(screen.queryByLabelText('캡처')).toBeNull();
    expect(screen.queryByLabelText('탐지 작업')).toBeNull();
    const headers = within(screen.getByRole('table')).getAllByRole('columnheader').map((h) => h.textContent?.trim());
    expect(headers).not.toContain('순위');
    expect(document.body.textContent).not.toMatch(/탐지 작업 #/);
    expect(document.body.textContent).not.toMatch(/\d+위/);
  });
});
