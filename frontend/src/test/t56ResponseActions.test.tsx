import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ActionPanel } from '../components/incident/ActionPanel';
import { buildTimeline } from '../components/incident/HistoryTimeline';
import { ToastProvider } from '../components/ToastContext';
import type { AssignmentHistoryItem, IncidentDetailView, ResponseActionItem } from '../types/api';
import { formatDateTime } from '../utils/format';
import { incidentMarkdown } from '../utils/incidentExport';
import { labelText, lookupLabel } from '../utils/labels';
import { baseDetail, DEFAULT_META } from './detailFixture';

/**
 * T56 대응 조치 기록: 조치 패널의 "대응 조치" 칸(분석가·신규·조회자), 메모 필수 조건, 기록 뒤 다시 읽기,
 * 정탐 + 기록 0건일 때 종결 막힘과 안내, 이력·마크다운 요약, 값이 최신이 아닐 때 막힘. 모의 서버(fetch 대역)로 본다.
 */

const REQUIRED_TEXT = "정탐으로 종결하려면 대응 조치를 먼저 기록하세요. 조치가 없었다면 '조치 없음'을 기록하세요.";
const VIEWER_NOTICE =
  '읽기 전용 계정입니다. 담당 지정·대응 조치 기록·상태 변경·에스컬레이션 결정은 분석가 계정에서 할 수 있습니다.';
const PATH = '/api/incidents/42/rank/1';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const userOf = (role: 'VIEWER' | 'ANALYST') => ({
  username: role === 'VIEWER' ? 'demo' : 'analyst1',
  displayName: role === 'VIEWER' ? '공개 데모' : '분석가1',
  role,
  maskedView: role === 'VIEWER',
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
});

const action = (overrides: Partial<ResponseActionItem> = {}): ResponseActionItem => ({
  action: 'block_ip',
  note: '방화벽 담당에 172.16.0.1 차단 요청',
  actorDisplay: '분석가1 (analyst1)',
  recordedAt: '2026-11-20T03:00:00Z',
  ...overrides,
});

const openDetail = (d: IncidentDetailView): IncidentDetailView => ({
  ...d,
  currentStatus: 'open',
  nextAllowedStatus: 'investigating',
});
const closedDetail = (d: IncidentDetailView): IncidentDetailView => ({
  ...d,
  currentStatus: 'closed',
  currentResolution: 'true_positive',
  nextAllowedStatus: null,
});

interface Setup {
  role?: 'VIEWER' | 'ANALYST';
  detail?: (d: IncidentDetailView) => IncidentDetailView;
  /** undefined면 응답에 responseActions·canRecordResponse를 싣지 않는다(옛 응답) */
  responseActions?: ResponseActionItem[];
  canRecordResponse?: boolean;
  assignmentHistory?: AssignmentHistoryItem[];
  postResponse?: (url: string) => Response | undefined;
}

function renderDetail(path: string, setup: Setup = {}) {
  document.cookie = 'XSRF-TOKEN=t56-test-token; path=/';
  const role = setup.role ?? 'ANALYST';
  const state = {
    detail: (setup.detail ?? ((d) => d))(baseDetail()),
    responseActions: setup.responseActions,
  };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (init?.method === 'POST') {
      const custom = setup.postResponse?.(url);
      if (custom) return custom;
      const body = init.body ? (JSON.parse(String(init.body)) as { action?: string; note?: string | null }) : {};
      if (url.endsWith('/response-actions')) {
        state.responseActions = [
          action({ action: body.action ?? '', note: body.note ?? null, recordedAt: '2026-11-21T01:00:00Z' }),
          ...(state.responseActions ?? []),
        ];
        return json({ succeeded: true, code: 'OK', message: '대응 조치를 기록했습니다. 조치: 조치 없음' });
      }
      return json({ succeeded: true, code: 'OK', message: '처리했습니다' });
    }
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
    if (m) {
      const d = state.detail;
      const extra =
        state.responseActions === undefined
          ? {}
          : {
              // 서버는 조회자에게 메모를 내리지 않는다
              responseActions:
                role === 'VIEWER' ? state.responseActions.map((a) => ({ ...a, note: null })) : state.responseActions,
              canRecordResponse: setup.canRecordResponse ?? (role !== 'VIEWER' && d.currentStatus !== 'open'),
            };
      return json({
        maskedView: role === 'VIEWER',
        canDecideReview: role !== 'VIEWER',
        detail: { ...d, incident: { ...d.incident, jobId: Number(m[1]), queueRank: Number(m[2]) } },
        queueMeta: DEFAULT_META,
        assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
        assignmentHistory: setup.assignmentHistory ?? [],
        canAssign: role !== 'VIEWER' && d.currentStatus !== 'closed',
        // incidentNo는 싣지 않는다(있으면 화면이 번호 주소로 옮겨 가 위치 조회를 한다. 이 시험이 보는 것이 아니다)
        ...extra,
      });
    }
    if (url.startsWith('/api/incidents/queue/neighbors')) {
      return json({ current: null, position: null, total: 0, prev: null, next: null });
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  const utils = render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { ...utils, fetchMock };
}

const actions = () => screen.getByRole('region', { name: '조치' });
const responseArea = () => within(actions()).getByRole('group', { name: '대응 조치' });
const transitionForm = () => within(actions()).getByRole('form', { name: '상태 변경' });
const closeButton = () => within(transitionForm()).getByRole('button', { name: '종결 처리' });
const recordButton = () => within(responseArea()).getByRole('button', { name: '조치 기록' });
const posts = (fetchMock: ReturnType<typeof vi.fn>, path: string) =>
  fetchMock.mock.calls.filter(([u, i]) => u === path && (i as RequestInit | undefined)?.method === 'POST');
const detailGets = (fetchMock: ReturnType<typeof vi.fn>) =>
  fetchMock.mock.calls.filter(([u, i]) => u === PATH && (i as RequestInit | undefined)?.method !== 'POST').length;
const ready = () => screen.findByRole('tab', { name: '요약', selected: true });

describe('T56 조치 패널의 "대응 조치" 칸', () => {
  it('분석가·분석 중: 담당 칸과 상태 변경 폼 사이에 칸이 있고 기록이 없으면 빈 문구와 기록 폼을 보인다', async () => {
    const { container } = renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    const g = responseArea();
    expect(within(g).getByRole('heading', { name: '대응 조치' })).toBeInTheDocument();
    expect(within(g).getByText('기록 0건')).toBeInTheDocument();
    expect(within(g).getByText('기록된 대응 조치가 없습니다.')).toBeInTheDocument();
    // 순서: 담당 → 대응 조치 → 상태 변경
    const assignment = within(actions()).getByRole('group', { name: '담당' });
    expect(assignment.compareDocumentPosition(g) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(g.compareDocumentPosition(transitionForm()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // 종류 일곱(표시 이름)과 고르기 전 빈 값
    const select = within(g).getByLabelText('조치 종류 (필수)');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual([
      '조치 종류 고르기',
      'IP 차단',
      '호스트 격리',
      '사용자 계정 잠금·비밀번호 초기화',
      '침해사고 대응팀 이관',
      '모니터링 강화',
      '조치 없음',
      '기타',
    ]);
    // 이 콘솔은 기록만 한다(차단·격리 실행 버튼이 없다)
    expect(within(g).getByText('실제 차단·격리는 해당 장비에서 하고 여기에는 한 일을 기록합니다.')).toBeInTheDocument();
    expect(within(g).getAllByRole('button').map((b) => b.textContent)).toEqual(['조치 기록']);
    // 패널 이름 "조치"는 하나뿐이다(새 칸의 이름과 겹치지 않는다)
    expect(screen.getAllByRole('region', { name: '조치' })).toHaveLength(1);
    expect(container.querySelector('[style]')).toBeNull();
  });

  it('메모는 종류가 "조치 없음"·"기타"일 때만 필수다. 종류를 고르지 않으면 기록할 수 없다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    const g = responseArea();
    const select = within(g).getByLabelText('조치 종류 (필수)');
    expect(recordButton()).toBeDisabled();
    expect(within(g).getByLabelText('메모 (선택)')).toHaveAttribute('maxlength', '500');

    await user.selectOptions(select, 'block_ip');
    expect(recordButton()).toBeEnabled();

    for (const kind of ['none', 'other']) {
      await user.selectOptions(select, kind);
      const note = within(g).getByLabelText('메모 (필수)');
      expect(recordButton()).toBeDisabled();
      await user.type(note, '   ');
      expect(recordButton()).toBeDisabled();
      await user.type(note, '사유');
      expect(recordButton()).toBeEnabled();
      await user.clear(note);
    }
    await user.selectOptions(select, 'monitor');
    expect(within(g).getByLabelText('메모 (선택)')).toBeInTheDocument();
    expect(recordButton()).toBeEnabled();
  });

  it('기록하면 종류와 메모를 보내고 서버 메시지를 토스트로 띄운 뒤 상세를 다시 읽는다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    const before = detailGets(fetchMock);
    const g = responseArea();
    await user.selectOptions(within(g).getByLabelText('조치 종류 (필수)'), 'none');
    await user.type(within(g).getByLabelText('메모 (필수)'), '  실습 트래픽으로 확인돼 차단하지 않음  ');
    await user.click(recordButton());

    const calls = posts(fetchMock, `${PATH}/response-actions`);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String((calls[0][1] as RequestInit).body))).toEqual({
      action: 'none',
      note: '실습 트래픽으로 확인돼 차단하지 않음',
    });
    expect(await screen.findByText('대응 조치를 기록했습니다. 조치: 조치 없음')).toBeInTheDocument();
    await waitFor(() => expect(detailGets(fetchMock)).toBe(before + 1));
    // 다시 읽은 값: 기록 1건, 조치 라벨·메모·기록자·기록 시각
    await waitFor(() => expect(within(responseArea()).getByText('기록 1건')).toBeInTheDocument());
    const latest = within(responseArea()).getByTestId('response-latest');
    expect(within(latest).getByText('조치 없음')).toBeInTheDocument();
    expect(within(latest).getByText('실습 트래픽으로 확인돼 차단하지 않음')).toBeInTheDocument();
    expect(latest).toHaveTextContent('기록자 분석가1 (analyst1)');
    expect(latest).toHaveTextContent(`기록 ${formatDateTime('2026-11-21T01:00:00Z')}`);
    // 폼은 비워진다
    expect(within(responseArea()).getByLabelText('조치 종류 (필수)')).toHaveValue('');
    expect(within(responseArea()).getByLabelText('메모 (선택)')).toHaveValue('');
  });

  it('메모 없이 기록하면 note는 null로 보낸다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    await user.selectOptions(within(responseArea()).getByLabelText('조치 종류 (필수)'), 'isolate_host');
    await user.click(recordButton());
    const calls = posts(fetchMock, `${PATH}/response-actions`);
    expect(JSON.parse(String((calls[0][1] as RequestInit).body))).toEqual({ action: 'isolate_host', note: null });
  });

  it('여러 건이면 기록 수와 가장 최근 1건만 칸에 보인다(나머지는 이력에서)', async () => {
    renderDetail('/incidents/42/rank/1', {
      responseActions: [
        action({ action: 'handover', note: 'CERT에 이관(최신)', recordedAt: '2026-11-20T05:00:00Z' }),
        action({ action: 'isolate_host', note: '단말 격리 요청(중간)', recordedAt: '2026-11-20T04:00:00Z' }),
        action({ action: 'block_ip', note: '차단 요청(처음)', recordedAt: '2026-11-20T03:00:00Z' }),
      ],
    });
    await ready();
    const g = responseArea();
    expect(within(g).getByText('기록 3건')).toBeInTheDocument();
    expect(within(g).getAllByTestId('response-latest')).toHaveLength(1);
    const latest = within(g).getByTestId('response-latest');
    expect(within(latest).getByText('침해사고 대응팀 이관')).toBeInTheDocument();
    expect(within(latest).getByText('CERT에 이관(최신)')).toBeInTheDocument();
    expect(within(g).queryByText('단말 격리 요청(중간)')).toBeNull();
    expect(within(g).queryByText('차단 요청(처음)')).toBeNull();
    expect(within(g).getByText('이전 기록 2건은 이력 탭에서 볼 수 있습니다.')).toBeInTheDocument();
  });

  it('신규(착수 전): 폼 대신 안내 문장을 보인다', async () => {
    renderDetail('/incidents/42/rank/1', { detail: openDetail, responseActions: [] });
    await ready();
    const g = responseArea();
    expect(within(g).getByText('착수한 뒤(분석 중) 기록할 수 있습니다.')).toBeInTheDocument();
    expect(within(g).queryByRole('combobox')).toBeNull();
    expect(within(g).queryByRole('textbox')).toBeNull();
    expect(within(g).queryByRole('button', { name: '조치 기록' })).toBeNull();
  });

  it('종결된 인시던트에도 기록 폼이 있다(뒤늦은 조치)', async () => {
    renderDetail('/incidents/42/rank/1', { detail: closedDetail, responseActions: [action()] });
    await ready();
    expect(within(responseArea()).getByLabelText('조치 종류 (필수)')).toBeInTheDocument();
    expect(recordButton()).toBeDisabled();
  });

  it('조회자: 기록 수와 최근 1건의 종류·기록자·시각만 보이고 메모와 폼은 없다. 안내 문장에 "대응 조치 기록"이 있다', async () => {
    const { container } = renderDetail('/incidents/42/rank/1', {
      role: 'VIEWER',
      detail: (d) => ({ ...d, canTransition: false, nextAllowedStatus: null, analystReview: { ...d.analystReview, canDecide: false } }),
      responseActions: [
        action({ action: 'lock_account', note: 'j.kim 계정 잠금', recordedAt: '2026-11-20T05:00:00Z' }),
        action({ note: '차단 요청', recordedAt: '2026-11-20T03:00:00Z' }),
      ],
    });
    await ready();
    const g = responseArea();
    expect(within(g).getByText('기록 2건')).toBeInTheDocument();
    const latest = within(g).getByTestId('response-latest');
    expect(within(latest).getByText('사용자 계정 잠금·비밀번호 초기화')).toBeInTheDocument();
    expect(latest).toHaveTextContent('기록자 분석가1 (analyst1)');
    expect(latest).toHaveTextContent(`기록 ${formatDateTime('2026-11-20T05:00:00Z')}`);
    expect(container.textContent).not.toContain('j.kim');
    expect(container.textContent).not.toContain('차단 요청');
    expect(within(actions()).queryByRole('textbox')).toBeNull();
    expect(within(actions()).queryByRole('combobox')).toBeNull();
    expect(within(g).queryByRole('button')).toBeNull();
    expect(within(g).queryByText('착수한 뒤(분석 중) 기록할 수 있습니다.')).toBeNull();
    expect(within(actions()).getByText(VIEWER_NOTICE)).toBeInTheDocument();
  });

  it('서버가 409로 거부하면 서버 문장을 보이고 상세를 다시 읽는다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', {
      responseActions: [],
      postResponse: (url) =>
        url.endsWith('/response-actions')
          ? json({ succeeded: false, code: 'INCIDENT_NOT_STARTED', message: '착수한 뒤(분석 중) 대응 조치를 기록할 수 있습니다.' }, 409)
          : undefined,
    });
    await ready();
    const before = detailGets(fetchMock);
    await user.selectOptions(within(responseArea()).getByLabelText('조치 종류 (필수)'), 'block_ip');
    await user.click(recordButton());
    expect(await within(responseArea()).findByRole('alert')).toHaveTextContent(
      '착수한 뒤(분석 중) 대응 조치를 기록할 수 있습니다.',
    );
    await waitFor(() => expect(detailGets(fetchMock)).toBe(before + 1));
  });

  it('값이 최신이 아니면(blockedReason) 다른 버튼처럼 조치 기록 버튼도 막는다', async () => {
    const user = userEvent.setup();
    const props = {
      detail: baseDetail(),
      readOnly: false,
      onRefresh: async () => {},
      onShowHistory: () => {},
      canAssign: true,
      currentUsername: 'analyst1',
      responseActions: [] as ResponseActionItem[],
      canRecordResponse: true,
    };
    const { rerender, container } = render(
      <ToastProvider>
        <ActionPanel {...props} blockedReason="최신 값을 불러온 뒤 조치할 수 있습니다" />
      </ToastProvider>,
    );
    await user.selectOptions(within(responseArea()).getByLabelText('조치 종류 (필수)'), 'block_ip');
    expect(recordButton()).toBeDisabled();
    expect(recordButton()).toHaveAttribute('title', '최신 값을 불러온 뒤 조치할 수 있습니다');
    rerender(
      <ToastProvider>
        <ActionPanel {...props} blockedReason={null} />
      </ToastProvider>,
    );
    expect(recordButton()).toBeEnabled();
    expect(container.querySelector('[style]')).toBeNull();
  });
});

describe('T56 정탐 종결에는 대응 조치 기록이 필요하다', () => {
  it('종결 + 정탐 + 기록 0건: 제출 버튼을 막고 버튼 위에 안내를 보인다. 판정을 오탐·정상으로 바꾸면 풀린다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    const form = transitionForm();
    await user.type(within(form).getByLabelText('변경 사유 (필수)'), '정탐 확정');
    expect(within(form).getByLabelText('판정 (필수)')).toHaveValue('true_positive');
    expect(closeButton()).toBeDisabled();
    const note = within(form).getByRole('note', { name: '정탐 종결 안내' });
    expect(note).toHaveTextContent(REQUIRED_TEXT);
    // 안내는 버튼 위에 있다
    expect(note.compareDocumentPosition(closeButton()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    for (const value of ['false_positive', 'benign']) {
      await user.selectOptions(within(form).getByLabelText('판정 (필수)'), value);
      expect(closeButton()).toBeEnabled();
      expect(within(form).queryByRole('note', { name: '정탐 종결 안내' })).toBeNull();
    }
    await user.selectOptions(within(form).getByLabelText('판정 (필수)'), 'true_positive');
    expect(closeButton()).toBeDisabled();
    expect(posts(fetchMock, `${PATH}/transition`)).toHaveLength(0);
  });

  it('"조치 없음"을 기록하면 막힘이 풀려 정탐으로 종결할 수 있다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', { responseActions: [] });
    await ready();
    await user.type(within(transitionForm()).getByLabelText('변경 사유 (필수)'), '정탐 확정');
    expect(closeButton()).toBeDisabled();
    await user.selectOptions(within(responseArea()).getByLabelText('조치 종류 (필수)'), 'none');
    await user.type(within(responseArea()).getByLabelText('메모 (필수)'), '차단할 대상이 없음');
    await user.click(recordButton());
    await waitFor(() => expect(closeButton()).toBeEnabled());
    expect(within(transitionForm()).queryByRole('note', { name: '정탐 종결 안내' })).toBeNull();
    await user.click(closeButton());
    const calls = posts(fetchMock, `${PATH}/transition`);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String((calls[0][1] as RequestInit).body))).toEqual({
      toStatus: 'closed',
      resolution: 'true_positive',
      reason: '정탐 확정',
    });
  });

  it('기록이 1건 이상이면 처음부터 막지 않는다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1', { responseActions: [action()] });
    await ready();
    await user.type(within(transitionForm()).getByLabelText('변경 사유 (필수)'), '정탐 확정');
    expect(closeButton()).toBeEnabled();
    expect(within(transitionForm()).queryByRole('note', { name: '정탐 종결 안내' })).toBeNull();
  });

  it('응답에 responseActions가 없으면(옛 응답) 화면은 막지 않고 서버가 막게 둔다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1', {
      postResponse: (url) =>
        url.endsWith('/transition') ? json({ succeeded: false, code: 'RESPONSE_ACTION_REQUIRED', message: REQUIRED_TEXT }, 409) : undefined,
    });
    await ready();
    await user.type(within(transitionForm()).getByLabelText('변경 사유 (필수)'), '정탐 확정');
    expect(closeButton()).toBeEnabled();
    expect(within(transitionForm()).queryByRole('note', { name: '정탐 종결 안내' })).toBeNull();
    await user.click(closeButton());
    expect(await within(transitionForm()).findByRole('alert')).toHaveTextContent(REQUIRED_TEXT);
  });

  it('착수(신규 → 분석 중) 전이는 기록 수와 상관없다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1', { detail: openDetail, responseActions: [] });
    await ready();
    await user.type(within(transitionForm()).getByLabelText('변경 사유 (필수)'), '착수');
    expect(within(transitionForm()).getByRole('button', { name: '분석 중으로 변경' })).toBeEnabled();
  });
});

describe('T56 이력과 마크다운 요약', () => {
  const review = { ...baseDetail().analystReview, present: false };
  const assignmentItem: AssignmentHistoryItem = {
    jobId: 42,
    from: null,
    to: { username: 'analyst1', displayName: '분석가1', enabled: true },
    actorDisplay: '분석가1 (analyst1)',
    reason: 'manual',
    changedAt: '2026-11-20T03:00:00Z',
  };

  it('buildTimeline: 대응 조치를 시각순으로 섞고 같은 시각이면 담당 다음에 둔다', () => {
    const history = baseDetail().statusHistory;
    const events = buildTimeline(
      [{ ...history[1], changedAt: '2026-11-20T03:00:00Z' }],
      review,
      [assignmentItem],
      // 서버는 시간 역순으로 준다
      [action({ action: 'none', note: '나중', recordedAt: '2026-11-20T04:00:00Z' }), action({ recordedAt: '2026-11-20T03:00:00Z' })],
    );
    expect(events.map((e) => e.kind)).toEqual(['status', 'assignment', 'response', 'response']);
    const responses = events.filter((e) => e.kind === 'response');
    expect(responses.map((e) => (e.kind === 'response' ? e.item.action : ''))).toEqual(['block_ip', 'none']);
    // 넷째 인자가 없으면 지금과 같다
    expect(buildTimeline(history, review, [assignmentItem]).map((e) => e.kind)).toEqual(['status', 'status', 'assignment']);
  });

  it('이력 탭과 패널의 최근 이력에 "대응 조치 · <라벨>"과 메모·기록자로 보인다', async () => {
    renderDetail('/incidents/42/rank/1?tab=history', {
      responseActions: [action({ action: 'isolate_host', note: 'EDR 담당에 단말 격리 요청' })],
    });
    await screen.findByRole('tab', { name: '이력', selected: true });
    const panel = screen.getByRole('tabpanel');
    const item = within(panel).getByText('대응 조치 · 호스트 격리').closest('li');
    expect(item).not.toBeNull();
    expect(item).toHaveTextContent('EDR 담당에 단말 격리 요청');
    expect(item).toHaveTextContent('기록자 분석가1 (analyst1)');
    expect(item).toHaveTextContent(formatDateTime('2026-11-20T03:00:00Z'));
    const recent = within(actions()).getByRole('list', { name: '최근 이력' });
    expect(within(recent).getByText('대응 조치 · 호스트 격리')).toBeInTheDocument();
    expect(within(actions()).getByRole('button', { name: '전체 이력 4건' })).toBeInTheDocument();
  });

  it('조회자의 이력에는 종류와 기록자만 있고 메모 줄이 없다', async () => {
    renderDetail('/incidents/42/rank/1?tab=history', {
      role: 'VIEWER',
      detail: (d) => ({ ...d, canTransition: false, nextAllowedStatus: null }),
      responseActions: [action({ action: 'lock_account', note: 'j.kim 계정 잠금' })],
    });
    await screen.findByRole('tab', { name: '이력', selected: true });
    const item = within(screen.getByRole('tabpanel')).getByText('대응 조치 · 사용자 계정 잠금·비밀번호 초기화').closest('li');
    expect(item).toHaveTextContent('기록자 분석가1 (analyst1)');
    expect(item).not.toHaveTextContent('메모');
    expect(document.body.textContent).not.toContain('j.kim');
  });

  it('이력이 하나도 없을 때의 빈 문구에 "대응 조치"가 있다', async () => {
    renderDetail('/incidents/42/rank/1?tab=history', {
      detail: (d) => ({ ...d, statusHistory: [], analystReview: { ...d.analystReview, present: false } }),
      responseActions: [],
    });
    await screen.findByRole('tab', { name: '이력', selected: true });
    expect(
      within(screen.getByRole('tabpanel')).getByText('아직 상태 변경·에스컬레이션·담당·대응 조치 이력이 없습니다.'),
    ).toBeInTheDocument();
  });

  it('incidentMarkdown: "대응 조치" 항목을 시각순으로 싣고 메모는 마크다운 기호를 이스케이프해 한 줄로 편다', () => {
    const md = incidentMarkdown(baseDetail(), DEFAULT_META, 7, [
      action({ action: 'none', note: '조치하지 않음:\n# 제목 *강조* <b>굵게</b>', recordedAt: '2026-11-20T04:00:00Z' }),
      action({ action: 'block_ip', note: null, recordedAt: '2026-11-20T03:00:00Z' }),
    ]);
    const section = md.slice(md.indexOf('## 대응 조치'));
    expect(section.split('\n').slice(0, 3)).toEqual([
      '## 대응 조치',
      `- IP 차단 (기록 ${formatDateTime('2026-11-20T03:00:00Z')} KST)`,
      `- 조치 없음 (기록 ${formatDateTime('2026-11-20T04:00:00Z')} KST): 조치하지 않음: # 제목 \\*강조\\* \\<b\\>굵게\\</b\\>`,
    ]);
    // 기록이 없으면 "기록 없음", 값이 없으면(옛 응답) 항목 자체가 없다
    expect(incidentMarkdown(baseDetail(), DEFAULT_META, 7, [])).toContain('## 대응 조치\n- 기록 없음\n');
    expect(incidentMarkdown(baseDetail(), DEFAULT_META, 7)).not.toContain('대응 조치');
  });

  it('헤더 "요약 복사"는 화면이 받은 조치 기록을 싣는다(조회자는 메모 없이)', async () => {
    for (const role of ['ANALYST', 'VIEWER'] as const) {
      const user = userEvent.setup();
      const items = [action({ action: 'lock_account', note: 'j.kim 계정 잠금' })];
      const view = renderDetail('/incidents/42/rank/1', {
        role,
        detail: role === 'VIEWER' ? (d) => ({ ...d, canTransition: false, nextAllowedStatus: null }) : undefined,
        responseActions: items,
      });
      await ready();
      await user.click(screen.getByRole('button', { name: '요약 복사' }));
      await screen.findByText('인시던트 요약을 복사했습니다.');
      const copied = await navigator.clipboard.readText();
      const line = `- 사용자 계정 잠금·비밀번호 초기화 (기록 ${formatDateTime('2026-11-20T03:00:00Z')} KST)`;
      expect(copied).toContain(role === 'VIEWER' ? `${line}\n` : `${line}: j.kim 계정 잠금\n`);
      if (role === 'VIEWER') expect(copied).not.toContain('j.kim');
      view.unmount();
    }
  });

  it('표시 이름: 조치 종류 일곱과 감사 유형 "대응 조치 기록"', () => {
    expect(
      ['block_ip', 'isolate_host', 'lock_account', 'handover', 'monitor', 'none', 'other'].map((v) => labelText('responseAction', v)),
    ).toEqual([
      'IP 차단',
      '호스트 격리',
      '사용자 계정 잠금·비밀번호 초기화',
      '침해사고 대응팀 이관',
      '모니터링 강화',
      '조치 없음',
      '기타',
    ]);
    expect(lookupLabel('responseAction', 'shutdown').known).toBe(false);
    expect(labelText('auditAction', 'INCIDENT_RESPONSE_ACTION')).toBe('대응 조치 기록');
  });
});
