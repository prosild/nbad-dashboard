import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ActionPanel } from '../components/incident/ActionPanel';
import { buildTimeline, HistoryTimeline } from '../components/incident/HistoryTimeline';
import { ToastProvider } from '../components/ToastContext';
import type { AnalystReviewView, IncidentDetailView, StatusHistoryItem } from '../types/api';
import { RESUME_MANUAL_CLOSE_TEXT } from '../utils/reviewResume';
import { baseDetail, DEFAULT_META } from './detailFixture';

/**
 * T53 다시 열기: 종결 건의 조치 패널 문구와 "다시 열기" 폼(분석가·관리자, 서버 값 canReopen), 보내는 값(화면의 판정 포함),
 * 409·501 문장, 값이 최신이 아닐 때 막힘, 이력의 "다시 열림" 표지, 오탐 종결 결정 뒤 사람이 다시 연 건에서
 * "직접 종결" 안내와 오탐 미리 채움이 뜨지 않음. 모의 서버(fetch 대역)로 본다.
 */

const PATH = '/api/incidents/42/rank/1';
const CLOSED_TEXT = '종결된 인시던트입니다.';
const REOPEN_NOTE = '다시 열면 상태가 분석 중으로 돌아가고 판정이 비워집니다. 앞선 종결과 판정은 이력에 남습니다.';
const ASSIGN_NOTE = '담당자가 없으면 다시 연 사람이 담당자로 지정됩니다.';
const CONFLICT_TEXT = '다른 사람이 먼저 상태나 판정을 바꿨습니다. 새로고침한 뒤 다시 확인하세요.';
const UNAVAILABLE_TEXT = '이 환경의 탐지 DB에는 다시 열기 기능이 아직 없습니다.';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const userOf = (role: 'VIEWER' | 'ANALYST' | 'ADMIN') => ({
  username: role === 'VIEWER' ? 'demo' : 'analyst1',
  displayName: role === 'VIEWER' ? '공개 데모' : '분석가1',
  role,
  maskedView: role === 'VIEWER',
  totpEnabled: role === 'ADMIN',
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
});

const closingHistory: StatusHistoryItem[] = [
  {
    jobId: 42,
    fromStatus: 'open',
    toStatus: 'investigating',
    resolution: null,
    actorDisplay: '분석가1 (analyst1)',
    reason: '조사 시작',
    changedAt: '2026-11-18T02:00:00Z',
  },
  {
    jobId: 42,
    fromStatus: 'investigating',
    toStatus: 'closed',
    resolution: 'false_positive',
    actorDisplay: '분석가1 (analyst1)',
    reason: '업무용 스캐너로 확인',
    changedAt: '2026-11-18T03:00:00Z',
  },
];

const reopenRow = (changedAt: string): StatusHistoryItem => ({
  jobId: 42,
  fromStatus: 'closed',
  toStatus: 'investigating',
  resolution: null,
  actorDisplay: '분석가2 (analyst2)',
  reason: '같은 대역에서 다시 보임',
  changedAt,
});

const closedDetail = (d: IncidentDetailView): IncidentDetailView => ({
  ...d,
  currentStatus: 'closed',
  currentResolution: 'false_positive',
  nextAllowedStatus: null,
  statusHistory: closingHistory,
});

interface Setup {
  role?: 'VIEWER' | 'ANALYST' | 'ADMIN';
  detail?: (d: IncidentDetailView) => IncidentDetailView;
  /** 서버 값. 주지 않으면 역할과 상태로 정한다 */
  canReopen?: boolean;
  /** 응답에 canReopen을 싣지 않는다(옛 응답) */
  omitCanReopen?: boolean;
  postResponse?: (url: string) => Response | undefined;
}

function renderDetail(setup: Setup = {}) {
  document.cookie = 'XSRF-TOKEN=t53-test-token; path=/';
  const role = setup.role ?? 'ANALYST';
  const state = { detail: (setup.detail ?? closedDetail)(baseDetail()) };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (init?.method === 'POST') {
      const custom = setup.postResponse?.(url);
      if (custom) return custom;
      if (url.endsWith('/reopen')) {
        state.detail = {
          ...state.detail,
          currentStatus: 'investigating',
          currentResolution: null,
          nextAllowedStatus: 'closed',
          statusHistory: [...state.detail.statusHistory, reopenRow('2026-11-21T01:00:00Z')],
        };
        return json({ succeeded: true, code: 'OK', message: '인시던트를 다시 열었습니다. 상태는 분석 중입니다.' });
      }
      return json({ succeeded: true, code: 'OK', message: '처리했습니다' });
    }
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
    if (m) {
      const d = state.detail;
      const closed = d.currentStatus === 'closed';
      return json({
        maskedView: role === 'VIEWER',
        canDecideReview: role !== 'VIEWER',
        detail: { ...d, incident: { ...d.incident, jobId: Number(m[1]), queueRank: Number(m[2]) } },
        queueMeta: { ...DEFAULT_META, priority: closed ? null : 'low' },
        assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
        assignmentHistory: [],
        canAssign: role !== 'VIEWER' && !closed,
        responseActions: [],
        canRecordResponse: role !== 'VIEWER' && d.currentStatus !== 'open',
        ...(setup.omitCanReopen ? {} : { canReopen: setup.canReopen ?? (role !== 'VIEWER' && closed) }),
      });
    }
    if (url.startsWith('/api/incidents/queue/neighbors')) {
      return json({ current: null, position: null, total: 0, prev: null, next: null });
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  const utils = render(
    <MemoryRouter initialEntries={['/incidents/42/rank/1']}>
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
const reopenForm = () => within(actions()).getByRole('form', { name: '다시 열기' });
const reopenButton = () => within(reopenForm()).getByRole('button', { name: '다시 열기' });
const posts = (fetchMock: ReturnType<typeof vi.fn>, path: string) =>
  fetchMock.mock.calls.filter(([u, i]) => u === path && (i as RequestInit | undefined)?.method === 'POST');
const detailGets = (fetchMock: ReturnType<typeof vi.fn>) =>
  fetchMock.mock.calls.filter(([u, i]) => u === PATH && (i as RequestInit | undefined)?.method !== 'POST').length;
const ready = () => screen.findByRole('tab', { name: '요약', selected: true });

describe('T53 종결 건의 다시 열기 폼', () => {
  it('분석가: "종결된 인시던트입니다." 아래에 사유(필수)·안내 두 줄·"다시 열기" 단추. 사유가 없으면 보낼 수 없다', async () => {
    const user = userEvent.setup();
    const { container } = renderDetail();
    await ready();
    const panel = actions();
    expect(within(panel).getByText(CLOSED_TEXT)).toBeInTheDocument();
    expect(panel.textContent).not.toContain('더 바꿀 상태가 없습니다');
    // 상태 변경 폼은 없다(다음 단계가 없다)
    expect(within(panel).queryByRole('form', { name: '상태 변경' })).toBeNull();
    const form = reopenForm();
    expect(within(form).getByRole('heading', { name: '다시 열기' })).toBeInTheDocument();
    expect(within(form).getByText(REOPEN_NOTE)).toBeInTheDocument();
    expect(within(form).getByText(ASSIGN_NOTE)).toBeInTheDocument();
    const reason = within(form).getByLabelText('다시 여는 사유 (필수)');
    expect(reason).toHaveAttribute('maxlength', '500');
    expect(reason).toBeRequired();
    // 확인 단계가 없다: 단추는 하나다
    expect(within(form).getAllByRole('button').map((b) => b.textContent)).toEqual(['다시 열기']);
    expect(reopenButton()).toBeDisabled();
    await user.type(reason, '   ');
    expect(reopenButton()).toBeDisabled();
    await user.type(reason, '재검토');
    expect(reopenButton()).toBeEnabled();
    // 문구 순서: 종결 문구 → 폼
    const closedText = within(panel).getByText(CLOSED_TEXT);
    expect(closedText.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(container.querySelector('[style]')).toBeNull();
  });

  it('보내면 다듬은 사유와 화면의 판정(expectedResolution)을 보내고, 서버 문장을 토스트로 띄운 뒤 상세를 다시 읽는다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail();
    await ready();
    const before = detailGets(fetchMock);
    await user.type(within(reopenForm()).getByLabelText('다시 여는 사유 (필수)'), '  같은 대역에서 다시 보임  ');
    await user.click(reopenButton());

    const calls = posts(fetchMock, `${PATH}/reopen`);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String((calls[0][1] as RequestInit).body))).toEqual({
      reason: '같은 대역에서 다시 보임',
      expectedResolution: 'false_positive',
    });
    expect(posts(fetchMock, `${PATH}/transition`)).toHaveLength(0);
    expect(await screen.findByText('인시던트를 다시 열었습니다. 상태는 분석 중입니다.')).toBeInTheDocument();
    await waitFor(() => expect(detailGets(fetchMock)).toBe(before + 1));
    // 다시 읽은 값: 분석 중, 상태 변경 폼(종결)이 돌아오고 다시 열기 폼은 없다
    await waitFor(() => expect(within(actions()).getByRole('form', { name: '상태 변경' })).toBeInTheDocument());
    expect(within(actions()).queryByRole('form', { name: '다시 열기' })).toBeNull();
    expect(within(actions()).queryByText(CLOSED_TEXT)).toBeNull();
  });

  it('409면 서버 문장과 "다시 불러오기"를 보인다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail({
      postResponse: (url) =>
        url.endsWith('/reopen') ? json({ succeeded: false, code: 'CONFLICT', message: CONFLICT_TEXT }, 409) : undefined,
    });
    await ready();
    await user.type(within(reopenForm()).getByLabelText('다시 여는 사유 (필수)'), '재검토');
    await user.click(reopenButton());
    const alert = await within(reopenForm()).findByRole('alert');
    expect(alert).toHaveTextContent(CONFLICT_TEXT);
    const before = detailGets(fetchMock);
    await user.click(within(alert).getByRole('button', { name: '다시 불러오기' }));
    await waitFor(() => expect(detailGets(fetchMock)).toBe(before + 1));
  });

  it('501이면 서버 문장을 보인다(다시 불러와도 바뀌지 않으므로 다시 불러오기 단추는 없다)', async () => {
    const user = userEvent.setup();
    renderDetail({
      postResponse: (url) =>
        url.endsWith('/reopen')
          ? json({ succeeded: false, code: 'REOPEN_UNAVAILABLE', message: UNAVAILABLE_TEXT }, 501)
          : undefined,
    });
    await ready();
    await user.type(within(reopenForm()).getByLabelText('다시 여는 사유 (필수)'), '재검토');
    await user.click(reopenButton());
    const alert = await within(reopenForm()).findByRole('alert');
    expect(alert).toHaveTextContent(UNAVAILABLE_TEXT);
    expect(within(alert).queryByRole('button')).toBeNull();
    // 사유는 지우지 않는다
    expect(within(reopenForm()).getByLabelText('다시 여는 사유 (필수)')).toHaveValue('재검토');
  });

  it('조회자: 종결 문구만 보이고 폼은 없다', async () => {
    renderDetail({
      role: 'VIEWER',
      canReopen: false,
      detail: (d) => ({ ...closedDetail(d), analystReview: { ...d.analystReview, canDecide: false } }),
    });
    await ready();
    expect(within(actions()).getByText(CLOSED_TEXT)).toBeInTheDocument();
    expect(actions().textContent).not.toContain('더 바꿀 상태가 없습니다');
    expect(within(actions()).queryByRole('form', { name: '다시 열기' })).toBeNull();
    expect(within(actions()).queryByLabelText('다시 여는 사유 (필수)')).toBeNull();
    expect(within(actions()).queryByRole('button', { name: '다시 열기' })).toBeNull();
  });

  it('서버가 canReopen을 주지 않으면(false·옛 응답) 분석가에게도 폼을 보이지 않는다', async () => {
    const first = renderDetail({ canReopen: false });
    await ready();
    expect(within(actions()).getByText(CLOSED_TEXT)).toBeInTheDocument();
    expect(within(actions()).queryByRole('form', { name: '다시 열기' })).toBeNull();
    first.unmount();

    renderDetail({ omitCanReopen: true });
    await ready();
    expect(within(actions()).getByText(CLOSED_TEXT)).toBeInTheDocument();
    expect(within(actions()).queryByRole('form', { name: '다시 열기' })).toBeNull();
  });

  it('값이 최신이 아니면(blockedReason) 상태 변경 단추처럼 다시 열기 단추도 막는다', async () => {
    const user = userEvent.setup();
    const props = {
      detail: closedDetail(baseDetail()),
      readOnly: false,
      onRefresh: async () => {},
      onShowHistory: () => {},
      canAssign: false,
      currentUsername: 'analyst1',
      responseActions: [],
      canRecordResponse: true,
      canReopen: true,
    };
    const { rerender, container } = render(
      <ToastProvider>
        <ActionPanel {...props} blockedReason="최신 값을 불러온 뒤 조치할 수 있습니다" />
      </ToastProvider>,
    );
    await user.type(within(reopenForm()).getByLabelText('다시 여는 사유 (필수)'), '재검토');
    expect(reopenButton()).toBeDisabled();
    expect(reopenButton()).toHaveAttribute('title', '최신 값을 불러온 뒤 조치할 수 있습니다');
    rerender(
      <ToastProvider>
        <ActionPanel {...props} blockedReason={null} />
      </ToastProvider>,
    );
    expect(reopenButton()).toBeEnabled();
    expect(container.querySelector('[style]')).toBeNull();
  });
});

describe('T53 이력의 "다시 열림" 표지', () => {
  it('종결 → 분석 중 행에 "다시 열림"을 붙이고 판정 배지는 없다. 다른 행에는 붙지 않는다', () => {
    const history = [...closingHistory, reopenRow('2026-11-19T01:00:00Z')];
    const review: AnalystReviewView = { ...baseDetail().analystReview, present: false };
    render(<HistoryTimeline events={buildTimeline(history, review)} emptyText="없음" />);
    const items = within(screen.getByRole('list', { name: '이력 타임라인' })).getAllByRole('listitem');
    expect(items).toHaveLength(3);
    expect(within(items[2]).getByText('다시 열림')).toBeInTheDocument();
    expect(within(items[2]).queryByText('오탐')).toBeNull();
    expect(items[2]).toHaveTextContent('같은 대역에서 다시 보임');
    expect(within(items[0]).queryByText('다시 열림')).toBeNull();
    expect(within(items[1]).queryByText('다시 열림')).toBeNull();
    expect(within(items[1]).getByText('오탐')).toBeInTheDocument();
  });
});

describe('T53 오탐 종결 결정 뒤 사람이 다시 연 건', () => {
  const dismissReview = (over: Partial<AnalystReviewView>): AnalystReviewView => ({
    ...baseDetail().analystReview,
    reviewAction: 'dismiss',
    analystDisplay: '분석가1 (analyst1)',
    decidedAt: '2026-11-18T02:30:00Z',
    pending: false,
    canDecide: true,
    ...over,
  });
  /** 결정(02:30) → 종결(03:00) → 사람이 다시 엶(reopenAt) → 지금 분석 중 */
  const reopenedDetail = (review: AnalystReviewView, reopenAt: string): IncidentDetailView => ({
    ...baseDetail(),
    analystReview: review,
    currentStatus: 'investigating',
    currentResolution: null,
    nextAllowedStatus: 'closed',
    statusHistory: [...closingHistory, reopenRow(reopenAt)],
  });
  const panelProps = (detail: IncidentDetailView) => ({
    detail,
    readOnly: false,
    onRefresh: async () => {},
    onShowHistory: () => {},
    canAssign: true,
    currentUsername: 'analyst1',
    responseActions: [],
    canRecordResponse: true,
  });

  const cases: Array<[string, Partial<AnalystReviewView>]> = [
    ['반영됨', { resumedAt: '2026-11-18T02:31:00Z', resumeStatusLabel: '반영됨' }],
    ['반영 실패', { resumeFailed: true, resumeStatusLabel: '반영 실패(관리자 확인 필요)' }],
    ['반영 지연', { resumeStatusLabel: '반영 중' }],
  ];

  for (const [name, over] of cases) {
    it(`${name}: 결정보다 늦은 종결 → 분석 중 이력이 있으면 "직접 종결" 안내와 오탐 미리 채움이 없다`, () => {
      render(
        <ToastProvider>
          <ActionPanel {...panelProps(reopenedDetail(dismissReview(over), '2026-11-19T01:00:00Z'))} />
        </ToastProvider>,
      );
      const form = within(actions()).getByRole('form', { name: '상태 변경' });
      expect(within(form).queryByRole('note', { name: '직접 종결 안내' })).toBeNull();
      expect(form.textContent).not.toContain(RESUME_MANUAL_CLOSE_TEXT);
      expect(within(form).getByLabelText('판정 (필수)')).toHaveValue('true_positive');
      expect(form.textContent).not.toContain('판정을 오탐으로 미리 채웠습니다');
    });
  }

  it('반영됨: 다시 연 건이 "반영 실패"로 보이지 않는다', () => {
    const { container } = render(
      <ToastProvider>
        <ActionPanel
          {...panelProps(
            reopenedDetail(dismissReview({ resumedAt: '2026-11-18T02:31:00Z', resumeStatusLabel: '반영됨' }), '2026-11-19T01:00:00Z'),
          )}
        />
      </ToastProvider>,
    );
    expect(container.textContent).not.toContain('반영 실패');
    expect(container.textContent).not.toContain('반영 지연');
    expect(container.textContent).not.toContain(RESUME_MANUAL_CLOSE_TEXT);
  });

  it('다시 연 이력이 결정보다 이르면(결정 전 재개) 지금처럼 반영 실패의 안내와 미리 채움이 뜬다', () => {
    render(
      <ToastProvider>
        <ActionPanel
          {...panelProps(
            reopenedDetail(
              dismissReview({ decidedAt: '2026-11-20T00:00:00Z', resumeFailed: true, resumeStatusLabel: '반영 실패(관리자 확인 필요)' }),
              '2026-11-19T01:00:00Z',
            ),
          )}
        />
      </ToastProvider>,
    );
    const form = within(actions()).getByRole('form', { name: '상태 변경' });
    expect(within(form).getByRole('note', { name: '직접 종결 안내' })).toHaveTextContent(RESUME_MANUAL_CLOSE_TEXT);
    expect(within(form).getByLabelText('판정 (필수)')).toHaveValue('false_positive');
  });
});
