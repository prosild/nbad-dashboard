import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentDetailView, IncidentQueueItem } from '../types/api';
import { formatSessionDuration } from '../utils/format';
import { findNeighbors, orderQueue, parseQueueView } from '../utils/triage';

/** T19 인시던트 상세: 요약 헤더·조치 패널·탭·오탐 종결 안전장치·주요 세션 열·이전·다음 */

const XSS = '<script>window.__xss=1</script><img src=x onerror=alert(1)>';
const INCIDENT_ID = 'cic17-wed|192.168.10.5|originator|100';

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

function queueItem(overrides: Partial<IncidentQueueItem> = {}): IncidentQueueItem {
  return {
    jobId: 42,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    queueRank: 1,
    incidentId: INCIDENT_ID,
    hostIp: '192.168.10.5',
    zeekadRole: 'originator',
    eventStart: '2017-07-05T13:45:00Z',
    eventEnd: '2017-07-05T14:15:00Z',
    zeekadPickedBy: 'tgn_recon',
    zeekadAlsoFlaggedBy: ['tail_rarity_v2'],
    connectionCount: 155261,
    hostName: ['ws-01.lab'],
    zeekadStatus: 'investigating',
    zeekadResolution: null,
    statusUpdatedAt: '2026-11-18T02:00:00Z',
    zeekadReportJobId: 40,
    hasReport: true,
    zeekadReportKind: 'llm',
    zeekadVerificationPassed: true,
    zeekadWouldSend: true,
    zeekadReviewAction: null,
    zeekadReviewPending: true,
    ...overrides,
  };
}

function baseDetail(): IncidentDetailView {
  return {
    incident: queueItem(),
    job: {
      jobId: 42,
      captureId: 'cic17-wed',
      bundleId: 'zeekad-fusion/3',
      status: 'succeeded',
      startedAt: '2026-11-12T02:20:00Z',
      finishedAt: '2026-11-12T02:27:00Z',
      error: null,
      incidentCount: 3,
    },
    modelScores: [
      { jobId: 42, incidentId: INCIDENT_ID, zeekadModel: 'tgn_recon', candidateWindows: 6, windows: 9, windowRatioLabel: '6 / 9' },
    ],
    assetNames: [
      {
        captureId: 'cic17-wed',
        hostIp: '192.168.10.5',
        kerberosUser: 'WS-01$',
        ntlmUser: null,
        extraAttributes: {
          zeekad_name: 'WS-01$',
          zeekad_name_kind: 'kerberos_machine',
          zeekad_source_log: 'kerberos.log',
          observations: 199,
          first_seen: '2017-07-05T11:54:41Z',
          last_seen: '2017-07-05T20:00:33Z',
        },
      },
    ],
    evidence: {
      available: true,
      statusMessage: '정상',
      connectionCount: 155261,
      bytesSent: 1791339786,
      bytesReceived: 123985880,
      payloadBytesInflated: 724,
      transportCounts: { tcp: 155221, udp: 40 },
      serviceProtocolCounts: { http: 147460 },
      connStateCounts: { SF: 58598 },
      topPeers: [{ ip: '172.16.0.1', connections: 155111 }],
      uniquePeers: 12,
      topPorts: [{ port: 80, transport: 'tcp', connections: 155111 }],
      uniquePorts: 27,
      protocolLogs: [],
      representativeConnections: [
        {
          zeek: { uid: 'CiQcQl2qxnMgafJIJc', conn_state: 'SF' },
          event: { start: '2017-07-05T13:43:23.865228Z', duration: 0.17 },
          source: { ip: '192.168.10.5', port: 52974, bytes: 704 },
          destination: { ip: '172.16.0.1', port: 80, bytes: 1229 },
          network: { protocol: 'http', transport: 'tcp' },
        },
        {
          zeek: { uid: 'Cxss', conn_state: 'RSTO' },
          event: { start: '2017-07-05T13:44:00Z', duration: 75.4 },
          source: { ip: XSS, port: 1, bytes: 0 },
          destination: { ip: '172.16.0.2', port: 443, bytes: null },
          network: { protocol: 'unidentified', transport: 'tcp' },
        },
      ],
      limits: ['점수는 정상 대비 이상함이다.'],
      additionalFields: { version: 'evidence.v1', note: XSS },
    },
    report: {
      present: true,
      reportKind: 'llm',
      reportVersion: 'llm-report.v1',
      inputVersion: 'evidence.v1',
      llmModelRequested: 'gemini-2.5-flash',
      llmModelVersion: 'gemini-2.5-flash-001',
      llmSeconds: 30.2,
      llmInputTokens: 4260,
      llmOutputTokens: 1208,
      llmThinkingTokens: null,
      llmError: null,
      verificationPassed: true,
      verificationReason: null,
      verificationProblems: [],
      createdAt: '2026-11-12T02:30:00Z',
      sourceRun: 'run-20261112',
      pseudonyms: { H: '192.168.10.5', X: '172.16.0.1' },
      observationSummary: '대상 호스트 H가 외부와 대량 세션을 주고받았습니다.',
      claims: [{ claim: `세션이 많습니다. ${XSS}`, facts: [{ id: 'F1', name: 'connection_count', value: '155261' }] }],
      possibleExplanations: [{ explanation: '웹 서버 부하 시험 가능성', facts: [], attackIds: ['T1498'] }],
      sendRecommendation: { choice: 'send', reason: '세션이 많습니다.', facts: [] },
      limitations: ['표본이 하루치입니다.'],
      followUp: ['웹 서버 로그를 확인하세요.'],
      attackCandidates: [{ attackId: 'T1498', name: 'Network Denial of Service', tactics: ['impact'] }],
    },
    sendDecision: {
      present: true,
      wouldSend: true,
      decidedBy: 'policy',
      policyId: 'rank-and-multi-model',
      policyChoice: 'send',
      policyMandatory: false,
      policyReasons: [],
      llmChoice: 'send',
      decisionModel: 'gemini-decision-1',
      decisionModelChoice: 'send',
      decisionModelConfidence: 0.61,
      decisionModelProbabilities: { send: 0.61, hold: 0.39 },
      decisionModelError: null,
      opinionMismatch: false,
    },
    slackDeliveries: [],
    slackThreadGroups: [
      {
        threadKey: INCIDENT_ID,
        deliveries: [
          {
            jobId: 40,
            messageKind: 'incident',
            messageVersion: 'v1',
            deliveryMode: 'live',
            deliveryStatus: 'failed',
            dryRunOrRecorded: false,
            slackTs: '17000.123',
            deliveredAt: '2026-11-12T02:31:00Z',
            error: `채널 없음 ${XSS}`,
            createdAt: '2026-11-12T02:31:00Z',
            payloadJson: '{"text":"secret-payload"}',
            threadParent: null,
            threadKey: INCIDENT_ID,
            threadRoleLabel: '최초 알림',
            replyBroadcast: false,
          },
        ],
      },
    ],
    analystReview: {
      present: true,
      reviewJobId: 40,
      reviewReason: '경계선 점수 검토',
      requestedAt: '2026-11-12T02:32:00Z',
      reviewAction: null,
      analystDisplay: null,
      decidedAt: null,
      resumedAt: null,
      resumeFailed: false,
      pending: true,
      resumeStatusLabel: '에스컬레이션 대기',
      canDecide: true,
    },
    currentStatus: 'investigating',
    currentResolution: null,
    statusUpdatedAt: '2026-11-18T02:00:00Z',
    statusUpdatedByDisplay: '분석가1 (analyst1)',
    statusHistory: [
      {
        jobId: 42,
        fromStatus: null,
        toStatus: 'open',
        resolution: null,
        actorDisplay: '시스템',
        reason: '최초 생성',
        changedAt: '2026-11-12T02:27:00Z',
      },
      {
        jobId: 42,
        fromStatus: 'open',
        toStatus: 'investigating',
        resolution: null,
        actorDisplay: '분석가1 (analyst1)',
        reason: '조사 시작',
        changedAt: '2026-11-18T02:00:00Z',
      },
    ],
    canTransition: true,
    nextAllowedStatus: 'closed',
  };
}

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

interface Setup {
  role?: 'VIEWER' | 'ANALYST' | 'ADMIN';
  detail?: (current: IncidentDetailView) => IncidentDetailView;
  list?: IncidentQueueItem[];
  /** POST 뒤 상세를 바꾸는 함수(상태 변경 흐름) */
  onPost?: (url: string, body: Record<string, unknown>, state: { detail: IncidentDetailView }) => void;
}

function renderDetail(path: string, setup: Setup = {}) {
  document.cookie = 'XSRF-TOKEN=detail-test-token; path=/';
  const role = setup.role ?? 'ANALYST';
  const state = { detail: (setup.detail ?? ((d) => d))(baseDetail()) };
  const listCalls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: userOf(role) });
    if (init?.method === 'POST') {
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      setup.onPost?.(url, body, state);
      return json({ succeeded: true, code: 'OK', message: '처리했습니다' });
    }
    const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
    if (m) {
      const d = state.detail;
      const incident = { ...d.incident, jobId: Number(m[1]), queueRank: Number(m[2]) };
      return json({ maskedView: role === 'VIEWER', canDecideReview: role !== 'VIEWER', detail: { ...d, incident } });
    }
    if (url === '/api/incidents' || url.startsWith('/api/incidents?')) {
      listCalls.push(url);
      return json({
        maskedView: false,
        allowedCaptures: ['cic17-wed'],
        selectedCaptureId: 'cic17-wed',
        selectedJob: null,
        captureJobs: [],
        incidents: setup.list ?? [],
        availableModels: [],
        availableRoles: [],
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
  return { ...utils, fetchMock, listCalls, state };
}

const loc = () => screen.getByTestId('loc').textContent ?? '';
const panel = () => screen.getByRole('tabpanel');
const actions = () => screen.getByRole('region', { name: '조치' });
const header = () => screen.getByRole('region', { name: '인시던트 요약' });
const posts = (fetchMock: ReturnType<typeof vi.fn>, path: string) =>
  fetchMock.mock.calls.filter(([u, i]) => u === path && (i as RequestInit | undefined)?.method === 'POST');

describe('인시던트 상세 화면(T19)', () => {
  it('탭을 바꾸면 tab= 쿼리에 남고, tab= 쿼리로 복원되며, 허용 밖 값은 요약으로 고친다', async () => {
    const user = userEvent.setup();
    const first = renderDetail('/incidents/42/rank/1');
    expect(await screen.findByRole('tab', { name: '요약', selected: true })).toBeInTheDocument();
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual([
      '요약',
      '증적',
      'AI 리포트',
      '경보 판단',
      'Slack',
      '이력',
    ]);
    expect(within(panel()).getByText('무슨 일인가')).toBeInTheDocument();
    expect(within(panel()).getByText('왜 의심스러운가')).toBeInTheDocument();
    expect(within(panel()).getByText('다음에 할 일')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: '증적' }));
    expect(loc()).toBe('/incidents/42/rank/1?tab=evidence');
    expect(screen.getByRole('tab', { name: '증적', selected: true })).toBeInTheDocument();
    // 화살표 키로도 탭을 옮긴다
    await user.keyboard('{ArrowRight}');
    expect(loc()).toBe('/incidents/42/rank/1?tab=report');
    await user.click(screen.getByRole('tab', { name: '요약' }));
    expect(loc()).toBe('/incidents/42/rank/1');
    first.unmount();

    const second = renderDetail('/incidents/42/rank/1?tab=slack');
    expect(await screen.findByRole('tab', { name: 'Slack', selected: true })).toBeInTheDocument();
    expect(within(panel()).getByText('최초 알림')).toBeInTheDocument();
    second.unmount();

    renderDetail('/incidents/42/rank/1?tab=bogus&from=captureId%3Dcic17-wed');
    expect(await screen.findByRole('tab', { name: '요약', selected: true })).toBeInTheDocument();
    await waitFor(() => expect(loc()).toBe('/incidents/42/rank/1?from=captureId%3Dcic17-wed'));
  });

  it('요약 헤더: 우선순위·상태·호스트·방향·탐지 모델·발생·세션·경보·검증, ID는 복사 버튼만(원문 복사)', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    const h = header();
    expect(within(h).getByText('High')).toBeInTheDocument();
    expect(within(h).getByText('분석 중')).toBeInTheDocument();
    expect(within(h).getByText('192.168.10.5')).toBeInTheDocument();
    expect(within(h).getByText('ws-01.lab')).toBeInTheDocument();
    expect(within(h).getByText('출발지')).toBeInTheDocument();
    expect(within(h).getByText('통신 관계 이상')).toBeInTheDocument();
    expect(within(h).getByText('교차 탐지 +1')).toBeInTheDocument();
    expect(within(h).getByText('2017-07-05 22:45:00')).toBeInTheDocument();
    expect(within(h).getByText('30분')).toBeInTheDocument();
    expect(within(h).getByText('155,261건')).toBeInTheDocument();
    expect(within(h).getByText('경보 발송')).toBeInTheDocument();
    expect(within(h).getByText('검증 통과')).toBeInTheDocument();
    // 모델 버전·탐지 작업 시각은 툴팁에만
    const when = within(h).getByText('발생').parentElement as HTMLElement;
    expect(when.getAttribute('title')).toContain('모델 버전 zeekad-fusion/3');
    expect(when.getAttribute('title')).toContain('탐지 작업 2026-11-12 11:27:00');
    expect(document.body.textContent).not.toContain('zeekad-fusion/3');
    // 인시던트 ID 원문은 글로 보이지 않고, 복사 버튼은 원문을 복사한다
    expect(document.body.textContent).not.toContain(INCIDENT_ID);
    await user.click(within(h).getByRole('button', { name: '인시던트 ID 복사' }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe(INCIDENT_ID));
  });

  it('헤더 우선순위는 상세의 현재 상태로 계산한다(종결이면 우선순위 없음)', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({ ...d, currentStatus: 'closed', currentResolution: 'true_positive', canTransition: false, nextAllowedStatus: null }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    expect(within(header()).getByText('우선순위 없음')).toBeInTheDocument();
    expect(within(header()).queryByText('High')).toBeNull();
    expect(within(actions()).getByText('종결된 인시던트입니다. 더 바꿀 상태가 없습니다.')).toBeInTheDocument();
  });

  it('조회자에게는 조치 폼이 없고 현재 상태·판정만 읽기 전용으로 보인다', async () => {
    renderDetail('/incidents/42/rank/1', {
      role: 'VIEWER',
      detail: (d) => ({ ...d, canTransition: false, nextAllowedStatus: null, analystReview: { ...d.analystReview, canDecide: false } }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getAllByText('분석 중').length).toBeGreaterThanOrEqual(1);
    expect(within(a).getByText('읽기 전용 계정입니다. 상태 변경과 에스컬레이션 결정은 분석가 계정에서 할 수 있습니다.')).toBeInTheDocument();
    expect(within(a).queryByRole('textbox')).toBeNull();
    expect(within(a).queryByRole('combobox')).toBeNull();
    expect(within(a).queryByRole('button', { name: '종결 처리' })).toBeNull();
    expect(within(a).queryByRole('button', { name: '승인' })).toBeNull();
    expect(within(a).queryByRole('button', { name: '오탐 종결' })).toBeNull();
  });

  it('분석가·관리자에게는 상태 변경·에스컬레이션 결정 폼과 두 결정의 관계 안내가 있다', async () => {
    for (const role of ['ANALYST', 'ADMIN'] as const) {
      const r = renderDetail('/incidents/42/rank/1', { role });
      await screen.findByRole('tab', { name: '요약', selected: true });
      const a = actions();
      expect(within(a).getByLabelText('판정 (필수)')).toBeInTheDocument();
      expect(within(a).getByLabelText('변경 사유 (필수)')).toBeInTheDocument();
      expect(within(a).getByRole('button', { name: '종결 처리' })).toBeInTheDocument();
      expect(within(a).getByRole('button', { name: '승인' })).toBeInTheDocument();
      expect(within(a).getByRole('button', { name: '오탐 종결' })).toBeInTheDocument();
      expect(within(a).getByText('에스컬레이션 결정은 인시던트 상태를 바꾸지 않습니다. 상태는 상태 변경으로 바꿉니다.')).toBeInTheDocument();
      // 최근 이력(최신이 위)과 전체 이력 이동
      const recent = within(a).getByRole('list', { name: '최근 이력' });
      expect(within(recent).getAllByRole('listitem')[0]).toHaveTextContent('조사 시작');
      r.unmount();
    }
  });

  it('오탐 종결은 메모가 있어야 하고 확인 단계를 한 번 더 거친다', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();

    // 메모 없이 누르면 막고 메모 칸으로 포커스
    await user.click(within(a).getByRole('button', { name: '오탐 종결' }));
    expect(within(a).getByRole('alert')).toHaveTextContent('오탐 종결에는 검토 메모가 필요합니다.');
    expect(within(a).getByLabelText('검토 메모 (오탐 종결 때 필수)')).toHaveFocus();
    expect(posts(fetchMock, '/api/incidents/42/rank/1/review-decision')).toHaveLength(0);

    // 메모를 쓰고 누르면 확인 단계. 취소하면 돌아간다
    await user.type(within(a).getByLabelText('검토 메모 (오탐 종결 때 필수)'), '정상 업무 트래픽');
    await user.click(within(a).getByRole('button', { name: '오탐 종결' }));
    const confirm = within(a).getByRole('group', { name: '오탐 종결 확인' });
    expect(confirm).toHaveTextContent('오탐 종결로 결정할까요? 결정은 되돌릴 수 없고, 인시던트 상태는 바뀌지 않습니다.');
    expect(posts(fetchMock, '/api/incidents/42/rank/1/review-decision')).toHaveLength(0);
    await user.click(within(confirm).getByRole('button', { name: '취소' }));
    expect(within(a).queryByRole('group', { name: '오탐 종결 확인' })).toBeNull();

    await user.click(within(a).getByRole('button', { name: '오탐 종결' }));
    await user.click(within(a).getByRole('button', { name: '오탐 종결 확정' }));
    await waitFor(() => expect(posts(fetchMock, '/api/incidents/42/rank/1/review-decision')).toHaveLength(1));
    const [, init] = posts(fetchMock, '/api/incidents/42/rank/1/review-decision')[0];
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ action: 'dismiss', note: '정상 업무 트래픽' });
  });

  it('승인은 메모 없이 바로 제출한다(메모는 선택)', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    await user.click(within(actions()).getByRole('button', { name: '승인' }));
    await waitFor(() => expect(posts(fetchMock, '/api/incidents/42/rank/1/review-decision')).toHaveLength(1));
    const [, init] = posts(fetchMock, '/api/incidents/42/rank/1/review-decision')[0];
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ action: 'confirm' });
  });

  it('결정 뒤에는 결정 버튼 대신 결정·반영 상태를 보인다', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({
        ...d,
        incident: { ...d.incident, zeekadReviewPending: false, zeekadReviewAction: 'confirm' },
        analystReview: {
          ...d.analystReview,
          reviewAction: 'confirm',
          analystDisplay: '김검토 (rev1)',
          decidedAt: '2026-11-12T04:00:00Z',
          pending: false,
          resumeStatusLabel: '반영 중',
        },
      }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).queryByRole('button', { name: '승인' })).toBeNull();
    expect(within(a).queryByRole('button', { name: '오탐 종결' })).toBeNull();
    expect(within(a).getAllByText('승인').length).toBeGreaterThanOrEqual(1);
    expect(within(a).getByText('반영 중')).toBeInTheDocument();
    expect(within(a).getAllByText('김검토 (rev1)').length).toBeGreaterThanOrEqual(1);
  });

  it('오탐 종결 뒤 신규 → 분석 중 → 종결 흐름에서 종결 폼의 판정이 오탐으로 미리 채워진다(바꿀 수 있음)', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({
        ...d,
        incident: { ...d.incident, zeekadStatus: 'open', zeekadReviewPending: false, zeekadReviewAction: 'dismiss' },
        currentStatus: 'open',
        nextAllowedStatus: 'investigating',
        analystReview: { ...d.analystReview, reviewAction: 'dismiss', pending: false, resumeStatusLabel: '반영됨', resumedAt: '2026-11-12T05:00:00Z' },
      }),
      onPost: (url, body, state) => {
        if (url.endsWith('/transition') && body.toStatus === 'investigating') {
          state.detail = { ...state.detail, currentStatus: 'investigating', nextAllowedStatus: 'closed' };
        }
      },
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    // 신규: 다음 단계가 분석 중이라 판정 칸이 없고 안내만 있다
    expect(within(actions()).queryByLabelText('판정 (필수)')).toBeNull();
    expect(within(actions()).getByText('에스컬레이션을 오탐 종결로 결정했습니다. 분석 중으로 바꾼 뒤 종결할 때 판정이 오탐으로 채워집니다.')).toBeInTheDocument();
    await user.type(within(actions()).getByLabelText('변경 사유 (필수)'), '확인 시작');
    await user.click(within(actions()).getByRole('button', { name: '분석 중으로 변경' }));

    // 분석 중: 종결 폼의 판정 기본값 = 오탐
    const select = await within(actions()).findByLabelText('판정 (필수)');
    expect(select).toHaveValue('false_positive');
    expect(within(actions()).getByText('에스컬레이션을 오탐 종결로 결정해 판정을 오탐으로 미리 채웠습니다. 바꿀 수 있습니다.')).toBeInTheDocument();
    await user.type(within(actions()).getByLabelText('변경 사유 (필수)'), '오탐 확인');
    await user.click(within(actions()).getByRole('button', { name: '종결 처리' }));
    await waitFor(() => expect(posts(fetchMock, '/api/incidents/42/rank/1/transition')).toHaveLength(2));
    const bodies = posts(fetchMock, '/api/incidents/42/rank/1/transition').map(([, i]) => JSON.parse(String((i as RequestInit).body)));
    expect(bodies).toEqual([
      { toStatus: 'investigating', resolution: null, reason: '확인 시작' },
      { toStatus: 'closed', resolution: 'false_positive', reason: '오탐 확인' },
    ]);
  });

  it('오탐 종결이 아니면 판정 기본값은 정탐이고, 사용자가 바꿀 수 있다(기존 규칙)', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    const select = within(actions()).getByLabelText('판정 (필수)');
    expect(select).toHaveValue('true_positive');
    await user.selectOptions(select, 'benign');
    // 사유가 없으면 제출 버튼이 꺼져 있다
    expect(within(actions()).getByRole('button', { name: '종결 처리' })).toBeDisabled();
    await user.type(within(actions()).getByLabelText('변경 사유 (필수)'), '정상 업무');
    await user.click(within(actions()).getByRole('button', { name: '종결 처리' }));
    await waitFor(() => expect(posts(fetchMock, '/api/incidents/42/rank/1/transition')).toHaveLength(1));
    const [, init] = posts(fetchMock, '/api/incidents/42/rank/1/transition')[0];
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ toStatus: 'closed', resolution: 'benign', reason: '정상 업무' });
  });

  it('주요 세션은 필드별 열로 보이고(세션 기준 바이트), 원본 증적은 기본 접힘이다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1?tab=evidence');
    await screen.findByRole('tab', { name: '증적', selected: true });
    const table = within(panel()).getAllByRole('table').find((t) => within(t).queryByRole('columnheader', { name: '시작 시각' }));
    if (!table) throw new Error('주요 세션 표 없음');
    expect(within(table).getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
      '시작 시각',
      '출발지 IP:포트',
      '목적지 IP:포트',
      '서비스 · 전송 계층',
      '지속 시간',
      '출발지 바이트',
      '목적지 바이트',
      '세션 상태',
    ]);
    const row = within(table).getAllByRole('row')[1];
    const cells = within(row).getAllByRole('cell').map((c) => c.textContent);
    expect(cells).toEqual([
      '2017-07-05 22:43:23',
      '192.168.10.5:52974',
      '172.16.0.1:80',
      'http · tcp',
      '170ms',
      '704 B',
      '1.2 KB',
      '정상 연결·종료',
    ]);
    expect(row).toHaveAttribute('title', 'Zeek 세션 ID CiQcQl2qxnMgafJIJc');
    expect(within(row).getByText('정상 연결·종료')).toHaveAttribute('title', 'SF');
    const row2 = within(table).getAllByRole('row')[2];
    expect(within(row2).getByText('1분 15초')).toBeInTheDocument();
    expect(within(row2).getByText('식별 안 됨')).toBeInTheDocument();
    // 중첩 JSON 셀이 없다
    expect(table.textContent).not.toContain('{"');
    // 원본 증적 데이터는 접혀 있다
    const raw = within(panel()).getByText('원본 증적 데이터').closest('details') as HTMLDetailsElement;
    expect(raw.open).toBe(false);
    await user.click(within(panel()).getByText('원본 증적 데이터'));
    expect(raw.open).toBe(true);
  });

  it('뺀 항목(생성 정보·가명표·정책 ID·판단 모델 ID·확률 막대·Slack 원본·ts·관측 부가 필드)은 화면에 없다', async () => {
    const user = userEvent.setup();
    const { container } = renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    const text = container.textContent ?? '';
    for (const removed of [
      'gemini-2.5-flash',
      '4,260',
      '30.2초',
      'llm-report.v1',
      'run-20261112',
      '리포트 속 가명',
      'rank-and-multi-model',
      'gemini-decision-1',
      '선택지별 선택 확률',
      'secret-payload',
      'Slack 원본 메시지 보기',
      '17000.123',
      'kerberos.log',
      '관측 횟수',
    ]) {
      expect(text, removed).not.toContain(removed);
    }
    expect(container.querySelector('[title*="rank-and-multi-model"]')).toBeNull();
    expect(container.querySelector('[title*="gemini-decision-1"]')).toBeNull();
    expect(container.querySelector('[title*="17000.123"]')).toBeNull();

    // 남긴 항목: 리포트 요약·사실·해석·ATT&CK·권고·한계·검증, 경보 판단 세 의견, Slack 시각·종류·결과
    await user.click(screen.getByRole('tab', { name: 'AI 리포트' }));
    const p = panel();
    for (const kept of ['관측 요약', '확인된 사실', '가능한 해석', '관련 ATT&CK 기법 후보', '추가 확인 권고', '리포트의 한계', '검증 통과']) {
      expect(within(p).getByText(kept)).toBeInTheDocument();
    }
    await user.click(screen.getByRole('tab', { name: '경보 판단' }));
    // 세 의견이 같으면 한 줄 요약을 먼저 보이고 펼친다
    const summaryLine = within(panel()).getByRole('button', { name: '세 의견 모두 전송' });
    expect(summaryLine).toHaveAttribute('aria-expanded', 'false');
    expect(within(panel()).queryByText('규칙 의견')).toBeNull();
    await user.click(summaryLine);
    expect(within(panel()).getByText('규칙 의견')).toBeInTheDocument();
    expect(within(panel()).getByText('AI 리포트 의견')).toBeInTheDocument();
    expect(within(panel()).getByText('판단 모델 의견')).toBeInTheDocument();
    expect(within(panel()).getByText('61.0%')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Slack' }));
    expect(within(panel()).getByText('2026-11-12 11:31:00')).toBeInTheDocument();
    expect(within(panel()).getByText('인시던트 알림')).toBeInTheDocument();
  });

  it('XSS 페이로드(주요 세션 값·원본 증적·Slack·리포트)는 모든 탭에서 글로만 나온다', async () => {
    const user = userEvent.setup();
    const { container } = renderDetail('/incidents/42/rank/1');
    await screen.findByRole('tab', { name: '요약', selected: true });
    for (const name of ['요약', '증적', 'AI 리포트', '경보 판단', 'Slack', '이력']) {
      await user.click(screen.getByRole('tab', { name }));
      expect(container.querySelectorAll('script')).toHaveLength(0);
      expect(container.querySelectorAll('img')).toHaveLength(0);
    }
    await user.click(screen.getByRole('tab', { name: '증적' }));
    expect(within(panel()).getByText(`${XSS}:1`)).toBeInTheDocument();
    expect(within(panel()).getByText(XSS)).toHaveAttribute('data-raw');
    await user.click(screen.getByRole('tab', { name: 'Slack' }));
    expect(within(panel()).getByText(`오류: 채널 없음 ${XSS}`)).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'AI 리포트' }));
    expect(within(panel()).getByText(`세션이 많습니다. ${XSS}`)).toBeInTheDocument();
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
  });

  it('이력 탭은 상태 변경과 에스컬레이션 요청·결정·반영을 시간 순서 하나로 합친다(마지막 변경자 표기)', async () => {
    renderDetail('/incidents/42/rank/1?tab=history', {
      detail: (d) => ({
        ...d,
        analystReview: {
          ...d.analystReview,
          reviewAction: 'confirm',
          analystDisplay: '김검토 (rev1)',
          decidedAt: '2026-11-12T04:00:00Z',
          resumedAt: '2026-11-12T04:05:00Z',
          pending: false,
          resumeStatusLabel: '반영됨',
        },
      }),
    });
    await screen.findByRole('tab', { name: '이력', selected: true });
    const items = within(within(panel()).getByRole('list', { name: '이력 타임라인' })).getAllByRole('listitem');
    expect(items.map((li) => li.textContent?.slice(0, 19))).toEqual([
      '2026-11-12 11:27:00',
      '2026-11-12 11:32:00',
      '2026-11-12 13:00:00',
      '2026-11-12 13:05:00',
      '2026-11-18 11:00:00',
    ]);
    expect(items[0]).toHaveTextContent('최초 생성');
    expect(items[1]).toHaveTextContent('에스컬레이션 요청');
    expect(items[2]).toHaveTextContent('에스컬레이션 결정');
    expect(items[3]).toHaveTextContent('결정이 자동 처리에 반영됨');
    expect(items[4]).toHaveTextContent('마지막 변경자 분석가1 (analyst1)');
    expect(document.body.textContent).not.toContain('담당자');
  });

  it('이전·다음: 목록이 넘긴 from= 쿼리의 필터·정렬 순서를 따르고, 목록으로 돌아가면 그 쿼리로 간다', async () => {
    const user = userEvent.setup();
    const list = [
      queueItem({ queueRank: 1, hostIp: '10.0.0.1', zeekadWouldSend: false, zeekadReviewPending: false, zeekadAlsoFlaggedBy: [], hasReport: false, zeekadReportJobId: null }),
      queueItem({ queueRank: 2, hostIp: '10.0.0.2' }),
      queueItem({ queueRank: 3, hostIp: '10.0.0.3' }),
      queueItem({ queueRank: 4, hostIp: '10.0.0.4' }),
    ];
    // 목록: High만, 순위 내림 → 4, 3, 2
    const from = 'captureId=cic17-wed&status=investigating&priority=high&sort=rank&dir=desc&page=1';
    const { listCalls } = renderDetail(`/incidents/42/rank/3?from=${encodeURIComponent(from)}&tab=evidence`, { list });
    await screen.findByRole('tab', { name: '증적', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    await waitFor(() => expect(within(nav).getByText('2 / 3')).toBeInTheDocument());
    // 서버 필터만 API로 보낸다
    expect(listCalls).toEqual(['/api/incidents?captureId=cic17-wed&status=investigating']);
    expect(within(nav).getByRole('link', { name: '이전 인시던트' })).toHaveAttribute(
      'href',
      `/incidents/42/rank/4?from=${encodeURIComponent(from).replace(/%20/g, '+')}&tab=evidence`,
    );
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute(
      'href',
      `/incidents/42/rank/2?from=${encodeURIComponent(from).replace(/%20/g, '+')}&tab=evidence`,
    );
    expect(within(nav).getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', `/incidents?${from}`);

    // 다음으로 가면 목록을 다시 부르지 않고 끝에서는 다음 버튼이 꺼진다
    await user.click(within(nav).getByRole('link', { name: '다음 인시던트' }));
    await waitFor(() => expect(within(nav).getByText('3 / 3')).toBeInTheDocument());
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(listCalls).toHaveLength(1);
  });

  it('from= 쿼리가 없으면 같은 캡처·탐지 작업의 목록을 파이프라인 순위 순으로 쓰고, 맨 앞에서는 이전이 꺼진다', async () => {
    const list = [queueItem({ queueRank: 2 }), queueItem({ queueRank: 1 }), queueItem({ queueRank: 3 })];
    const { listCalls } = renderDetail('/incidents/42/rank/1', { list });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    await waitFor(() => expect(within(nav).getByText('1 / 3')).toBeInTheDocument());
    expect(listCalls).toEqual(['/api/incidents?captureId=cic17-wed&jobId=42']);
    expect(within(nav).getByText('1 / 3')).toHaveAttribute('title', '이전·다음 기준: 파이프라인 순위 순');
    expect(within(nav).getByRole('link', { name: '이전 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('href', '/incidents/42/rank/2');
    expect(within(nav).getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', '/incidents?captureId=cic17-wed');
  });
});

describe('T19 순수 함수', () => {
  it('세션 지속 시간 표기(L6)', () => {
    expect(formatSessionDuration(0)).toBe('1ms 미만');
    expect(formatSessionDuration(0.0004)).toBe('1ms 미만');
    expect(formatSessionDuration(0.001)).toBe('1ms');
    expect(formatSessionDuration(0.17)).toBe('170ms');
    expect(formatSessionDuration(0.9996)).toBe('999ms');
    expect(formatSessionDuration(1)).toBe('1.0초');
    expect(formatSessionDuration(59.99)).toBe('59.9초');
    expect(formatSessionDuration(60)).toBe('1분 0초');
    expect(formatSessionDuration(3725.5)).toBe('62분 5초');
    expect(formatSessionDuration(null)).toBe('-');
    expect(formatSessionDuration(-1)).toBe('-');
  });

  it('목록 순서(orderQueue)와 이웃 찾기(findNeighbors)', () => {
    const items = [
      queueItem({ queueRank: 1, zeekadWouldSend: false, zeekadReviewPending: false, zeekadAlsoFlaggedBy: [], hasReport: false }),
      queueItem({ queueRank: 2 }),
      queueItem({ queueRank: 3, jobId: 7 }),
    ];
    const ordered = orderQueue(items, parseQueueView(new URLSearchParams('priority=high&sort=rank&dir=desc')));
    expect(ordered.map((i) => i.queueRank)).toEqual([3, 2]);
    expect(findNeighbors(ordered, 42, 2)).toMatchObject({ index: 1, total: 2, next: null });
    expect(findNeighbors(ordered, 42, 2).prev?.queueRank).toBe(3);
    expect(findNeighbors(ordered, 42, 1)).toMatchObject({ index: -1, prev: null, next: null });
    // 기본 정렬은 우선순위 → 순위
    expect(orderQueue(items, parseQueueView(new URLSearchParams(''))).map((i) => i.queueRank)).toEqual([2, 3, 1]);
  });
});
