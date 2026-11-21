import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentDetailView, IncidentQueueItem, IncidentQueueMeta, QueueNeighborsResponse, UnifiedQueueItem } from '../types/api';
import { formatSessionDuration } from '../utils/format';
import { fakeNeighbors, unified } from './fakeQueueServer';
import { expectAllTablesInScrollBox, tablesOutsideScrollBox } from './tableScrollBox';

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
    alerted: true,
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
  /** T23: 가짜 neighbors 서버가 쓸 큐 행(우선순위는 서버 값으로 준다) */
  list?: UnifiedQueueItem[];
  /** T23: neighbors 응답을 직접 정한다(list보다 먼저) */
  neighbors?: QueueNeighborsResponse;
  /** T23: 상세 응답의 queueMeta(기본: 가져온 데이터, High, 탐지 2026-11-12 11:27) */
  meta?: IncidentQueueMeta | null;
  snapshot?: boolean;
  /** POST 뒤 상세를 바꾸는 함수(상태 변경 흐름) */
  onPost?: (url: string, body: Record<string, unknown>, state: { detail: IncidentDetailView }) => void;
  /** T21: 이동 목록(T23: GET /api/incidents/queue/neighbors) 조회가 실패할 횟수 */
  listFailures?: number;
}

const DEFAULT_META: IncidentQueueMeta = {
  sourceType: 'imported',
  detectedAt: '2026-11-12T02:27:00Z',
  priority: 'high',
  ongoing: false,
  latestJobId: 42,
  latestQueueRank: 1,
};

/** 서버 우선순위를 준 큐 행 */
function listItem(overrides: Partial<IncidentQueueItem>, priority: UnifiedQueueItem['priority'] = 'high'): UnifiedQueueItem {
  return unified(queueItem(overrides), { priority, detectedAt: '2026-11-12T02:27:00Z' });
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
    if (url === '/api/time-context') {
      return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: setup.snapshot ? 'latest-data' : 'now', snapshot: Boolean(setup.snapshot) });
    }
    const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
    if (m) {
      const d = state.detail;
      const incident = { ...d.incident, jobId: Number(m[1]), queueRank: Number(m[2]) };
      return json({
        maskedView: role === 'VIEWER',
        canDecideReview: role !== 'VIEWER',
        detail: { ...d, incident },
        queueMeta: setup.meta === undefined ? DEFAULT_META : setup.meta,
      });
    }
    if (url.startsWith('/api/incidents/queue/neighbors')) {
      listCalls.push(url);
      if (listCalls.length <= (setup.listFailures ?? 0)) {
        return json({ code: 'INTERNAL', message: '일시 오류' }, 500);
      }
      if (setup.neighbors) return json(setup.neighbors);
      return json(fakeNeighbors(url, { items: setup.list ?? [] }));
    }
    if (url === '/api/incidents' || url.startsWith('/api/incidents?') || url.startsWith('/api/incidents/queue')) {
      // T23: 상세는 목록 전체를 받지 않는다
      throw new Error(`상세가 목록 API를 불렀다: ${url}`);
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
      '발송 판단',
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
    // T23: 수집원(종류 + 표시 이름)·탐지 시각·캡처 내 순위
    expect(within(h).getByText('가져온 데이터')).toBeInTheDocument();
    expect(within(h).getByText('CIC-IDS2017 수요일')).toBeInTheDocument();
    expect(within(h).getByText('탐지')).toBeInTheDocument();
    expect(within(h).getByText('2026-11-12 11:27:00')).toBeInTheDocument();
    expect(within(h).getByText('캡처 내 순위')).toBeInTheDocument();
    expect(within(h).getByText('1위')).toBeInTheDocument();
    expect(within(h).queryByText('진행 중')).toBeNull();
    // 모델 버전·탐지 작업 시각은 툴팁에만
    const when = within(h).getByText('발생').parentElement as HTMLElement;
    expect(when.getAttribute('title')).toContain('모델 버전 zeekad-fusion/3');
    expect(when.getAttribute('title')).toContain('탐지 작업 2026-11-12 11:27:00');
    // T20: 캡처 표시 이름(zeek_AD Q65)과 원래 ID도 같은 툴팁에
    expect(when.getAttribute('title')).toContain('캡처 CIC-IDS2017 수요일 · cic17-wed');
    expect(document.body.textContent).not.toContain('zeekad-fusion/3');
    // 인시던트 ID 원문은 글로 보이지 않고, 복사 버튼은 원문을 복사한다
    expect(document.body.textContent).not.toContain(INCIDENT_ID);
    await user.click(within(h).getByRole('button', { name: '인시던트 ID 복사' }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe(INCIDENT_ID));
  });

  it('헤더 우선순위는 서버 값(queueMeta.priority)이다(종결이면 서버가 없음을 준다. 화면이 다시 계산하지 않는다)', async () => {
    const first = renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({ ...d, currentStatus: 'closed', currentResolution: 'true_positive', canTransition: false, nextAllowedStatus: null }),
      meta: { ...DEFAULT_META, priority: null },
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    expect(within(header()).getByText('우선순위 없음')).toBeInTheDocument();
    expect(within(header()).queryByText('High')).toBeNull();
    expect(within(actions()).getByText('종결된 인시던트입니다. 더 바꿀 상태가 없습니다.')).toBeInTheDocument();
    first.unmount();

    // 발송 판단 "발송"인 행이어도 서버가 Low를 주면 Low를 보인다
    renderDetail('/incidents/42/rank/1', { meta: { ...DEFAULT_META, priority: 'low' } });
    await screen.findByRole('tab', { name: '요약', selected: true });
    expect(within(header()).getByText('Low')).toBeInTheDocument();
  });

  it('진행 중이면 헤더에 표지를 붙이고, 고정 스냅샷이면 툴팁에 기준 시각 기준을 적는다. 실습망 센서 표시', async () => {
    renderDetail('/incidents/42/rank/1', {
      meta: { ...DEFAULT_META, sourceType: 'live', ongoing: true },
      detail: (d) => ({ ...d, incident: { ...d.incident, captureId: 'lab-20261118' } }),
      snapshot: true,
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const h = header();
    expect(within(h).getByText('실습망 센서')).toBeInTheDocument();
    expect(within(h).getByText('실습망 2026-11-18 · 시험')).toBeInTheDocument();
    await waitFor(() =>
      expect(within(h).getByText('진행 중').closest('[title]')).toHaveAttribute('title', expect.stringContaining('기준 시각 기준')),
    );
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
      // T21 정정: zeek_AD 계약대로 결정은 반영되면 상태를 바꾼다
      expect(
        within(a).getByText('에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).'),
      ).toBeInTheDocument();
      expect(a.textContent).not.toContain('인시던트 상태를 바꾸지 않습니다');
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
    expect(confirm).toHaveTextContent('오탐 종결로 결정할까요? 결정은 되돌릴 수 없습니다. 반영되면 인시던트가 종결(오탐)됩니다.');
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

  it('오탐 종결이 반영 실패면 신규 → 분석 중 → 종결 흐름에서 종결 폼의 판정이 오탐으로 미리 채워진다(바꿀 수 있음)', async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({
        ...d,
        incident: { ...d.incident, zeekadStatus: 'open', zeekadReviewPending: false, zeekadReviewAction: 'dismiss' },
        currentStatus: 'open',
        nextAllowedStatus: 'investigating',
        analystReview: {
          ...d.analystReview,
          reviewAction: 'dismiss',
          decidedAt: '2026-11-12T04:00:00Z',
          pending: false,
          resumeFailed: true,
          resumedAt: null,
          resumeStatusLabel: '반영 실패(관리자 확인 필요)',
        },
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
    expect(within(actions()).getByText('분석 중으로 바꾼 뒤 종결할 때 판정이 오탐으로 채워집니다.')).toBeInTheDocument();
    expect(within(actions()).getByRole('note', { name: '직접 종결 안내' })).toHaveTextContent(
      '오탐 종결 결정이 자동 반영되지 않았습니다. 상태 변경으로 직접 종결하세요. 판정을 오탐으로 미리 채웠습니다.',
    );
    expect(within(actions()).getByText('자동 반영에 실패했습니다. 관리자에게 알리거나 상태 변경으로 직접 처리하세요.')).toBeInTheDocument();
    await user.type(within(actions()).getByLabelText('변경 사유 (필수)'), '확인 시작');
    await user.click(within(actions()).getByRole('button', { name: '분석 중으로 변경' }));

    // 분석 중: 종결 폼의 판정 기본값 = 오탐
    const select = await within(actions()).findByLabelText('판정 (필수)');
    expect(select).toHaveValue('false_positive');
    expect(within(actions()).getByText('판정을 오탐으로 미리 채웠습니다. 바꿀 수 있습니다.')).toBeInTheDocument();
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

  it('T26 휴대폰 폭: 모든 탭의 표(증적 탭의 관측 계정 표 포함)는 가로 스크롤 상자 안에 있다', async () => {
    const user = userEvent.setup();
    renderDetail('/incidents/42/rank/1?tab=evidence');
    await screen.findByRole('tab', { name: '증적', selected: true });
    // 관측 계정 표가 그려지는 데이터(assetNames: WS-01$)로 본다
    const accounts = within(panel()).getByText('WS-01$').closest('table') as HTMLTableElement;
    expect(accounts).not.toBeNull();
    expectAllTablesInScrollBox();
    for (const tab of screen.getAllByRole('tab')) {
      await user.click(tab);
      await waitFor(() => expect(tab).toHaveAttribute('aria-selected', 'true'));
      expect(tablesOutsideScrollBox()).toEqual([]);
    }
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

    // 남긴 항목: 리포트 요약·사실·해석·ATT&CK·권고·한계·검증, 발송 판단 세 의견, Slack 시각·종류·결과
    await user.click(screen.getByRole('tab', { name: 'AI 리포트' }));
    const p = panel();
    for (const kept of ['관측 요약', '확인된 사실', '가능한 해석', '관련 ATT&CK 기법 후보', '추가 확인 권고', '리포트의 한계', '검증 통과']) {
      expect(within(p).getByText(kept)).toBeInTheDocument();
    }
    await user.click(screen.getByRole('tab', { name: '발송 판단' }));
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
    for (const name of ['요약', '증적', 'AI 리포트', '발송 판단', 'Slack', '이력']) {
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

  it('이력 탭은 상태 변경과 에스컬레이션 요청·결정·반영을 시간 순서 하나로 합친다(항목마다 변경자·사유)', async () => {
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
    expect(items[3]).toHaveTextContent('결정 반영됨(파이프라인)');
    // T21: 각 항목은 그 변경의 변경자다("마지막 변경자" 아님)
    expect(items[4]).toHaveTextContent('변경자 분석가1 (analyst1)');
    expect(items[4]).not.toHaveTextContent('마지막 변경자');
    expect(document.body.textContent).not.toContain('담당자');
  });

  it('이전·다음: 목록이 넘긴 from= 쿼리(기간·수집원·거르기·정렬)로 서버 neighbors를 부르고, 목록으로 돌아가면 그 쿼리로 간다', async () => {
    const user = userEvent.setup();
    const list = [
      listItem({ queueRank: 1, hostIp: '10.0.0.1' }, 'low'),
      listItem({ queueRank: 2, hostIp: '10.0.0.2', connectionCount: 20 }),
      listItem({ queueRank: 3, hostIp: '10.0.0.3', connectionCount: 30 }),
      listItem({ queueRank: 4, hostIp: '10.0.0.4', connectionCount: 40 }),
    ];
    // 목록: High만, 세션 수 내림 → 4, 3, 2
    const from = 'period=all&source=imported&status=investigating&priority=high&sort=connections&dir=desc&page=1';
    const { listCalls } = renderDetail(`/incidents/42/rank/3?from=${encodeURIComponent(from)}&tab=evidence`, { list });
    await screen.findByRole('tab', { name: '증적', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    await waitFor(() => expect(within(nav).getByText('2 / 3')).toBeInTheDocument());
    // 목록 조건을 그대로(쪽 번호·크기 없이) 보낸다
    const sent = new URLSearchParams(listCalls[0].split('?')[1]);
    expect(Object.fromEntries(sent)).toEqual({
      jobId: '42',
      queueRank: '3',
      period: 'all',
      source: 'imported',
      priority: 'high',
      status: 'investigating',
      sort: 'connections',
      dir: 'desc',
    });
    expect(within(nav).getByRole('link', { name: '이전 인시던트' })).toHaveAttribute(
      'href',
      `/incidents/42/rank/4?from=${encodeURIComponent(from).replace(/%20/g, '+')}&tab=evidence`,
    );
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute(
      'href',
      `/incidents/42/rank/2?from=${encodeURIComponent(from).replace(/%20/g, '+')}&tab=evidence`,
    );
    expect(within(nav).getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', `/incidents?${from}`);

    // 다음으로 가면 그 인시던트 기준으로 다시 묻고, 끝에서는 다음 버튼이 꺼진다
    await user.click(within(nav).getByRole('link', { name: '다음 인시던트' }));
    await waitFor(() => expect(within(nav).getByText('3 / 3')).toBeInTheDocument());
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(listCalls).toHaveLength(2);
  });

  it('from= 쿼리가 없으면 기본 큐(기간 24시간·우선순위 순) 조건을 쓰고 목록으로는 기본 큐(/incidents)로 간다(캡처 쿼리를 만들지 않는다)', async () => {
    const list = [listItem({ queueRank: 2 }, 'medium'), listItem({ queueRank: 1 }), listItem({ queueRank: 3 }, 'low')];
    const { listCalls } = renderDetail('/incidents/42/rank/1', { list });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    await waitFor(() => expect(within(nav).getByText('1 / 3')).toBeInTheDocument());
    const sent = new URLSearchParams(listCalls[0].split('?')[1]);
    expect(sent.get('period')).toBe('24h');
    expect(sent.get('sort')).toBe('priority');
    expect(sent.get('captureId')).toBeNull();
    expect(within(nav).getByText('1 / 3')).toHaveAttribute('title', '이전·다음 기준: 기본 목록 순서');
    expect(within(nav).getByRole('link', { name: '이전 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('href', '/incidents/42/rank/2');
    expect(within(nav).getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', '/incidents');
  });

  it('보고 있는 탐지 작업이 최신이 아니면 더 새로운 분석 결과 안내와 최신 보기 링크를 보인다', async () => {
    const from = 'period=all';
    renderDetail(`/incidents/41/rank/5?from=${encodeURIComponent(from)}`, {
      neighbors: {
        current: { jobId: 44, queueRank: 2, hostIp: '192.168.10.5' },
        position: 1,
        total: 1,
        prev: null,
        next: null,
      },
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    expect(await screen.findByText('이 인시던트의 더 새로운 분석 결과가 있습니다')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '최신 보기' })).toHaveAttribute('href', '/incidents/44/rank/2?from=period%3Dall');
  });

  it('거르기 결과에 없으면(위치 없음) 목록이 갱신되었다고 알리고 이전·다음을 끈다. 최신이면 새 결과 안내는 없다', async () => {
    renderDetail('/incidents/42/rank/1', {
      neighbors: { current: { jobId: 42, queueRank: 1, hostIp: '192.168.10.5' }, position: null, total: 7, prev: null, next: null },
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    expect(await within(nav).findByText('목록이 갱신되어 이 인시던트가 지금 목록에 없습니다')).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: '이전 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.queryByText('이 인시던트의 더 새로운 분석 결과가 있습니다')).toBeNull();
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
});

describe('T21: 결정 반영 상태·반영 지연·오탐 미리 채움·이력 사유·이동 실패', () => {
  const RELATION = '에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).';
  const PENDING_NOTE =
    '에스컬레이션 결정이 아직 반영 중입니다. 지금 상태를 직접 바꾸면 반영 때 그 단계는 건너뜁니다. 결정과 다른 판정으로 종결하면 둘이 어긋난 채 남습니다.';
  const DELAYED = '반영이 늦어지고 있습니다. 파이프라인 상태를 확인하거나 상태 변경으로 직접 처리하세요.';
  const MANUAL_CLOSE = '오탐 종결 결정이 자동 반영되지 않았습니다. 상태 변경으로 직접 종결하세요. 판정을 오탐으로 미리 채웠습니다.';
  const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

  function decided(
    action: 'confirm' | 'dismiss',
    review: Partial<IncidentDetailView['analystReview']>,
  ): (d: IncidentDetailView) => IncidentDetailView {
    return (d) => ({
      ...d,
      incident: { ...d.incident, zeekadReviewPending: false, zeekadReviewAction: action },
      analystReview: { ...d.analystReview, reviewAction: action, pending: false, analystDisplay: '김검토 (rev1)', ...review },
    });
  }

  it('반영 중(지연 전): 서버 라벨 "반영 중", 지연 표시 없음, 미리 채움 없음, 폼은 막지 않고 위에 안내', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: decided('dismiss', { decidedAt: minutesAgo(2), resumeStatusLabel: '반영 중' }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getByText('반영 중')).toBeInTheDocument();
    expect(within(a).queryByText('반영 지연')).toBeNull();
    expect(within(a).queryByText(DELAYED)).toBeNull();
    expect(within(a).getByText(RELATION)).toBeInTheDocument();
    expect(within(a).getByRole('note', { name: '반영 중 상태 변경 안내' })).toHaveTextContent(PENDING_NOTE);
    // 오탐 종결이어도 반영 중에는 판정을 미리 채우지 않는다(정탐 기본값)
    expect(within(a).getByLabelText('판정 (필수)')).toHaveValue('true_positive');
    expect(within(a).queryByRole('note', { name: '직접 종결 안내' })).toBeNull();
    expect(within(a).getByRole('button', { name: '종결 처리' })).toBeInTheDocument();
  });

  it('반영 지연(결정 뒤 10분 넘게 반영 중): 서버 라벨은 그대로 "반영 중"이고 반영 지연 표시·안내, 오탐이면 미리 채움', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: decided('dismiss', { decidedAt: minutesAgo(11), resumeStatusLabel: '반영 중' }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getByText('반영 중')).toBeInTheDocument();
    expect(within(a).getByText('반영 지연')).toBeInTheDocument();
    expect(within(a).getByText(DELAYED)).toBeInTheDocument();
    expect(within(a).queryByRole('note', { name: '반영 중 상태 변경 안내' })).toBeNull();
    expect(within(a).getByRole('note', { name: '직접 종결 안내' })).toHaveTextContent(MANUAL_CLOSE);
    expect(within(a).getByLabelText('판정 (필수)')).toHaveValue('false_positive');
  });

  it('반영 실패: 서버 라벨 "반영 실패(관리자 확인 필요)"와 실패 안내, 오탐이면 미리 채움', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: decided('dismiss', {
        decidedAt: minutesAgo(1),
        resumeFailed: true,
        resumeStatusLabel: '반영 실패(관리자 확인 필요)',
      }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getByText('반영 실패(관리자 확인 필요)')).toBeInTheDocument();
    expect(within(a).getByText('자동 반영에 실패했습니다. 관리자에게 알리거나 상태 변경으로 직접 처리하세요.')).toBeInTheDocument();
    expect(within(a).queryByText('반영 지연')).toBeNull();
    expect(within(a).getByLabelText('판정 (필수)')).toHaveValue('false_positive');
  });

  it('반영됨: 서버 라벨 "반영됨"과 반영 시각, 안내·미리 채움 없음', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({
        ...decided('confirm', {
          decidedAt: '2026-11-12T04:00:00Z',
          resumedAt: '2026-11-12T04:00:30Z',
          resumeStatusLabel: '반영됨',
        })(d),
        currentStatus: 'investigating',
      }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getByText('반영됨')).toBeInTheDocument();
    expect(within(a).getAllByText('2026-11-12 13:00:30').length).toBeGreaterThanOrEqual(1);
    expect(within(a).queryByText('반영 지연')).toBeNull();
    expect(within(a).queryByRole('note', { name: '반영 중 상태 변경 안내' })).toBeNull();
    expect(within(a).queryByRole('note', { name: '직접 종결 안내' })).toBeNull();
    expect(within(a).getByLabelText('판정 (필수)')).toHaveValue('true_positive');
  });

  it('승인 결정이 반영 지연이면 지연 안내는 있고 판정 미리 채움은 없다(오탐 종결 결정만 미리 채운다)', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: decided('confirm', { decidedAt: minutesAgo(30), resumeStatusLabel: '반영 중' }),
    });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const a = actions();
    expect(within(a).getByText(DELAYED)).toBeInTheDocument();
    expect(within(a).queryByRole('note', { name: '직접 종결 안내' })).toBeNull();
    expect(within(a).getByLabelText('판정 (필수)')).toHaveValue('true_positive');
  });

  it('상세 헤더의 경보는 alerted 값이다(발송 판단과 다른 값이면 alerted를 따른다)', async () => {
    renderDetail('/incidents/42/rank/1', {
      detail: (d) => ({ ...d, incident: { ...d.incident, alerted: false, zeekadWouldSend: true } }),
    });
    const header = await screen.findByRole('region', { name: '인시던트 요약' });
    expect(within(header).getByText('발송 기록 없음')).toBeInTheDocument();
    expect(within(header).queryByText('경보 발송')).toBeNull();
  });

  it('이력 탭: 상태 변경 항목마다 변경자·사유·판정(종결)을 보인다(결정 반영 항목의 사유 = 결정 메모)', async () => {
    renderDetail('/incidents/42/rank/1?tab=history', {
      detail: (d) => ({
        ...d,
        currentStatus: 'closed',
        currentResolution: 'false_positive',
        nextAllowedStatus: null,
        statusHistory: [
          {
            jobId: 42,
            fromStatus: 'open',
            toStatus: 'investigating',
            resolution: null,
            actorDisplay: '김검토 (rev1)',
            reason: '정기 백업 작업 트래픽으로 확인(오탐)',
            changedAt: '2026-11-12T04:00:30Z',
          },
          {
            jobId: 42,
            fromStatus: 'investigating',
            toStatus: 'closed',
            resolution: 'false_positive',
            actorDisplay: '김검토 (rev1)',
            reason: '정기 백업 작업 트래픽으로 확인(오탐)',
            changedAt: '2026-11-12T04:00:31Z',
          },
        ],
      }),
    });
    await screen.findByRole('tab', { name: '이력', selected: true });
    const items = within(within(panel()).getByRole('list', { name: '이력 타임라인' })).getAllByRole('listitem');
    const statusItems = items.filter((li) => li.textContent?.includes('변경자'));
    expect(statusItems).toHaveLength(2);
    for (const li of statusItems) {
      expect(li).toHaveTextContent('사유정기 백업 작업 트래픽으로 확인(오탐)');
      expect(li).toHaveTextContent('변경자 김검토 (rev1)');
    }
    expect(within(statusItems[1]).getByText('오탐')).toBeInTheDocument();
    expect(within(statusItems[0]).queryByText('오탐')).toBeNull();
  });

  it('이동 목록 조회가 실패하면 헤더에 안내와 다시 시도가 있고, 다시 시도하면 이동 버튼이 살아난다', async () => {
    const user = userEvent.setup();
    const list = [
      listItem({ queueRank: 1, hostIp: '10.0.0.1' }),
      listItem({ queueRank: 2, hostIp: '10.0.0.2', incidentId: 'b|2' }),
    ];
    const { listCalls } = renderDetail('/incidents/42/rank/1', { list, listFailures: 1 });
    await screen.findByRole('tab', { name: '요약', selected: true });
    const nav = screen.getByRole('navigation', { name: '인시던트 이동' });
    expect(await within(nav).findByRole('alert')).toHaveTextContent('이동 목록을 불러오지 못했습니다');
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('aria-disabled', 'true');

    await user.click(within(nav).getByRole('button', { name: '다시 시도' }));
    await waitFor(() => expect(within(nav).queryByRole('alert')).toBeNull());
    expect(listCalls.length).toBe(2);
    expect(within(nav).getByRole('link', { name: '다음 인시던트' })).toHaveAttribute('href', '/incidents/42/rank/2');
  });
});
