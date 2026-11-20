import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

/**
 * 화면 문구 회귀 검사(T17): 주요 화면의 보이는 글에 내부 DB·필드 이름과 `한국어 (영어 코드)` 병기가 없어야 한다.
 * 데이터 원문을 그대로 보여 주는 요소(data-raw: 사건 ID, 모델·구성 식별자, 사람 표시, 원본 근거, 보고서 버전 값)만 검사에서 뺀다.
 */
const FORBIDDEN = ['dashboard.', 'zeekad_', 'job_id', 'queue_rank', 'evidence.v1', '단계 5'];
const PAREN_PATTERN = /[가-힣]\s*\(([A-Za-z_][A-Za-z0-9_.-]*)\)/g;
const ALLOWED_ABBREVIATIONS = new Set([
  'IP',
  'DNS',
  'HTTP',
  'HTTPS',
  'TCP',
  'UDP',
  'Kerberos',
  'NTLM',
  'Slack',
  'TOTP',
  'KST',
]);

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  clone.querySelectorAll('[data-raw]').forEach((el) => el.remove());
  return clone.textContent ?? '';
}

function expectCleanText(root: HTMLElement) {
  const text = visibleText(root);
  for (const word of FORBIDDEN) {
    expect(text, `금지 문자열 "${word}"`).not.toContain(word);
  }
  const mixed = [...text.matchAll(PAREN_PATTERN)]
    .filter((m) => !ALLOWED_ABBREVIATIONS.has(m[1]))
    .map((m) => m[0]);
  expect(mixed, '한국어 (영어 코드) 병기').toEqual([]);
  expect(text).not.toContain('정확도');
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const viewerUser = {
  username: 'demo',
  displayName: '공개 데모',
  role: 'VIEWER',
  maskedView: true,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
};

const analystUser = { ...viewerUser, username: 'analyst1', displayName: '분석가1', role: 'ANALYST', maskedView: false };
const adminUser = {
  ...viewerUser,
  username: 'admin',
  displayName: '최고관리자',
  role: 'ADMIN',
  maskedView: false,
  totpEnabled: true,
  totpRequired: true,
};

const INCIDENT_ID = 'cic17-wed|192.168.*.*|responder|1499262300';

const queueItem = {
  jobId: 2,
  captureId: 'cic17-wed',
  bundleId: 'zeekad-fusion/3',
  queueRank: 1,
  incidentId: INCIDENT_ID,
  hostIp: '192.168.*.*',
  zeekadRole: 'responder',
  eventStart: '2017-07-05T13:45:00Z',
  eventEnd: '2017-07-05T14:15:00Z',
  zeekadPickedBy: 'tgn_recon',
  zeekadAlsoFlaggedBy: ['tail_rarity_v2', 'transformer_v2'],
  connectionCount: 155261,
  hostName: ['CIC-WEBSERVER$'],
  zeekadStatus: 'investigating',
  zeekadResolution: null,
  statusUpdatedAt: '2026-11-18T02:00:00Z',
  zeekadReportJobId: 5,
  hasReport: true,
  zeekadReportKind: 'llm',
  zeekadVerificationPassed: true,
  zeekadWouldSend: true,
  zeekadReviewAction: null,
  zeekadReviewPending: true,
};

const scoringJob = {
  jobId: 2,
  captureId: 'cic17-wed',
  bundleId: 'zeekad-fusion/3',
  status: 'succeeded',
  startedAt: '2026-11-12T02:20:00Z',
  finishedAt: '2026-11-12T02:27:00Z',
  error: null,
  incidentCount: 241,
};

const queueResponse = {
  maskedView: true,
  allowedCaptures: ['cic17-wed'],
  selectedCaptureId: 'cic17-wed',
  selectedJob: scoringJob,
  captureJobs: [scoringJob, { ...scoringJob, jobId: 1, status: 'failed', error: 'timeout' }],
  incidents: [
    queueItem,
    {
      ...queueItem,
      queueRank: 2,
      incidentId: 'cic17-wed|192.168.*.*|originator|1499262300',
      zeekadRole: 'originator',
      zeekadStatus: 'closed',
      zeekadResolution: 'true_positive',
      zeekadReportJobId: null,
      zeekadReportKind: null,
      zeekadVerificationPassed: null,
      zeekadWouldSend: false,
      zeekadReviewAction: 'dismiss',
      zeekadReviewPending: false,
    },
  ],
  availableModels: ['tail_rarity_v2', 'transformer_v2', 'tgn_recon'],
  availableRoles: ['originator', 'responder'],
};

const detailResponse = (masked: boolean) => ({
  maskedView: masked,
  canDecideReview: !masked,
  detail: {
    incident: queueItem,
    job: scoringJob,
    modelScores: [
      { jobId: 2, incidentId: INCIDENT_ID, zeekadModel: 'tail_rarity_v2', candidateWindows: 6, windows: 6, windowRatioLabel: '6 / 6' },
    ],
    assetNames: [
      {
        captureId: 'cic17-wed',
        hostIp: '192.168.*.*',
        kerberosUser: 'CIC-WEBSERVER$',
        ntlmUser: null,
        extraAttributes: {
          zeekad_name: 'CIC-WEBSERVER$',
          zeekad_name_kind: 'kerberos_machine',
          zeekad_source_log: 'kerberos.log',
          observations: 199,
          first_seen: '2017-07-05T11:54:41.816297Z',
          last_seen: '2017-07-05T20:00:33.274617Z',
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
      serviceProtocolCounts: { http: 147460, dns: 40, unidentified: 7663 },
      connStateCounts: { SF: 58598, RSTO: 91898, S0: 4169 },
      topPeers: [{ ip: '172.16.*.*', connections: 155111 }],
      uniquePeers: 12,
      topPorts: [{ port: 80, transport: 'tcp', connections: 155111 }],
      uniquePorts: 27,
      protocolLogs: [
        { protocol: 'dns', metrics: { queries: 80, nxdomain: 0 } },
        { protocol: 'dce_rpc', metrics: { calls: 10, top_operations: [{ operation: 'NetrShareEnum', connections: 10 }] } },
      ],
      representativeConnections: [
        {
          zeek: { uid: 'CiQcQl2qxnMgafJIJc', conn_state: 'SF' },
          event: { start: '2017-07-05T13:43:23.865228Z', duration: 0.17 },
          source: { ip: '172.16.*.*', port: 52974, bytes: 704 },
        },
      ],
      limits: ['점수는 정상(월요일) 대비 이상함이다. 공격 확정이 아니다'],
      additionalFields: { version: 'evidence.v1', zeekad_role: 'responder' },
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
      pseudonyms: { H: '192.168.*.*' },
      observationSummary: '대상 호스트 H가 외부와 대량 연결을 주고받았습니다.',
      claims: [{ claim: '연결 수가 많습니다.', facts: [{ id: 'F02', name: 'connection_count', value: '155261' }] }],
      possibleExplanations: [{ explanation: '웹 서버 부하 시험 가능성', facts: [], attackIds: ['T1498'] }],
      sendRecommendation: { choice: 'analyst_review', reason: '판단이 엇갈립니다.', facts: [] },
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
      policyMandatory: true,
      policyReasons: ['queue_rank 1 <= 5', 'flagging_models 3 >= 2'],
      llmChoice: 'analyst_review',
      decisionModel: 'gemini-decision-1',
      decisionModelChoice: 'analyst_review',
      decisionModelConfidence: 0.61,
      decisionModelProbabilities: { analyst_review: 0.61, send: 0.3, hold: 0.09 },
      decisionModelError: null,
      opinionMismatch: true,
    },
    slackDeliveries: [],
    slackThreadGroups: [
      {
        threadKey: INCIDENT_ID,
        deliveries: [
          {
            jobId: 5,
            messageKind: 'incident',
            messageVersion: 'v1',
            deliveryMode: 'dry_run',
            deliveryStatus: 'recorded',
            dryRunOrRecorded: true,
            slackTs: '17000.1',
            deliveredAt: '2026-11-12T02:31:00Z',
            error: null,
            createdAt: '2026-11-12T02:31:00Z',
            payloadJson: '{"zeekad_incident_id":"x","job_id":2}',
            threadParent: null,
            threadKey: INCIDENT_ID,
            threadRoleLabel: '첫 알림',
            replyBroadcast: false,
          },
          {
            jobId: 6,
            messageKind: 'status',
            messageVersion: 'v1',
            deliveryMode: 'dry_run',
            deliveryStatus: 'recorded',
            dryRunOrRecorded: true,
            slackTs: '17000.2',
            deliveredAt: '2026-11-12T03:31:00Z',
            error: null,
            createdAt: '2026-11-12T03:31:00Z',
            payloadJson: '{}',
            threadParent: INCIDENT_ID,
            threadKey: INCIDENT_ID,
            threadRoleLabel: '후속 알림',
            replyBroadcast: true,
          },
        ],
      },
    ],
    analystReview: {
      present: true,
      reviewJobId: 5,
      reviewReason: 'llm=analyst_review, decision_model=analyst_review',
      requestedAt: '2026-11-12T02:32:00Z',
      reviewAction: 'confirm',
      analystDisplay: '김검토 (rev_analyst_1)',
      decidedAt: '2026-11-12T04:00:00Z',
      resumedAt: null,
      resumeFailed: true,
      pending: false,
      resumeStatusLabel: '반영 실패(관리자 확인 필요)',
      canDecide: false,
    },
    currentStatus: 'investigating',
    currentResolution: null,
    statusUpdatedAt: '2026-11-18T02:00:00Z',
    statusUpdatedByDisplay: '분석가1 (analyst1)',
    statusHistory: [
      {
        jobId: 2,
        fromStatus: null,
        toStatus: 'open',
        resolution: null,
        actorDisplay: '시스템 (zeekad_pipeline)',
        reason: '최초 생성',
        changedAt: '2026-11-12T02:27:00Z',
      },
      {
        jobId: 2,
        fromStatus: 'open',
        toStatus: 'investigating',
        resolution: null,
        actorDisplay: '분석가1 (analyst1)',
        reason: '조사 시작',
        changedAt: '2026-11-18T02:00:00Z',
      },
    ],
    canTransition: !masked,
    nextAllowedStatus: masked ? null : 'closed',
  },
});

const reviewsResponse = (masked: boolean) => ({
  maskedView: masked,
  canDecideReview: !masked,
  allowedCaptures: ['cic17-wed'],
  selectedCaptureId: null,
  pendingOnly: false,
  reviews: [
    {
      jobId: 2,
      reviewJobId: 5,
      captureId: 'cic17-wed',
      incidentId: INCIDENT_ID,
      queueRank: 1,
      hostIp: '192.168.*.*',
      zeekadRole: 'responder',
      zeekadReviewReason: 'llm=analyst_review, decision_model=analyst_review',
      requestedAt: '2026-11-12T02:32:00Z',
      zeekadReviewAction: null,
      analyst: null,
      analystDisplay: null,
      decidedAt: null,
      zeekadReviewResumedAt: null,
      zeekadReviewResumeFailed: false,
      resumeStatusLabel: '판단 대기',
    },
    {
      jobId: 2,
      reviewJobId: 5,
      captureId: 'cic17-wed',
      incidentId: 'cic17-wed|192.168.*.*|originator|1499262300',
      queueRank: 2,
      hostIp: '192.168.*.*',
      zeekadRole: 'originator',
      zeekadReviewReason: '경계선 점수 검토',
      requestedAt: '2026-11-12T02:32:00Z',
      zeekadReviewAction: 'dismiss',
      analyst: 'rev_analyst_1',
      analystDisplay: '김검토 (rev_analyst_1)',
      decidedAt: '2026-11-12T04:00:00Z',
      zeekadReviewResumedAt: null,
      zeekadReviewResumeFailed: true,
      resumeStatusLabel: '반영 실패(관리자 확인 필요)',
    },
  ],
});

const operationsResponse = {
  maskedView: true,
  allowedCaptures: ['cic17-wed'],
  selectedCaptureId: null,
  jobs: [scoringJob, { ...scoringJob, jobId: 1, status: 'failed', error: '근거 API 시간 초과' }],
  bundles: [
    {
      bundleId: 'zeekad-fusion/3',
      registryName: 'zeekad-fusion',
      registryVersion: '3',
      manifestSha256: 'ab12cd34',
      registeredAt: '2026-11-12T00:00:00Z',
      thresholds: null,
      thresholdEntries: { tail_rarity_v2: '5.55', tgn_recon: '20.1' },
    },
  ],
  feedbackSummaries: [
    {
      captureId: 'cic17-wed',
      bundleId: 'zeekad-fusion/3',
      zeekadPickedBy: 'all',
      incidents: 79,
      alerted: 9,
      resolved: 1,
      truePositive: 1,
      falsePositive: 0,
      benign: 0,
      zeekadPrecision: 1,
      zeekadAlertPrecision: 1,
      zeekadAlertResolvedRate: 0.111,
      alertedResolved: 1,
      extraAttributes: {},
      allModel: true,
      effectiveAlertedResolved: 1,
      precisionSummaryText: '정밀도 1.00, 결론 1/79 (1.3%)',
      alertPrecisionSummaryText: '정밀도 1.00, 결론 1/9 (11.1%)',
    },
    {
      captureId: 'cic17-wed',
      bundleId: 'zeekad-fusion/3',
      zeekadPickedBy: 'tgn_recon',
      incidents: 30,
      alerted: 0,
      resolved: 0,
      truePositive: 0,
      falsePositive: 0,
      benign: 0,
      zeekadPrecision: null,
      zeekadAlertPrecision: null,
      zeekadAlertResolvedRate: null,
      alertedResolved: null,
      extraAttributes: {},
      allModel: false,
      effectiveAlertedResolved: 0,
      precisionSummaryText: '- (결론 0/30, 0.0%)',
      alertPrecisionSummaryText: '- (알림 없음)',
    },
  ],
  slackSummaries: [
    {
      jobId: 2,
      captureId: 'cic17-wed',
      zeekadMessageVersion: 'daily-summary.v1',
      zeekadDeliveryMode: 'dry_run',
      zeekadDeliveryStatus: 'recorded',
      slackPayload: null,
      slackTs: null,
      deliveredAt: null,
      createdAt: '2026-11-12T02:40:00Z',
      dryRunOrRecorded: true,
      payloadTextPreview: '오늘 탐지 사건 241건',
      payloadChannel: '#sec-alerts',
    },
  ],
};

const usersResponse = {
  users: [
    {
      id: 1,
      username: 'analyst1',
      displayName: '분석가1',
      role: 'ANALYST',
      totpEnabled: false,
      failedAttempts: 2,
      lockedUntil: '2026-11-19T01:00:00Z',
      enabled: true,
      createdAt: '2026-11-18T00:00:00Z',
      updatedAt: '2026-11-18T00:00:00Z',
      capturePatterns: ['cic17-*'],
    },
    {
      id: 2,
      username: 'admin',
      displayName: '관리자',
      role: 'ADMIN',
      totpEnabled: false,
      failedAttempts: 0,
      lockedUntil: null,
      enabled: true,
      createdAt: '2026-11-18T00:00:00Z',
      updatedAt: null,
      capturePatterns: ['*'],
    },
  ],
  roles: ['VIEWER', 'ANALYST', 'ADMIN'],
};

const auditResponse = {
  logs: [
    {
      id: 10,
      occurredAt: '2026-11-19T01:00:00Z',
      actorUsername: 'demo',
      actorRole: 'VIEWER',
      actionType: 'ACCESS_DENIED_IDOR',
      targetCaptureId: 'cic17-wed',
      targetJobId: 2,
      targetIncidentId: INCIDENT_ID,
      detailJson: '{"zeekad_job_id":2,"queue_rank":1}',
      clientIp: '127.0.0.1',
    },
    {
      id: 11,
      occurredAt: '2026-11-19T01:05:00Z',
      actorUsername: 'admin',
      actorRole: 'ADMIN',
      actionType: 'INCIDENT_VIEW_UNMASKED',
      targetCaptureId: null,
      targetJobId: null,
      targetIncidentId: null,
      detailJson: null,
      clientIp: '127.0.0.1',
    },
  ],
  actionTypes: ['LOGIN_SUCCESS', 'ACCESS_DENIED_IDOR', 'INCIDENT_VIEW_UNMASKED'],
  selectedActionType: '',
  selectedActorUsername: '',
  selectedLimit: 100,
};

function renderAt(path: string, user: unknown) {
  document.cookie = 'XSRF-TOKEN=terminology-test-token; path=/';
  const masked = (user as { maskedView?: boolean } | null)?.maskedView ?? false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return json({ authenticated: user !== null, user });
      if (url.startsWith('/api/incidents/2/rank/1')) return json(detailResponse(masked));
      if (url.startsWith('/api/incidents')) return json({ ...queueResponse, maskedView: masked });
      if (url.startsWith('/api/reviews')) return json(reviewsResponse(masked));
      if (url.startsWith('/api/operations')) return json({ ...operationsResponse, maskedView: masked });
      if (url.startsWith('/api/admin/users')) return json(usersResponse);
      if (url.startsWith('/api/admin/audit-logs')) return json(auditResponse);
      return json({}, 404);
    }) as unknown as typeof fetch,
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('화면 문구 회귀 검사 함수 자체', () => {
  it('병기·금지 문자열을 잡아내고 data-raw 하위 글만 뺀다', () => {
    const { container, unmount } = render(<div>미해결 (open)</div>);
    expect(() => expectCleanText(container)).toThrow();
    unmount();
    const internal = render(<div>dashboard.latest_incident_queue 기반</div>);
    expect(() => expectCleanText(internal.container)).toThrow();
    internal.unmount();
    const allowed = render(
      <div>
        담당자 <span data-raw="">분석가1 (analyst1)</span> · 관리자 2단계 인증 (TOTP)
      </div>,
    );
    expect(() => expectCleanText(allowed.container)).not.toThrow();
  });
});

describe('화면 문구 회귀 검사(내부 이름·영어 병기 없음)', () => {
  it('로그인 화면', async () => {
    const { container } = renderAt('/login', null);
    expect(await screen.findByRole('heading', { name: 'zeek_AD 보안 관제' })).toBeInTheDocument();
    expect(screen.getByText('로그인을 여러 번 실패하면 잠시 로그인이 제한될 수 있습니다. 관리자 계정은 2단계 인증을 거칩니다.')).toBeInTheDocument();
    expect(container.textContent).not.toContain('15분간 잠깁니다');
    expect(screen.getByLabelText('아이디')).not.toHaveAttribute('placeholder', '예: analyst1');
    expectCleanText(container);
  });

  it('탐지 사건 목록(조회자): 마스킹 안내는 상단 바 한 곳, 시각은 한국 표준시', async () => {
    const { container } = renderAt('/incidents', viewerUser);
    expect(await screen.findByRole('heading', { name: '탐지 사건' })).toBeInTheDocument();
    await screen.findAllByText('192.168.*.*');
    expect(screen.getAllByText('읽기 전용 · 개인정보 가림')).toHaveLength(1);
    expect(container.textContent).not.toMatch(/마스킹/);
    expect(screen.getByText('시각 기준 KST')).toBeInTheDocument();
    expect(screen.getAllByText('2017-07-05 22:45:00').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('연결 수신 측').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('함께 탐지한 모델 +2').length).toBeGreaterThanOrEqual(1);
    expectCleanText(container);
  });

  it('사건 상세(조회자)', async () => {
    const { container } = renderAt('/incidents/2/rank/1', viewerUser);
    expect(await screen.findByText('근거 요약')).toBeInTheDocument();
    expect(screen.getAllByText('읽기 전용 · 개인정보 가림')).toHaveLength(1);
    expect(screen.getByText('이름 종류')).toBeInTheDocument();
    expect(screen.getByText('식별 안 됨')).toBeInTheDocument();
    expect(screen.getByText('http')).not.toHaveAttribute('data-unregistered');
    expect(screen.getByText('컴퓨터 계정')).toBeInTheDocument();
    expect(screen.getByText('2017-07-05 20:54:41')).toBeInTheDocument();
    expect(screen.getByText('탐지 순위 5위 이내(현재 1위)')).toBeInTheDocument();
    expect(screen.getByText('AI 보고서: 분석가 판단 요청 · 판단 모델: 분석가 판단 요청')).toBeInTheDocument();
    expect(screen.getByText('반영 실패(관리자 확인 필요)')).toBeInTheDocument();
    expectCleanText(container);
  });

  it('사건 상세(분석가, 상태 변경 폼 포함)', async () => {
    const { container } = renderAt('/incidents/2/rank/1', analystUser);
    expect(await screen.findByRole('button', { name: '종료 처리' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: '정탐' })).toBeInTheDocument();
    expectCleanText(container);
  });

  it('판단 요청 목록(조회자·분석가)', async () => {
    const viewer = renderAt('/reviews', viewerUser);
    expect(await screen.findByRole('heading', { name: '판단 요청' })).toBeInTheDocument();
    await screen.findAllByText('192.168.*.*');
    expect(screen.getByText('읽기 전용 계정입니다. 판단은 분석가 계정에서 할 수 있습니다.')).toBeInTheDocument();
    expectCleanText(viewer.container);
    viewer.unmount();

    const analyst = renderAt('/reviews', analystUser);
    expect(await screen.findByRole('button', { name: '조사 진행' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '오탐으로 종료' })).toBeInTheDocument();
    expectCleanText(analyst.container);
  });

  it('운영 현황', async () => {
    const { container } = renderAt('/operations', viewerUser);
    expect(await screen.findByText('모든 모델 합계')).toBeInTheDocument();
    expect(screen.getAllByText('실패').length).toBeGreaterThanOrEqual(1);
    expectCleanText(container);
  });

  it('관리자 사용자 관리·감사 로그', async () => {
    const users = renderAt('/admin/users', adminUser);
    expect(await screen.findByRole('heading', { name: '사용자 관리' })).toBeInTheDocument();
    await screen.findByText('analyst1');
    expect(screen.getByText('2단계 인증 미등록')).toBeInTheDocument();
    expectCleanText(users.container);
    users.unmount();

    const audit = renderAt('/admin/audit-logs', adminUser);
    expect(await screen.findByRole('heading', { name: '감사 로그' })).toBeInTheDocument();
    expect((await screen.findAllByText('허용 범위 밖 접근 거부')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByLabelText('사용자 아이디')).not.toHaveAttribute('placeholder', '예: analyst1');
    expectCleanText(audit.container);
  });
});
