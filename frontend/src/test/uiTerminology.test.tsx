import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { DashboardOverviewResponse, IncidentQueueItem, QueuePriority } from '../types/api';
import { fakeQueue, unified } from './fakeQueueServer';
import { EmptyPeriodText, OutsidePeriodNotice } from '../components/OutsidePeriodNotice';
import { SourceSelect } from '../components/ConditionBar';
import { ThreatPanels } from '../components/dashboard/ThreatPanels';
import { OLD_TERMS } from './screenTerms';

/**
 * 화면 문구 회귀 검사(T17): 주요 화면의 보이는 글에 내부 DB·필드 이름과 `한국어 (영어 코드)` 병기가 없어야 한다.
 * 데이터 원문을 그대로 보여 주는 요소(data-raw: 인시던트 ID, 모델 종류·식별자, 모델 버전, 사람 표시, 원본 증적, 리포트 버전 값)만 검사에서 뺀다.
 * T18b: 관제 표준 용어로 바꾸기 전의 풀어 쓴 옛 표기(OLD_TERMS)도 남으면 안 된다(2026-11-21 결정).
 */
const FORBIDDEN = ['dashboard.', 'zeekad_', 'job_id', 'queue_rank', 'evidence.v1', '단계 5'];
// OLD_TERMS(T17·T18 표기 중 T18b~T27에서 바꾼 것)는 T68에서 소스 정적 검사(t68ScreenWording.test.ts)와 함께 쓰려고 screenTerms.ts로 옮겼다.
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
  // T25 처리 시간 지표의 업계 약어(docs/ui-terminology.md "처리 흐름 용어")
  'MTTD',
  'MTTA',
  'MTTR',
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
  for (const word of OLD_TERMS) {
    expect(text, `옛 표기 "${word}"`).not.toContain(word);
  }
  const mixed = [...text.matchAll(PAREN_PATTERN)]
    .filter((m) => !ALLOWED_ABBREVIATIONS.has(m[1]))
    .map((m) => m[0]);
  expect(mixed, '한국어 (영어 코드) 병기').toEqual([]);
  expect(text).not.toContain('정확도');
  // T27: 툴팁에도 작업 번호를 '#'으로 쓰지 않는다
  const titles = Array.from(root.querySelectorAll('[title]')).map((el) => el.getAttribute('title') ?? '');
  expect(titles.filter((t) => t.includes('작업 #')), '툴팁의 작업 # 표기').toEqual([]);
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
  alerted: true,
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
    { ...queueItem, priority: 'high' },
    {
      ...queueItem,
      priority: null,
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
      alerted: false,
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
      claims: [{ claim: '세션이 많습니다.', facts: [{ id: 'F02', name: 'connection_count', value: '155261' }] }],
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
            threadRoleLabel: '최초 알림',
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
      resumeStatusLabel: '에스컬레이션 대기',
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

/** T25 처리 시간·담당 현황 블록 */
const t25Stat = (n: number, median: number | null) => ({ n, medianSeconds: median, p90Seconds: median, excluded: 1, smallSample: n > 0 && n < 10 });

const operationsResponse = {
  handlingTimes: {
    detection: t25Stat(4, 3600),
    acknowledge: t25Stat(12, 600),
    resolve: {
      all: t25Stat(3, 7200),
      byResolution: [
        { resolution: 'true_positive', stat: t25Stat(1, 3600) },
        { resolution: 'false_positive', stat: t25Stat(0, null) },
        { resolution: 'benign', stat: t25Stat(1, 2400) },
        { resolution: 'none', stat: t25Stat(1, 7200) },
      ],
    },
  },
  workload: {
    unclosed: 3,
    assigned: 1,
    unassigned: 2,
    ackOverdue: 1,
    byAssignee: [{ username: 'analyst1', displayName: '분석가1', enabled: false, open: 1, investigating: 0 }],
  },
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
      precisionSummaryText: '표본 부족 · 분석가 판정 1건 / 모델이 올린 인시던트 79건',
      alertPrecisionSummaryText: '표본 부족 · 분석가 판정 1건 / 경보 9건',
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
      precisionSummaryText: '분석가 판정 없음 / 모델이 올린 인시던트 30건',
      alertPrecisionSummaryText: '경보 없음',
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
      payloadTextPreview: '오늘 인시던트 241건',
      payloadChannel: '#sec-alerts',
    },
  ],
};

/** T24 현황판 overview(센서 하나·가져온 데이터 하나) */
const overviewResponse = {
  anchor: '2026-11-21T00:00:00Z',
  anchorMode: 'now',
  snapshot: false,
  period: '24h',
  timeZone: 'Asia/Seoul',
  staleAfterSeconds: 900,
  downAfterSeconds: 3600,
  trend: {
    bucket: '1h',
    buckets: [
      { start: '2026-11-20T22:00:00Z', end: '2026-11-20T23:00:00Z', partial: false, high: 1, medium: 0, low: 1, none: 0, total: 2 },
      { start: '2026-11-20T23:00:00Z', end: '2026-11-21T00:00:00Z', partial: false, high: 0, medium: 1, low: 0, none: 1, total: 2 },
    ],
    unbucketed: { noDetectedAt: 0, afterAnchor: 0 },
  },
  sensors: [
    {
      sensorKey: 'lab-*',
      label: '실습망 센서',
      health: 'stale',
      latestJob: { jobId: 70, captureId: 'lab-20261119', bundleId: 'zeekad-fusion/3', status: 'succeeded', startedAt: null, finishedAt: '2026-11-20T23:30:00Z', error: null },
      activeCaptureId: 'lab-20261119',
      lastScoredAt: '2026-11-20T23:30:00Z',
      lastActivityAt: null,
      total: 0,
      high: 0,
      alerted: 0,
      failedJobs: 0,
      captureCount: 1,
    },
  ],
  captures: [
    { captureId: 'lab-20261119', sourceType: 'live', sensorKey: 'lab-*', state: 'active', latestJob: null, lastScoredAt: '2026-11-20T23:30:00Z', lastActivityAt: null, total: 0, high: 0, alerted: 0, failedJobs: 0 },
    { captureId: 'cic17-wed', sourceType: 'imported', sensorKey: null, state: 'failed', latestJob: { jobId: 1, captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', status: 'failed', startedAt: null, finishedAt: '2026-11-20T00:00:00Z', error: '근거 API 시간 초과' }, lastScoredAt: '2026-11-12T02:27:00Z', lastActivityAt: '2026-11-12T02:00:00Z', total: 4, high: 1, alerted: 1, failedJobs: 1 },
  ],
  alerting: { latestDeliveryMode: 'dry_run', latestDeliveryStatus: 'recorded', latestDryRun: true, latestCreatedAt: '2026-11-20T15:40:00Z', latestDeliveredAt: null, latestCaptureId: 'cic17-wed', summariesInPeriod: 1 },
  maskedView: false,
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

/** T46 호스트 위험도 목록(조회자면 가려진 대역 한 줄) */
function hostRiskResponse(masked: boolean) {
  return {
    items: [
      {
        hostIp: masked ? '192.168.*.*' : '192.168.10.50',
        hostNames: ['dc01.corp.local', 'ad-primary'],
        hostNameCount: 2,
        accounts: masked ? ['j***'] : ['jdoe.admin'],
        accountCount: 1,
        high: 1,
        medium: 0,
        low: 2,
        incidents: 4,
        connections: 512,
        models: ['tgn_recon', 'tail_rarity_v2'],
        lastDetectedAt: '2026-11-16T03:08:00Z',
        roleTransition: !masked,
      },
    ],
    total: 1,
    page: 1,
    size: 50,
    pageCount: 1,
    anchor: '2026-11-20T01:30:00Z',
    anchorMode: 'latest-data',
    snapshot: true,
    period: '7d',
    periodStart: '2026-11-13T01:30:00Z',
    periodEnd: '2026-11-20T01:30:00Z',
    sources: [{ captureId: 'cic17-wed', sourceType: 'imported', latestJobId: null, lastDetectedAt: null }],
    maskedView: masked,
  };
}

/** T46 상세 요약 탭의 같은 호스트 인시던트(10건을 넘어 "전체 보기"가 보이는 경우) */
function relatedHostResponse(masked: boolean) {
  const hostIp = masked ? '192.168.*.*' : '192.168.10.50';
  return {
    hostIp,
    total: 12,
    maskedView: masked,
    items: [
      {
        incidentNo: 1042,
        jobId: 2,
        queueRank: 5,
        captureId: 'cic17-wed',
        hostIp,
        zeekadRole: 'responder',
        eventStart: '2017-07-05T10:15:00Z',
        detectedAt: '2026-11-16T03:08:00Z',
        priority: null,
        zeekadStatus: 'closed',
        zeekadResolution: 'false_positive',
        zeekadPickedBy: 'transformer_v2',
        connectionCount: 85,
      },
      {
        incidentNo: null,
        jobId: 2,
        queueRank: 6,
        captureId: 'lab-20261119',
        hostIp,
        zeekadRole: 'originator',
        eventStart: '2017-07-05T16:15:00Z',
        detectedAt: '2026-11-16T03:08:00Z',
        priority: 'medium',
        zeekadStatus: 'investigating',
        zeekadResolution: null,
        zeekadPickedBy: 'tgn_recon',
        connectionCount: 12,
      },
    ],
  };
}

function renderAt(path: string, user: unknown, overrides: { queue?: unknown } = {}) {
  document.cookie = 'XSRF-TOKEN=terminology-test-token; path=/';
  const masked = (user as { maskedView?: boolean } | null)?.maskedView ?? false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return json({ authenticated: user !== null, user });
      // T46: 상세 주소로 시작하므로 상세 분기보다 먼저 본다
      if (url.startsWith('/api/incidents/2/rank/1/related-host-incidents')) return json(relatedHostResponse(masked));
      if (url.startsWith('/api/hosts')) return json(hostRiskResponse(masked));
      if (url.startsWith('/api/incidents/2/rank/1')) return json(detailResponse(masked));
      if (url.startsWith('/api/incidents/queue/neighbors'))
        return json({ current: null, position: null, total: 0, prev: null, next: null });
      if (url.startsWith('/api/incidents/queue')) {
        // T23: 통합 큐. 우선순위는 시험 데이터가 정한 서버 값이다.
        const q = (overrides.queue ?? queueResponse) as {
          incidents: (IncidentQueueItem & { priority?: QueuePriority | null })[];
          availableModels: string[];
        };
        return json(
          fakeQueue(url, {
            items: q.incidents.map((i) => unified(i, { priority: i.priority ?? null })),
            maskedView: masked,
            availableModels: q.availableModels,
          }),
        );
      }
      if (url.startsWith('/api/reviews')) return json(reviewsResponse(masked));
      if (url.startsWith('/api/operations')) return json({ ...operationsResponse, maskedView: masked });
      if (url.startsWith('/api/dashboard/overview')) return json({ ...overviewResponse, maskedView: masked });
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
    allowed.unmount();
    // T18b: 옛 표기는 잡고, data-raw 원문 영역 안의 글은 뺀다.
    const old = render(<div>탐지 사건 목록</div>);
    expect(() => expectCleanText(old.container)).toThrow();
    old.unmount();
    const rawOld = render(
      <div>
        인시던트 <span data-raw="">연결 수 원문</span>
      </div>,
    );
    expect(() => expectCleanText(rawOld.container)).not.toThrow();
  });
});

describe('관제 표준 용어(T18b)', () => {
  it('메뉴·상태·판정·검토 결정·통신 방향·우선순위·탐지 모델이 새 표기로 보인다', async () => {
    const base = { ...queueResponse.incidents[0], alerted: false };
    const queue = {
      ...queueResponse,
      incidents: [
        // High: 발송 판단 발송, 에스컬레이션 대기, 목적지, 분석 중 (경보 발송 = 사건 알림 기록 있음)
        { ...base, priority: 'high', queueRank: 1, incidentId: 'a|1', zeekadStatus: 'investigating', zeekadRole: 'responder', alerted: true },
        // Medium: 교차 탐지, 승인, 출발지, 신규
        {
          ...base,
          priority: 'medium',
          queueRank: 2,
          incidentId: 'a|2',
          zeekadStatus: 'open',
          zeekadRole: 'originator',
          zeekadPickedBy: 'tail_rarity_v2',
          zeekadAlsoFlaggedBy: ['tgn_recon'],
          zeekadReportJobId: null,
          hasReport: false,
          zeekadReportKind: null,
          zeekadVerificationPassed: null,
          zeekadWouldSend: false,
          zeekadReviewAction: 'confirm',
          zeekadReviewPending: false,
        },
        // Low
        {
          ...base,
          priority: 'low',
          queueRank: 3,
          incidentId: 'a|3',
          zeekadStatus: 'open',
          zeekadPickedBy: 'transformer_v2',
          zeekadAlsoFlaggedBy: [],
          zeekadReportJobId: null,
          hasReport: false,
          zeekadReportKind: null,
          zeekadVerificationPassed: null,
          zeekadWouldSend: false,
          zeekadReviewAction: null,
          zeekadReviewPending: false,
        },
        // 종결 · 오탐 · 오탐 종결
        {
          ...base,
          priority: null,
          queueRank: 4,
          incidentId: 'a|4',
          zeekadStatus: 'closed',
          zeekadResolution: 'false_positive',
          zeekadReviewAction: 'dismiss',
          zeekadReviewPending: false,
          zeekadWouldSend: false,
        },
        // 종결 · 정탐 / 종결 · 정상
        {
          ...base,
          priority: null,
          queueRank: 5,
          incidentId: 'a|5',
          zeekadStatus: 'closed',
          zeekadResolution: 'true_positive',
          zeekadReviewPending: false,
          zeekadWouldSend: false,
        },
        {
          ...base,
          priority: null,
          queueRank: 6,
          incidentId: 'a|6',
          zeekadStatus: 'closed',
          zeekadResolution: 'benign',
          zeekadReviewPending: false,
          zeekadWouldSend: false,
        },
      ],
    };
    const { container } = renderAt('/incidents', analystUser, { queue });
    expect(await screen.findByRole('heading', { name: '인시던트' })).toBeInTheDocument();

    const nav = screen.getByRole('navigation', { name: '주 메뉴' });
    expect(within(nav).getByRole('link', { name: '인시던트' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: '에스컬레이션' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: '운영 현황' })).toBeInTheDocument();

    const table = await screen.findByRole('table');
    // T23: 순위 열이 없다. 서버 순서(우선순위 → 탐지 시각 → 캡처 → 순위)가 시험 데이터의 순위 순서와 같다.
    const row = (rank: number) => {
      const found = within(table).getAllByRole('row').slice(1)[rank - 1];
      if (!found) throw new Error(`순위 ${rank} 행 없음`);
      return found;
    };
    // 상태
    expect(within(row(1)).getByText('분석 중')).toBeInTheDocument();
    expect(within(row(2)).getByText('신규')).toBeInTheDocument();
    expect(within(row(4)).getByText('종결')).toBeInTheDocument();
    // 판정
    expect(within(row(5)).getByText('정탐')).toBeInTheDocument();
    expect(within(row(4)).getByText('오탐')).toBeInTheDocument();
    expect(within(row(6)).getByText('정상')).toBeInTheDocument();
    // 검토 결정
    expect(within(row(2)).getByText('승인')).toBeInTheDocument();
    expect(within(row(4)).getByText('오탐 종결')).toBeInTheDocument();
    expect(within(row(1)).getByText('대기')).toBeInTheDocument();
    // 통신 방향
    expect(within(row(1)).getByText('목적지')).toBeInTheDocument();
    expect(within(row(2)).getByText('출발지')).toBeInTheDocument();
    // 우선순위(표와 요약 띠)
    expect(within(row(1)).getByText('High')).toBeInTheDocument();
    expect(within(row(2)).getByText('Medium')).toBeInTheDocument();
    expect(within(row(3)).getByText('Low')).toBeInTheDocument();
    const strip = screen.getByRole('region', { name: '인시던트 요약' });
    expect(within(strip).getByRole('button', { name: '우선순위 High 1건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByRole('button', { name: '우선순위 Medium 1건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByRole('button', { name: '우선순위 Low 1건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByRole('button', { name: '에스컬레이션 대기 1건만 보기' })).toBeInTheDocument();
    expect(within(strip).getByRole('button', { name: '경보 발송 1건만 보기' })).toBeInTheDocument();
    // 탐지 모델: 표에는 표시 이름만(식별자는 툴팁)
    expect(within(row(1)).getByText('통신 관계 이상')).toHaveAttribute('title', expect.stringContaining('TGN(시간 그래프 신경망) · tgn_recon'));
    expect(within(row(2)).getByText('기준선 이탈')).toBeInTheDocument();
    expect(within(row(3)).getByText('행위 패턴 이탈')).toBeInTheDocument();
    expect(within(table).queryByText('tgn_recon')).toBeNull();
    // 필터의 탐지 모델 선택지는 표시 이름, 값은 식별자
    await userEvent.setup().click(screen.getByRole('button', { name: /^필터(\s\d+)?$/ }));
    const modelSelect = screen.getByLabelText('탐지 모델');
    expect(within(modelSelect).getByRole('option', { name: '기준선 이탈' })).toHaveValue('tail_rarity_v2');
    expect(within(modelSelect).getByRole('option', { name: '통신 관계 이상' })).toHaveValue('tgn_recon');
    expectCleanText(container);
  });
});

describe('화면 문구 회귀 검사(내부 이름·영어 병기 없음)', () => {
  it('로그인 화면', async () => {
    const { container } = renderAt('/login', null);
    expect(await screen.findByRole('heading', { name: 'NBAD 보안 관제' })).toBeInTheDocument();
    expect(screen.getByText('로그인을 여러 번 실패하면 잠시 로그인이 제한될 수 있습니다. 관리자 계정은 2단계 인증을 거칩니다.')).toBeInTheDocument();
    expect(container.textContent).not.toContain('15분간 잠깁니다');
    expect(screen.getByLabelText('아이디')).not.toHaveAttribute('placeholder', '예: analyst1');
    expectCleanText(container);
  });

  it('인시던트 목록(조회자): 마스킹 안내는 상단 바 한 곳, 시각은 한국 표준시', async () => {
    const { container } = renderAt('/incidents', viewerUser);
    expect(await screen.findByRole('heading', { name: '인시던트' })).toBeInTheDocument();
    await screen.findAllByText('192.168.*.*');
    expect(screen.getAllByText('마스킹 적용')).toHaveLength(1);
    // T18b: 안내 문구가 "마스킹 적용"이 되었으므로 "마스킹"이 상단 바 한 곳에만 나오는지로 같은 뜻을 단언한다.
    expect(container.textContent?.match(/마스킹/g) ?? []).toHaveLength(1);
    expect(screen.getByText('시각 기준 KST')).toBeInTheDocument();
    // T18: 표와 휴대폰 목록이 함께 DOM에 있으므로 표 범위로 좁힌다. 함께 탐지 수는 '+2' 글 대신 읽기 프로그램용 글로 같은 값을 단언한다.
    const table = screen.getByRole('table');
    // T23 7절: 표의 발생 시각은 초 없이(해가 기준 시각과 다르면 연도 포함), 전체 구간(초 포함)은 칸 툴팁에 있다. 둘 다 KST다.
    expect(within(table).getAllByText('2017-07-05 22:45').length).toBeGreaterThanOrEqual(1);
    expect(within(table).getAllByTitle(/^발생 구간 2017-07-05 22:45:00/).length).toBeGreaterThanOrEqual(1);
    expect(within(table).getAllByText('목적지').length).toBeGreaterThanOrEqual(1);
    expect(within(table).getAllByText('교차 탐지 모델 2개').length).toBeGreaterThanOrEqual(1);
    expectCleanText(container);
  });

  it('인시던트 상세(조회자)', async () => {
    const user = userEvent.setup();
    const { container } = renderAt('/incidents/2/rank/1', viewerUser);
    const panel = () => screen.getByRole('tabpanel');
    const openTab = async (name: string) => user.click(screen.getByRole('tab', { name }));
    expect(await screen.findByRole('tab', { name: '요약', selected: true })).toBeInTheDocument();
    expect(screen.getAllByText('마스킹 적용')).toHaveLength(1);
    // T18b: 상세에는 탐지 모델 표시 이름과 "모델 종류 · 식별자"(data-raw)가 함께 보인다(헤더·요약 탭의 모델별 탐지 윈도우).
    expect(screen.getAllByText('통신 관계 이상').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('TGN(시간 그래프 신경망) · tgn_recon')).toHaveAttribute('data-raw');
    expect(within(panel()).getByText('통계 기준선 · tail_rarity_v2')).toHaveAttribute('data-raw');
    expect(screen.getByText('교차 탐지 +2')).toBeInTheDocument();
    // 조치 패널(읽기 전용): 에스컬레이션 요청 사유와 반영 상태
    const actions = screen.getByRole('region', { name: '조치' });
    expect(within(actions).getByText('AI 리포트: 에스컬레이션 · 판단 모델: 에스컬레이션')).toBeInTheDocument();
    expect(within(actions).getByText('반영 실패(관리자 확인 필요)')).toBeInTheDocument();
    expect(within(actions).queryByRole('button', { name: '종결 처리' })).toBeNull();
    expectCleanText(container);

    await openTab('증적');
    expect(within(panel()).getByText('증적 요약')).toBeInTheDocument();
    expect(within(panel()).getByText('식별 안 됨')).toBeInTheDocument();
    expect(within(panel()).getByText('http')).not.toHaveAttribute('data-unregistered');
    // T19: 관측 계정은 이름·종류·마지막 관측만(출처 로그·관측 횟수·처음 관측은 화면에서 뺐다)
    expect(within(panel()).getByRole('columnheader', { name: '종류' })).toBeInTheDocument();
    expect(within(panel()).getByText('컴퓨터 계정')).toBeInTheDocument();
    expect(within(panel()).getByText('2017-07-06 05:00:33')).toBeInTheDocument();
    expect(within(panel()).queryByText('출처 로그')).toBeNull();
    expect(within(panel()).queryByText('2017-07-05 20:54:41')).toBeNull();
    expect(within(panel()).getByText('주요 세션 (최대 10건)')).toBeInTheDocument();
    // 세션 표의 열은 사건 단위 통신 방향(출발지·목적지)과 구분해 IP를 붙인다(T19: 필드별 열 "출발지 IP:포트").
    expect(within(panel()).getByRole('columnheader', { name: '출발지 IP:포트' })).toBeInTheDocument();
    expectCleanText(container);

    await openTab('발송 판단');
    expect(within(panel()).getByText('탐지 순위 5위 이내(현재 1위)')).toBeInTheDocument();
    await openTab('Slack');
    expect(within(panel()).getByText('최초 알림')).toBeInTheDocument();
    expect(within(panel()).getAllByText('Dry-run').length).toBeGreaterThanOrEqual(1);
    await openTab('AI 리포트');
    expect(within(panel()).getByText('대상 호스트 H가 외부와 대량 연결을 주고받았습니다.')).toBeInTheDocument();
    await openTab('이력');
    expect(within(panel()).getByText('에스컬레이션 요청')).toBeInTheDocument();
    expectCleanText(container);
  });

  it('인시던트 상세(분석가, 상태 변경 폼 포함)', async () => {
    const { container } = renderAt('/incidents/2/rank/1', analystUser);
    expect(await screen.findByRole('button', { name: '종결 처리' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: '정탐' })).toBeInTheDocument();
    expect(
      screen.getByText('에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).'),
    ).toBeInTheDocument();
    expectCleanText(container);
  });

  it('T21: 발송 판단(wouldSend)을 그리는 요소에는 "경보 발송"이 없다(목록 칩·필터·상세 발송 판단 탭)', async () => {
    const user = userEvent.setup();
    const list = renderAt('/incidents', analystUser);
    const table = await screen.findByRole('table');
    // 목록 행 칩: 발송 판단 발송/보류
    expect(within(table).getByRole('img', { name: '발송 판단: 발송' })).toHaveAttribute('title', '발송 판단: 발송');
    expect(within(table).getByRole('img', { name: '발송 판단: 보류' })).toBeInTheDocument();
    for (const img of within(table).getAllByRole('img', { name: /발송 판단/ })) {
      expect(img.getAttribute('aria-label')).not.toContain('경보 발송');
      expect(img.getAttribute('title') ?? '').not.toContain('경보 발송');
    }
    // 필터 드롭다운(서버 wouldSend 파라미터)
    await user.click(screen.getByRole('button', { name: /^필터(\s\d+)?$/ }));
    const select = screen.getByLabelText('발송 판단');
    expect(within(select).getByRole('option', { name: '발송' })).toHaveValue('true');
    expect(select.textContent).not.toContain('경보 발송');
    list.unmount();

    const detail = renderAt('/incidents/2/rank/1?tab=decision', analystUser);
    const tab = await screen.findByRole('tab', { name: '발송 판단', selected: true });
    expect(tab).toBeInTheDocument();
    const decisionPanel = screen.getByRole('tabpanel');
    // T68(A8): 규칙 의견의 선택지 send도 최종 판단처럼 "발송"이다(전에는 "전송"). 최종 + 규칙 의견 두 곳
    expect(within(decisionPanel).getAllByText('발송').length).toBeGreaterThanOrEqual(2);
    expect(decisionPanel.textContent).not.toContain('전송');
    expect(decisionPanel.textContent).not.toContain('경보 발송');
    // 상세 헤더의 경보 발송은 사건 알림 기록(alerted) 값이다
    expect(within(screen.getByRole('region', { name: '인시던트 요약' })).getByText('경보 발송')).toBeInTheDocument();
    expectCleanText(detail.container);
  });

  it('에스컬레이션 목록(조회자·분석가)', async () => {
    const viewer = renderAt('/reviews', viewerUser);
    expect(await screen.findByRole('heading', { name: '에스컬레이션' })).toBeInTheDocument();
    await screen.findAllByText('192.168.*.*');
    expect(screen.getByText('읽기 전용 계정입니다. 검토 결정은 분석가 계정에서 할 수 있습니다.')).toBeInTheDocument();
    // T21: 관계 안내(새 문구)는 에스컬레이션 화면에도 있다
    expect(
      screen.getByRole('note', { name: '에스컬레이션 결정과 상태' }),
    ).toHaveTextContent('에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).');
    expectCleanText(viewer.container);
    viewer.unmount();

    const analyst = renderAt('/reviews', analystUser);
    expect(await screen.findByRole('button', { name: '승인' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '오탐 종결' })).toBeInTheDocument();
    expectCleanText(analyst.container);
  });

  it('현황판(첫 화면)', async () => {
    const { container } = renderAt('/', viewerUser);
    expect(await screen.findByRole('heading', { name: '현황판' })).toBeInTheDocument();
    // T24: 시간·수집원 기준 KPI와 패널. 옛 "전체 인시던트"·"판정 완료"·"데이터 기준"·"캡처별 현황"은 없다(OLD_TERMS)
    expect(await screen.findByText('탐지된 인시던트')).toBeInTheDocument();
    // T68(A11): "경보 발송 상태" → "Slack 일일 요약 상태"(일일 요약 기록만 보이는 패널)
    for (const name of ['핵심 지표', '탐지 추이', '최근 인시던트', '수집원 상태', 'Slack 일일 요약 상태']) {
      expect(await screen.findByRole('region', { name })).toBeInTheDocument();
    }
    // 수집원은 짧은 이름이 보이고 전체 이름(zeek_AD Q65)·캡처 ID는 툴팁·판독기 글자에 있다
    expect((await screen.findAllByText('CIC 수')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('실습망 센서')).toBeInTheDocument();
    expect(screen.getByText('지연')).toBeInTheDocument();
    expect(screen.getByText('실패')).toBeInTheDocument();
    expect(screen.getAllByText('통신 관계 이상').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Dry-run')).toBeInTheDocument();
    expectCleanText(container);
  });

  it('운영 현황', async () => {
    const { container } = renderAt('/operations', viewerUser);
    expect(await screen.findByText('모든 모델 합계')).toBeInTheDocument();
    // T20: 탐지 모델별 행은 펼쳐야 보인다.
    await userEvent.setup().click(screen.getByRole('button', { name: /탐지 모델별 1개 펼치기/ }));
    // T18b: 결론 집계의 모델·임계값 키도 탐지 모델 표시 이름 사전을 쓴다.
    expect(screen.getAllByText('통신 관계 이상').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('실패').length).toBeGreaterThanOrEqual(1);
    // T24: 수집원 상태 표와 누적 표시
    expect(await screen.findByRole('region', { name: '수집원 상태 표' })).toBeInTheDocument();
    expect(screen.getByText('누적(기간 없음)')).toBeInTheDocument();
    expect(screen.getAllByText('지연').length).toBeGreaterThanOrEqual(1);
    // T25 처리 흐름 용어(docs/ui-terminology.md "처리 흐름 용어")
    const handling = screen.getByRole('region', { name: '처리 시간' });
    for (const term of ['탐지 지연(MTTD)', '착수 시간(MTTA)', '처리 시간(MTTR)', '중앙값', 'p90', '제외', '표본 부족', '판정 없음', '실습망만']) {
      expect(handling, term).toHaveTextContent(term);
    }
    const workload = screen.getByRole('region', { name: '담당 현황' });
    for (const term of ['미종결', '배정', '미배정', '착수 지연', '담당자', '비활성']) {
      expect(workload, term).toHaveTextContent(term);
    }
    // 지표 이름에 평균을 쓰지 않는다(중앙값·p90)
    for (const th of within(handling).getAllByRole('rowheader')) expect(th.textContent).not.toContain('평균');
    expectCleanText(container);
  });

  it('T46 호스트 위험도(분석가·조회자)', async () => {
    const analyst = renderAt('/hosts', analystUser);
    expect(await screen.findByRole('heading', { name: '호스트 위험도' })).toBeInTheDocument();
    const table = await screen.findByRole('table');
    for (const term of ['미종결 우선순위', '인시던트', '세션 수', '탐지 모델', '관측 계정', '마지막 탐지', '방향 전환']) {
      expect(table, term).toHaveTextContent(term);
    }
    // 화면 글은 "전환"이다("전이"는 T17에서 화면 용어에서 뺐다). 탐지 모델은 표시 이름이다
    expect(screen.getAllByText('목적지 → 출발지 전환').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('통신 관계 이상').length).toBeGreaterThanOrEqual(1);
    expect(analyst.container.textContent).not.toContain('전이');
    for (const title of Array.from(analyst.container.querySelectorAll('[title]')).map((el) => el.getAttribute('title') ?? '')) {
      expect(title).not.toContain('전이');
    }
    expectCleanText(analyst.container);
    analyst.unmount();

    const viewer = renderAt('/hosts', viewerUser);
    expect(await screen.findByText(/같은 대역\(A\.B\.\*\.\*\)의 호스트 전부입니다/)).toBeInTheDocument();
    await screen.findByRole('table');
    expect(screen.getAllByText('192.168.*.*').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('목적지 → 출발지 전환')).toBeNull();
    // 마스킹 안내는 상단 바 한 곳뿐이다
    expect(screen.getAllByText(/마스킹/)).toHaveLength(1);
    expectCleanText(viewer.container);
  });

  it('T46 상세 요약 탭의 같은 호스트 인시던트(분석가·조회자)', async () => {
    const analyst = renderAt('/incidents/2/rank/1', analystUser);
    const heading = await screen.findByRole('heading', { name: '같은 호스트의 다른 인시던트' });
    const section = heading.closest('section') as HTMLElement;
    await within(section).findByText('#1042');
    for (const term of ['이 인시던트 외 12건', '가까운 2건', '전체 보기', '목적지', '출발지', '종결', '분석 중', '오탐', '행위 패턴 이탈', '상세 보기']) {
      expect(section, term).toHaveTextContent(term);
    }
    expect(section).toHaveTextContent(/\d+(분|시간|일) (전|뒤)/);
    expectCleanText(analyst.container);
    analyst.unmount();

    const viewer = renderAt('/incidents/2/rank/1', viewerUser);
    const masked = await screen.findByRole('heading', { name: '같은 대역(192.168.*.*) 인시던트' });
    await within(masked.closest('section') as HTMLElement).findByText('#1042');
    expect(screen.queryByRole('heading', { name: '같은 호스트의 다른 인시던트' })).toBeNull();
    expect(screen.getAllByText(/마스킹/)).toHaveLength(1);
    expectCleanText(viewer.container);
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

describe('T29 기간 밖 안내·수집원 목록 문구', () => {
  it('한 줄 안내·빈 결과 안내·수집원 목록에 내부 이름·영어 병기가 없다', () => {
    const items = [
      unified({ ...queueResponse.incidents[0], captureId: 'cic17-wed' } as IncidentQueueItem, { detectedAt: '2026-11-12T03:10:00Z' }),
      unified({ ...queueResponse.incidents[0], captureId: 'lab-20261119', queueRank: 2 } as IncidentQueueItem, { detectedAt: '2026-11-20T01:00:00Z' }),
    ];
    const opts = {
      items,
      anchor: '2026-11-20T01:30:00Z',
      snapshot: true,
      newestOutsidePeriod: '2026-11-12T03:10:00Z',
      newestOutsideAlways: true,
      lastDetected: { 'cic17-wed': '2026-11-12T03:10:00Z', 'lab-20261119': '2026-11-20T01:00:00Z' },
      periodFilter: (it: { captureId: string }, period: string) => period === 'all' || it.captureId.startsWith('lab-'),
    };
    const some = fakeQueue('/api/incidents/queue?period=24h', opts);
    const none = fakeQueue('/api/incidents/queue?period=24h&captureId=cic17-wed', opts);
    const { container } = render(
      <div>
        <OutsidePeriodNotice queue={some} onAllPeriod={() => undefined} />
        <EmptyPeriodText queue={none} sourceValue="cap:cic17-wed" />
        <SourceSelect sources={some.sources} value="" onChange={() => undefined} anchor={some.anchor} snapshot />
      </div>,
    );
    expect(container.textContent).toContain('선택한 기간 밖 인시던트 1건');
    expect(container.textContent).toContain('마지막 탐지 11-12 12:10(기준 시각 7일 전)');
    expectCleanText(container);
  });
});

describe('T45b 현황판 위협 가시성 패널 문구', () => {
  it('ATT&CK 후보·위험 호스트·주요 알림 묶음(조회자, 값이 있을 때와 계산 생략·빈 값)에 내부 이름·영어 병기가 없다', () => {
    const base = {
      anchor: '2026-11-21T00:00:00Z',
      maskedView: true,
    } as DashboardOverviewResponse;
    const full: DashboardOverviewResponse = {
      ...base,
      attack: {
        incidentsWithCandidates: 3,
        tactics: [
          { tactic: 'credential-access', count: 2 },
          { tactic: 'custom-stage', count: 1 },
        ],
        techniques: [
          { attackId: 'T1059', name: 'Command and Scripting Interpreter', count: 2 },
          { attackId: 'T1110', name: null, count: 1 },
        ],
        techniqueCount: 12,
      },
      topHosts: {
        originator: [{ hostIp: '10.50.*.*', high: 2, medium: 1, low: 0, total: 4, lastDetectedAt: '2026-11-20T10:00:00Z' }],
        responder: [],
      },
      topThreads: [
        { headIncidentNo: 41, headHostIp: '10.80.*.*', headPickedBy: 'tgn_recon', periodIncidentCount: 2, totalMemberCount: 3, latestDetectedAt: '2026-11-20T10:00:00Z' },
        { headIncidentNo: 7, headHostIp: null, headPickedBy: null, periodIncidentCount: 2, totalMemberCount: 2, latestDetectedAt: null },
      ],
      topThreadsOmitted: false,
    };
    const { container } = render(
      <MemoryRouter>
        <ThreatPanels overview={full} listQuery={(extra) => new URLSearchParams({ period: '24h', ...extra }).toString()} />
        <ThreatPanels overview={{ ...base, topThreads: [], topThreadsOmitted: true }} listQuery={() => 'period=24h'} />
      </MemoryRouter>,
    );
    expect(container.textContent).toContain('확정이 아닌 가설 · 후보가 있는 인시던트 3건');
    expect(container.textContent).toContain('기간 내 2건 · 전체 3건');
    expect(container.textContent).toContain('묶음 2건');
    expect(container.textContent).toContain('외 10개');
    expect(container.textContent).toContain('알림 묶음이 많아 묶음 계산을 생략했습니다.');
    // 화면 이름은 "주요 알림 묶음"이다(Slack 스레드로 묶인 알림이지 공격으로 확정된 묶음이 아니다)
    expect(container.textContent).not.toContain('공격 묶음');
    expectCleanText(container);
  });
});
