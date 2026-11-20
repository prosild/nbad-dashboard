import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

function renderWithAnalyst(initialEntry: string, fetchImpl: typeof fetch) {
  document.cookie = 'XSRF-TOKEN=xsrf-test-token; path=/';
  vi.stubGlobal('fetch', fetchImpl);
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

const analystMeResponse = () =>
  new Response(
    JSON.stringify({
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
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );

describe('조사 큐 및 사건 상세 화면', () => {
  it('조사 큐 KPI 카드, 30분 초과 지속 시간, 보고서 없음 및 필터를 렌더링한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return analystMeResponse();
      if (url.startsWith('/api/incidents')) {
        return new Response(
          JSON.stringify({
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
              incidentCount: 2,
            },
            captureJobs: [
              {
                jobId: 42,
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                status: 'succeeded',
                startedAt: null,
                finishedAt: null,
                error: null,
                incidentCount: 2,
              },
            ],
            incidents: [
              {
                jobId: 42,
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                queueRank: 1,
                incidentId: 'cic17-wed|192.168.10.5|originator|100',
                hostIp: '192.168.10.5',
                zeekadRole: 'originator',
                eventStart: '2026-11-18T01:00:00Z',
                eventEnd: '2026-11-18T01:45:00Z',
                zeekadPickedBy: 'ae_v2',
                zeekadAlsoFlaggedBy: ['iforest_v1'],
                connectionCount: 180,
                hostName: ['ws-01.lab'],
                zeekadStatus: 'open',
                zeekadResolution: null,
                statusUpdatedAt: null,
                zeekadReportJobId: 40,
                hasReport: true,
                zeekadReportKind: 'llm',
                zeekadVerificationPassed: true,
                zeekadWouldSend: true,
                zeekadReviewAction: null,
                zeekadReviewPending: true,
              },
              {
                jobId: 42,
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                queueRank: 2,
                incidentId: 'cic17-wed|192.168.10.8|responder|200',
                hostIp: '192.168.10.8',
                zeekadRole: 'responder',
                eventStart: '2026-11-18T02:00:00Z',
                eventEnd: '2026-11-18T02:10:00Z',
                zeekadPickedBy: 'iforest_v1',
                zeekadAlsoFlaggedBy: [],
                connectionCount: 25,
                hostName: [],
                zeekadStatus: 'closed',
                zeekadResolution: 'benign',
                statusUpdatedAt: '2026-11-18T03:00:00Z',
                zeekadReportJobId: null,
                hasReport: false,
                zeekadReportKind: null,
                zeekadVerificationPassed: null,
                zeekadWouldSend: false,
                zeekadReviewAction: 'dismiss',
                zeekadReviewPending: false,
              },
            ],
            availableModels: ['ae_v2', 'iforest_v1'],
            availableRoles: ['originator', 'responder'],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    renderWithAnalyst('/incidents', fetchMock as unknown as typeof fetch);

    expect(await screen.findByText('192.168.10.5')).toBeInTheDocument();
    expect(screen.getByText('지속 45분')).toBeInTheDocument();
    expect(screen.getByText('함께 탐지한 모델 +1')).toBeInTheDocument();
    expect(screen.getAllByText('보고서 없음').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByTitle('보고서 실행 #40')).toBeInTheDocument();
    expect(screen.getByText('전체 사건 수')).toBeInTheDocument();
  });

  it('사건 상세에서 F* 근거 펼침, 선택 확률, Slack 스레드, 상태 전이, 검토 결정 및 XSS 이스케이프를 검증한다', async () => {
    const xssPayload = '<script>window.__xss=1</script><img src=x onerror=alert(1)>';
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return analystMeResponse();
      if (url === '/api/incidents/42/rank/1' && (!init?.method || init.method === 'GET')) {
        return new Response(
          JSON.stringify({
            maskedView: false,
            canDecideReview: true,
            detail: {
              incident: {
                jobId: 42,
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                queueRank: 1,
                incidentId: 'cic17-wed|192.168.10.5|originator|100',
                hostIp: '192.168.10.5',
                zeekadRole: 'originator',
                eventStart: '2026-11-18T01:00:00Z',
                eventEnd: '2026-11-18T01:45:00Z',
                zeekadPickedBy: 'ae_v2',
                zeekadAlsoFlaggedBy: [],
                connectionCount: 180,
                hostName: [xssPayload],
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
              },
              job: null,
              modelScores: [
                {
                  jobId: 42,
                  incidentId: 'cic17-wed|192.168.10.5|originator|100',
                  zeekadModel: 'ae_v2',
                  candidateWindows: 6,
                  windows: 9,
                  windowRatioLabel: '6 / 9',
                },
              ],
              assetNames: [
                {
                  captureId: 'cic17-wed',
                  hostIp: '192.168.10.5',
                  kerberosUser: 'alice',
                  ntlmUser: null,
                  extraAttributes: { observation_count: 4 },
                },
              ],
              evidence: {
                available: false,
                statusMessage: '상세 근거를 불러오지 못했습니다. 기본 정보만 표시합니다.',
                connectionCount: null,
                bytesSent: null,
                bytesReceived: null,
                payloadBytesInflated: null,
                transportCounts: {},
                serviceProtocolCounts: {},
                connStateCounts: {},
                topPeers: [],
                uniquePeers: null,
                topPorts: [],
                uniquePorts: null,
                protocolLogs: [],
                representativeConnections: [],
                limits: [],
                additionalFields: {},
              },
              report: {
                present: true,
                reportKind: 'llm',
                reportVersion: 'llm-report.v1',
                inputVersion: 'evidence.v1',
                llmModelRequested: 'gemini',
                llmModelVersion: 'gemini-2.5',
                llmSeconds: 1.4,
                llmInputTokens: 500,
                llmOutputTokens: 200,
                llmThinkingTokens: 50,
                llmError: null,
                verificationPassed: true,
                verificationReason: null,
                verificationProblems: [],
                createdAt: '2026-11-18T01:50:00Z',
                sourceRun: 'run-1',
                pseudonyms: { H: '192.168.10.5' },
                observationSummary: `관측 요약 ${xssPayload}`,
                claims: [
                  {
                    claim: '다수의 외부 443 연결이 관측되었습니다.',
                    facts: [{ id: 'F1', name: 'outbound_443_count', value: '142' }],
                  },
                ],
                possibleExplanations: [
                  {
                    explanation: '비정상 C2 비커닝 가능성',
                    facts: [{ id: 'F2', name: 'beacon_interval', value: '30s' }],
                    attackIds: ['T1071.001'],
                  },
                ],
                sendRecommendation: null,
                limitations: [],
                followUp: [],
                attackCandidates: [
                  { attackId: 'T1071.001', name: 'Web Protocols', tactics: ['Command and Control'] },
                ],
              },
              sendDecision: {
                present: true,
                wouldSend: true,
                decidedBy: 'policy',
                policyId: 'pol-1',
                policyChoice: 'send',
                policyMandatory: false,
                policyReasons: ['다중 창 탐지'],
                llmChoice: 'analyst_review',
                decisionModel: 'gemini-decision-1',
                decisionModelChoice: 'send',
                decisionModelConfidence: 0.74,
                decisionModelProbabilities: { send: 0.74, hold: 0.26 },
                decisionModelError: null,
                opinionMismatch: true,
              },
              slackDeliveries: [],
              slackThreadGroups: [
                {
                  threadKey: 'cic17-wed|192.168.10.5|originator|100',
                  deliveries: [
                    {
                      jobId: 40,
                      messageKind: 'incident',
                      messageVersion: 'v1',
                      deliveryMode: 'dry_run',
                      deliveryStatus: 'recorded',
                      dryRunOrRecorded: true,
                      slackTs: '17000.1',
                      deliveredAt: '2026-11-18T01:51:00Z',
                      error: null,
                      createdAt: '2026-11-18T01:51:00Z',
                      payloadJson: '{"text":"hello"}',
                      threadParent: null,
                      threadKey: 'cic17-wed|192.168.10.5|originator|100',
                      threadRoleLabel: '첫 알림',
                      replyBroadcast: true,
                    },
                  ],
                },
              ],
              analystReview: {
                present: true,
                reviewJobId: 40,
                reviewReason: '정책·LLM 불일치로 검토 필요',
                requestedAt: '2026-11-18T01:52:00Z',
                reviewAction: null,
                analystDisplay: null,
                decidedAt: null,
                resumedAt: null,
                resumeFailed: false,
                pending: true,
                resumeStatusLabel: '판단 대기',
                canDecide: true,
              },
              currentStatus: 'investigating',
              currentResolution: null,
              statusUpdatedAt: '2026-11-18T02:00:00Z',
              statusUpdatedByDisplay: '분석가1 (analyst1)',
              statusHistory: [],
              canTransition: true,
              nextAllowedStatus: 'closed',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/incidents/42/rank/1/transition') {
        return new Response(
          JSON.stringify({ succeeded: true, code: 'OK', message: '상태 변경 완료' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/incidents/42/rank/1/review-decision') {
        return new Response(
          JSON.stringify({ succeeded: true, code: 'OK', message: '검토 결정 완료' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const user = userEvent.setup();
    const { container } = renderWithAnalyst(
      '/incidents/42/rank/1',
      fetchMock as unknown as typeof fetch,
    );

    expect(await screen.findByText('상세 근거를 불러오지 못했습니다. 기본 정보만 표시합니다.')).toBeInTheDocument();
    expect(screen.getByText('6 / 9')).toBeInTheDocument();
    expect(screen.getByText('선택 확률')).toBeInTheDocument();
    expect(screen.getByText('확정이 아닌 가설')).toBeInTheDocument();
    expect(screen.getByText('채널에도 표시')).toBeInTheDocument();
    expect(screen.getByText('시험 모드(실제 전송 안 함)')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('정확도');

    // XSS 무해화 확인: 텍스트로만 출력되고 <script>/<img> 요소가 생성되지 않아야 함
    expect(screen.getByText(`관측 요약 ${xssPayload}`)).toBeInTheDocument();
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('img')).toHaveLength(0);

    // F1 클릭 시 근거 이름/값 펼치기
    await user.click(screen.getByRole('button', { name: /F1/ }));
    expect(screen.getByText('outbound_443_count')).toBeInTheDocument();
    expect(screen.getByText('142')).toBeInTheDocument();

    // 상태 전이 제출
    await user.type(screen.getByLabelText('변경 사유 (필수)'), '실제 공격 확인');
    await user.click(screen.getByRole('button', { name: '종료 처리' }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([u]) => u === '/api/incidents/42/rank/1/transition');
      expect(call).toBeDefined();
      expect(JSON.parse(String(call![1]?.body))).toEqual({
        toStatus: 'closed',
        resolution: 'true_positive',
        reason: '실제 공격 확인',
      });
    });

    // 검토 결정 제출
    await user.type(screen.getByLabelText('판단 메모 (선택)'), '진행 승인');
    await user.click(screen.getByRole('button', { name: '조사 진행' }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        ([u]) => u === '/api/incidents/42/rank/1/review-decision',
      );
      expect(call).toBeDefined();
      expect(JSON.parse(String(call![1]?.body))).toEqual({
        action: 'confirm',
        note: '진행 승인',
      });
    });
  });

  it('전송 판단이 없을 때 sendDecision 빈 상태 카드를 표시한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return analystMeResponse();
      if (url === '/api/incidents/10/rank/1') {
        return new Response(
          JSON.stringify({
            maskedView: false,
            canDecideReview: false,
            detail: {
              incident: {
                jobId: 10,
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                queueRank: 1,
                incidentId: 'cic17-wed|192.168.10.9|originator|50',
                hostIp: '192.168.10.9',
                zeekadRole: 'originator',
                eventStart: null,
                eventEnd: null,
                zeekadPickedBy: 'ae_v2',
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
              },
              job: null,
              modelScores: [],
              assetNames: [],
              evidence: {
                available: false,
                statusMessage: '상세 근거를 불러오지 못했습니다. 기본 정보만 표시합니다.',
                connectionCount: null,
                bytesSent: null,
                bytesReceived: null,
                payloadBytesInflated: null,
                transportCounts: {},
                serviceProtocolCounts: {},
                connStateCounts: {},
                topPeers: [],
                uniquePeers: null,
                topPorts: [],
                uniquePorts: null,
                protocolLogs: [],
                representativeConnections: [],
                limits: [],
                additionalFields: {},
              },
              report: {
                present: false,
                reportKind: null,
                reportVersion: null,
                inputVersion: null,
                llmModelRequested: null,
                llmModelVersion: null,
                llmSeconds: null,
                llmInputTokens: null,
                llmOutputTokens: null,
                llmThinkingTokens: null,
                llmError: null,
                verificationPassed: null,
                verificationReason: null,
                verificationProblems: [],
                createdAt: null,
                sourceRun: null,
                pseudonyms: {},
                observationSummary: null,
                claims: [],
                possibleExplanations: [],
                sendRecommendation: null,
                limitations: [],
                followUp: [],
                attackCandidates: [],
              },
              sendDecision: {
                present: false,
                wouldSend: null,
                decidedBy: null,
                policyId: null,
                policyChoice: null,
                policyMandatory: null,
                policyReasons: [],
                llmChoice: null,
                decisionModel: null,
                decisionModelChoice: null,
                decisionModelConfidence: null,
                decisionModelProbabilities: {},
                decisionModelError: null,
                opinionMismatch: false,
              },
              slackDeliveries: [],
              slackThreadGroups: [],
              analystReview: {
                present: false,
                reviewJobId: null,
                reviewReason: null,
                requestedAt: null,
                reviewAction: null,
                analystDisplay: null,
                decidedAt: null,
                resumedAt: null,
                resumeFailed: false,
                pending: false,
                resumeStatusLabel: null,
                canDecide: false,
              },
              currentStatus: 'open',
              currentResolution: null,
              statusUpdatedAt: null,
              statusUpdatedByDisplay: null,
              statusHistory: [],
              canTransition: true,
              nextAllowedStatus: 'investigating',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    renderWithAnalyst('/incidents/10/rank/1', fetchMock as unknown as typeof fetch);

    expect(await screen.findByText('보고서 없음')).toBeInTheDocument();
    expect(screen.getByText('이 사건은 알림 전송 판단 대상이 아닙니다.')).toBeInTheDocument();
  });
});
