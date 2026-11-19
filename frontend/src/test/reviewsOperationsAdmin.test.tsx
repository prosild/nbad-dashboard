import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

function renderWithAdmin(initialEntry: string, fetchImpl: typeof fetch) {
  document.cookie = 'XSRF-TOKEN=admin-xsrf-token; path=/';
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

const adminMeResponse = () =>
  new Response(
    JSON.stringify({
      authenticated: true,
      user: {
        username: 'admin',
        displayName: '최고관리자',
        role: 'ADMIN',
        maskedView: false,
        totpEnabled: true,
        totpVerified: true,
        totpRequired: true,
        allowedCapturePatterns: ['*'],
      },
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );

describe('승인 대기, 운영 상태(feedback_summary), 관리자 화면', () => {
  it('/reviews에서 reviewJobId를 jobId로 전달해 confirm 결정을 제출한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return adminMeResponse();
      if (url.startsWith('/api/reviews?pendingOnly=true') || url === '/api/reviews') {
        return new Response(
          JSON.stringify({
            maskedView: false,
            canDecideReview: true,
            allowedCaptures: ['cic17-wed'],
            selectedCaptureId: null,
            pendingOnly: false,
            reviews: [
              {
                jobId: 99,
                reviewJobId: 88,
                captureId: 'cic17-wed',
                incidentId: 'cic17-wed|192.168.10.5|originator|100',
                queueRank: 1,
                hostIp: '192.168.10.5',
                zeekadRole: 'originator',
                zeekadReviewReason: '경계선 점수 검토',
                requestedAt: '2026-11-18T01:00:00Z',
                zeekadReviewAction: null,
                analyst: null,
                analystDisplay: null,
                decidedAt: null,
                zeekadReviewResumedAt: null,
                zeekadReviewResumeFailed: false,
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/reviews/decide') {
        return new Response(
          JSON.stringify({ succeeded: true, code: 'OK', message: '검토 결정 반영됨' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const user = userEvent.setup();
    renderWithAdmin('/reviews', fetchMock as unknown as typeof fetch);

    expect(await screen.findByText('경계선 점수 검토')).toBeInTheDocument();

    await user.type(
      screen.getByLabelText('cic17-wed|192.168.10.5|originator|100 검토 메모'),
      '조사 진행',
    );
    await user.click(screen.getByRole('button', { name: /confirm/ }));

    await waitFor(() => {
      const decideCall = fetchMock.mock.calls.find(([u]) => u === '/api/reviews/decide');
      expect(decideCall).toBeDefined();
      expect(JSON.parse(String(decideCall![1]?.body))).toEqual({
        jobId: 88,
        incidentId: 'cic17-wed|192.168.10.5|originator|100',
        action: 'confirm',
        note: '조사 진행',
      });
    });
  });

  it('/operations에서 feedback_summary all 행 강조, null 안전 정밀도 및 재현율 한계 안내를 표시한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return adminMeResponse();
      if (url.startsWith('/api/operations')) {
        return new Response(
          JSON.stringify({
            maskedView: false,
            allowedCaptures: ['cic17-wed'],
            selectedCaptureId: null,
            jobs: [],
            bundles: [],
            feedbackSummaries: [
              {
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                zeekadPickedBy: 'all',
                incidents: 18,
                alerted: 6,
                resolved: 5,
                truePositive: 3,
                falsePositive: 1,
                benign: 1,
                zeekadPrecision: 0.6,
                zeekadAlertPrecision: 0.75,
                zeekadAlertResolvedRate: 0.667,
                alertedResolved: 4,
                extraAttributes: {},
                allModel: true,
                effectiveAlertedResolved: 4,
                precisionSummaryText: '정밀도 0.60, 결론 5/18 (27.8%)',
                alertPrecisionSummaryText: '정밀도 0.75, 결론 4/6 (66.7%)',
              },
              {
                captureId: 'cic17-wed',
                bundleId: 'zeekad-fusion/3',
                zeekadPickedBy: 'ae_v2',
                incidents: 0,
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
                precisionSummaryText: '- (결론 없음)',
                alertPrecisionSummaryText: '- (알림 없음)',
              },
            ],
            slackSummaries: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    renderWithAdmin('/operations', fetchMock as unknown as typeof fetch);

    expect(await screen.findByText('전체 (all)')).toBeInTheDocument();
    expect(screen.getByText('정밀도 0.60, 결론 5/18 (27.8%)')).toBeInTheDocument();
    expect(screen.getByText('- (결론 없음)')).toBeInTheDocument();
    expect(screen.getByText('놓친 공격(재현율)은 이 집계로 알 수 없습니다.')).toBeInTheDocument();
  });

  it('/admin/users에서 신규 사용자를 생성하고 /admin/audit-logs에서 상세 JSON을 펼친다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return adminMeResponse();
      if (url === '/api/admin/users' && (!init?.method || init.method === 'GET')) {
        return new Response(
          JSON.stringify({
            users: [
              {
                id: 1,
                username: 'analyst1',
                displayName: '분석가1',
                role: 'ANALYST',
                totpEnabled: false,
                failedAttempts: 0,
                lockedUntil: null,
                enabled: true,
                createdAt: '2026-11-18T00:00:00Z',
                updatedAt: '2026-11-18T00:00:00Z',
                capturePatterns: ['cic17-*'],
              },
            ],
            roles: ['VIEWER', 'ANALYST', 'ADMIN'],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/admin/users' && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            message: '사용자가 생성되었습니다.',
            user: {
              id: 2,
              username: 'analyst3',
              displayName: '분석가3',
              role: 'ANALYST',
              totpEnabled: false,
              failedAttempts: 0,
              lockedUntil: null,
              enabled: true,
              createdAt: '2026-11-19T00:00:00Z',
              updatedAt: '2026-11-19T00:00:00Z',
              capturePatterns: ['cic17-*', 'syn1-*'],
            },
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.startsWith('/api/admin/audit-logs')) {
        return new Response(
          JSON.stringify({
            logs: [
              {
                id: 10,
                occurredAt: '2026-11-19T01:00:00Z',
                actorUsername: 'admin',
                actorRole: 'ADMIN',
                actionType: 'USER_ADMIN_CHANGE',
                targetCaptureId: null,
                targetJobId: null,
                targetIncidentId: null,
                detailJson: '{"created":"analyst3"}',
                clientIp: '127.0.0.1',
              },
            ],
            actionTypes: ['LOGIN_SUCCESS', 'USER_ADMIN_CHANGE'],
            selectedActionType: '',
            selectedActorUsername: '',
            selectedLimit: 100,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    const user = userEvent.setup();
    renderWithAdmin('/admin/users', fetchMock as unknown as typeof fetch);

    expect(await screen.findByText('analyst1')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /신규 사용자 생성/ }));
    await user.type(screen.getByLabelText('아이디 (username)'), 'analyst3');
    await user.type(screen.getByLabelText('표시 이름 (displayName)'), '분석가3');
    await user.type(screen.getByLabelText('초기 비밀번호'), 'StrongPass!1');
    await user.selectOptions(screen.getByLabelText('역할 (Role)'), 'ANALYST');
    const patternsInput = screen.getByLabelText(/허용 캡처 패턴/);
    await user.clear(patternsInput);
    await user.type(patternsInput, 'cic17-*, syn1-*');
    await user.click(screen.getByRole('button', { name: '사용자 생성' }));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([u, i]) => u === '/api/admin/users' && i?.method === 'POST',
      );
      expect(postCall).toBeDefined();
      expect(JSON.parse(String(postCall![1]?.body))).toEqual({
        username: 'analyst3',
        displayName: '분석가3',
        password: 'StrongPass!1',
        role: 'ANALYST',
        capturePatterns: ['cic17-*', 'syn1-*'],
      });
    });

    await user.click(screen.getByRole('link', { name: '감사 로그' }));
    const badges = await screen.findAllByText('USER_ADMIN_CHANGE');
    expect(badges.length).toBeGreaterThanOrEqual(2);
    await user.click(screen.getByRole('button', { name: /JSON 보기/ }));
    expect(screen.getByText('{"created":"analyst3"}')).toBeInTheDocument();
  });
});
