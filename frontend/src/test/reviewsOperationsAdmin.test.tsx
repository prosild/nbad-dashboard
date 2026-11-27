import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { expectAllTablesInScrollBox } from './tableScrollBox';

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
    // T26: 휴대폰 폭에서 표가 페이지를 넓히지 않게 모든 표는 가로 스크롤 상자 안에 있다
    expectAllTablesInScrollBox();

    // T68(A13, 설계자 답 L2): 번호가 없는 행은 접근성 이름이 "인시던트 검토 메모"이고 "상세 보기" 링크가 있다. 원문 ID는 글로 보이지 않는다
    expect(screen.queryByText('cic17-wed|192.168.10.5|originator|100')).toBeNull();
    expect(screen.getByRole('link', { name: '상세 보기' })).toHaveAttribute('href', '/incidents/99/rank/1');
    expect(screen.getByRole('button', { name: '인시던트 ID 복사' })).toBeInTheDocument();
    await user.type(screen.getByLabelText('인시던트 검토 메모'), '조사 진행');
    await user.click(screen.getByRole('button', { name: '승인' }));

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

  it('/reviews의 오탐 종결도 상세와 같이 메모 필수와 확인 단계를 거친다(T19)', async () => {
    const incidentId = 'cic17-wed|192.168.10.5|originator|100';
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return adminMeResponse();
      if (url.startsWith('/api/reviews?') || url === '/api/reviews') {
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
                incidentId,
                incidentNo: 2188,
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
        return new Response(JSON.stringify({ succeeded: true, code: 'OK', message: '검토 결정 반영됨' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('{}', { status: 404 });
    });
    const decideCalls = () => fetchMock.mock.calls.filter(([u]) => u === '/api/reviews/decide');

    const user = userEvent.setup();
    renderWithAdmin('/reviews', fetchMock as unknown as typeof fetch);
    expect(await screen.findByText('경계선 점수 검토')).toBeInTheDocument();
    // T68(A13): 번호가 있으면 "#번호" 링크(번호 주소)와 "인시던트 #번호 검토 메모". 원문 ID는 복사로만 준다
    expect(screen.getByRole('link', { name: '#2188' })).toHaveAttribute('href', '/incidents/2188');
    expect(screen.queryByText(incidentId)).toBeNull();
    const note = screen.getByLabelText('인시던트 #2188 검토 메모');

    // 메모 없이 누르면 막고 메모 칸으로 포커스
    await user.click(screen.getByRole('button', { name: '오탐 종결' }));
    expect(screen.getByRole('alert')).toHaveTextContent('오탐 종결에는 검토 메모가 필요합니다.');
    expect(note).toHaveFocus();
    expect(decideCalls()).toHaveLength(0);

    // 메모 → 확인 단계 → 확정
    await user.type(note, '정상 업무');
    await user.click(screen.getByRole('button', { name: '오탐 종결' }));
    const confirm = screen.getByRole('group', { name: '인시던트 #2188 오탐 종결 확인' });
    expect(decideCalls()).toHaveLength(0);
    await user.click(within(confirm).getByRole('button', { name: '오탐 종결 확정' }));
    await waitFor(() => expect(decideCalls()).toHaveLength(1));
    expect(JSON.parse(String(decideCalls()[0][1]?.body))).toEqual({
      jobId: 88,
      incidentId,
      action: 'dismiss',
      note: '정상 업무',
    });
  });

  it('/operations에서 feedback_summary all 행 강조, null 안전 정탐률·표본 부족 및 미탐 한계 안내를 표시한다', async () => {
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
                precisionSummaryText: '표본 부족 · 분석가 판정 5건 / 모델이 올린 인시던트 18건',
                alertPrecisionSummaryText: '표본 부족 · 분석가 판정 4건 / 경보 6건',
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
                precisionSummaryText: '분석가 판정 없음',
                alertPrecisionSummaryText: '경보 없음',
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

    expect(await screen.findByText('모든 모델 합계')).toBeInTheDocument();
    // T20: 판정 5건(10건 미만)이라 정탐률 대신 표본 부족, 실제 값(60.0%)은 툴팁. 경보도 같은 규칙.
    const table = screen.getByText('모든 모델 합계').closest('table') as HTMLElement;
    const precision = within(table).getByText('표본 부족 · 분석가 판정 5건 / 모델이 올린 인시던트 18건');
    expect(precision).toHaveAttribute('title', expect.stringContaining('정탐률 60.0%(판정 5건)'));
    const alertPrecision = within(table).getByText('표본 부족 · 분석가 판정 4건 / 경보 6건');
    expect(alertPrecision).toHaveAttribute('title', expect.stringContaining('경보 정탐률 75.0%(판정 4건)'));
    // 판정 없는 탐지 모델 행은 기본으로 접혀 있고, 펼치면 "분석가 판정 없음" 한 줄로 보인다(T67).
    expect(within(table).queryByText('분석가 판정 없음')).not.toBeInTheDocument();
    await userEvent.setup().click(within(table).getByRole('button', { name: /탐지 모델별 1개 펼치기/ }));
    expect(within(table).getByText('분석가 판정 없음')).toBeInTheDocument();
    expect(screen.getByText(/미탐\(재현율\)은 이 집계로 알 수 없음 — 이 표는 탐지된 인시던트만 셉니다/)).toBeInTheDocument();
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
    expectAllTablesInScrollBox();

    await user.click(screen.getByRole('button', { name: /신규 사용자 생성/ }));
    await user.type(screen.getByLabelText('아이디'), 'analyst3');
    await user.type(screen.getByLabelText('표시 이름'), '분석가3');
    await user.type(screen.getByLabelText('초기 비밀번호'), 'StrongPass!1');
    await user.selectOptions(screen.getByLabelText('역할'), 'ANALYST');
    const patternsInput = screen.getByLabelText(/열람 허용 캡처/);
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
    const badges = await screen.findAllByText('사용자 계정 변경');
    expect(badges.length).toBeGreaterThanOrEqual(2);
    await user.click(screen.getByRole('button', { name: /상세 보기/ }));
    expect(screen.getByText('{"created":"analyst3"}')).toBeInTheDocument();
    expectAllTablesInScrollBox();
  });
});
