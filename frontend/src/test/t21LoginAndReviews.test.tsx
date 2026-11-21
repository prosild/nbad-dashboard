import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

/** T21: 로그인 안내 문구(설정값), 에스컬레이션 화면의 반영 상태(서버 라벨)·반영 지연·관계 안내 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function renderAt(path: string, fetchImpl: (url: string) => Response) {
  document.cookie = 'XSRF-TOKEN=t21-token; path=/';
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => fetchImpl(typeof input === 'string' ? input : input.toString()));
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

const anonymous = (notice: string | null, noticeStatus = 200) => (url: string) => {
  if (url === '/api/auth/me') return json({ authenticated: false, user: null });
  if (url === '/api/auth/csrf') return json({ headerName: 'X-XSRF-TOKEN', parameterName: '_csrf', token: 't' });
  if (url === '/api/auth/login-notice') return noticeStatus === 200 ? json({ notice }) : json({}, noticeStatus);
  return json({}, 404);
};

describe('T21 로그인 안내 문구', () => {
  it('값이 있으면 로그인 폼 위에 일반 텍스트로 보인다(HTML은 해석하지 않고, 줄바꿈은 CSS로)', async () => {
    const notice = '포트폴리오 공개 데모입니다.\n읽기 전용 계정 demo로 둘러볼 수 있습니다. <b>굵게</b><img src=x onerror=alert(1)>';
    const { container, fetchMock } = renderAt('/login', anonymous(notice));
    const note = await screen.findByRole('note', { name: '안내' });
    expect(note.textContent).toBe(notice);
    expect(note.querySelector('b, img')).toBeNull();
    expect(within(note).getByText(notice, { normalizer: (s) => s }).className).toContain('whitespace-pre-line');
    // 폼보다 위
    const form = container.querySelector('form') as HTMLFormElement;
    expect(note.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(fetchMock.mock.calls.some(([u]) => u === '/api/auth/login-notice')).toBe(true);
    // 잠금 정책 숫자·예시 아이디가 없다
    expect(container.textContent).not.toMatch(/\d+\s*회|\d+\s*분 동안|예:\s*\w+/);
  });

  it('값이 비었거나 불러오지 못하면 아무것도 보이지 않는다', async () => {
    const empty = renderAt('/login', anonymous(''));
    expect(await screen.findByRole('button', { name: '로그인' })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole('note', { name: '안내' })).toBeNull();
    empty.unmount();

    renderAt('/login', anonymous(null, 500));
    expect(await screen.findByRole('button', { name: '로그인' })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole('note', { name: '안내' })).toBeNull();
  });
});

describe('T21 에스컬레이션 화면 반영 상태', () => {
  const analyst = {
    username: 'analyst1',
    displayName: '분석가1',
    role: 'ANALYST',
    maskedView: false,
    totpEnabled: false,
    totpVerified: true,
    totpRequired: false,
    allowedCapturePatterns: ['*'],
  };
  const row = (n: number, extra: Record<string, unknown>) => ({
    jobId: 9,
    reviewJobId: 9,
    captureId: 'cic17-wed',
    incidentId: `cic17-wed|10.0.0.${n}|originator|${n}`,
    queueRank: n,
    hostIp: `10.0.0.${n}`,
    zeekadRole: 'originator',
    zeekadReviewReason: 'decision_model=analyst_review',
    requestedAt: '2026-11-12T02:00:00Z',
    analyst: 'analyst1',
    analystDisplay: '분석가1 (analyst1)',
    zeekadReviewResumedAt: null,
    zeekadReviewResumeFailed: false,
    ...extra,
  });

  it('반영 상태는 서버 라벨 그대로 쓰고, 결정 뒤 10분 넘게 반영 중이면 반영 지연을 덧붙인다', async () => {
    const recent = new Date(Date.now() - 2 * 60_000).toISOString();
    const old = new Date(Date.now() - 40 * 60_000).toISOString();
    renderAt('/reviews', (url) => {
      if (url === '/api/auth/me') return json({ authenticated: true, user: analyst });
      if (url.startsWith('/api/reviews')) {
        return json({
          maskedView: false,
          canDecideReview: true,
          allowedCaptures: ['cic17-wed'],
          selectedCaptureId: null,
          pendingOnly: false,
          reviews: [
            row(1, { zeekadReviewAction: 'confirm', decidedAt: recent, resumeStatusLabel: '반영 중' }),
            row(2, { zeekadReviewAction: 'confirm', decidedAt: old, resumeStatusLabel: '반영 중' }),
            row(3, { zeekadReviewAction: 'dismiss', decidedAt: old, zeekadReviewResumeFailed: true, resumeStatusLabel: '반영 실패(관리자 확인 필요)' }),
            row(4, { zeekadReviewAction: 'dismiss', decidedAt: old, zeekadReviewResumedAt: old, resumeStatusLabel: '반영됨' }),
            // 서버 라벨이 화면 규칙과 달라도 서버 라벨을 그대로 보인다(프론트엔드가 따로 끌어내지 않는다)
            row(5, { zeekadReviewAction: 'confirm', decidedAt: recent, resumeStatusLabel: '서버 라벨 그대로' }),
          ],
        });
      }
      return json({}, 404);
    });
    const table = await screen.findByRole('table');
    const r = (n: number) => within(table).getByText(`10.0.0.${n}`).closest('tr') as HTMLElement;
    expect(within(r(1)).getByText('반영 중')).toBeInTheDocument();
    expect(within(r(1)).queryByText('반영 지연')).toBeNull();
    expect(within(r(2)).getByText('반영 중')).toBeInTheDocument();
    expect(within(r(2)).getByText('반영 지연')).toBeInTheDocument();
    expect(within(r(3)).getByText('반영 실패(관리자 확인 필요)')).toBeInTheDocument();
    expect(within(r(3)).queryByText('반영 지연')).toBeNull();
    expect(within(r(4)).getByText('반영됨')).toBeInTheDocument();
    expect(within(r(5)).getByText('서버 라벨 그대로')).toBeInTheDocument();
    expect(
      screen.getByRole('note', { name: '에스컬레이션 결정과 상태' }),
    ).toHaveTextContent('에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).');
    expect(document.body.textContent).not.toContain('인시던트 상태를 바꾸지 않습니다');
  });
});
