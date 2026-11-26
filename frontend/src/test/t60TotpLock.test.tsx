import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { labelText, lookupLabel } from '../utils/labels';

const LOCKED_MESSAGE = '2단계 인증 연속 실패 횟수 초과로 계정이 잠겼습니다.';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const adminUser = (totpVerified: boolean) => ({
  username: 'admin',
  displayName: '최고관리자',
  role: 'ADMIN',
  maskedView: false,
  totpEnabled: true,
  totpVerified,
  totpRequired: true,
  allowedCapturePatterns: ['*'],
});

function renderAt(path: string, fetchMock: ReturnType<typeof vi.fn>) {
  document.cookie = 'XSRF-TOKEN=admin-xsrf-token; path=/';
  vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
  render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T60 관리자 TOTP 실패 제한: 화면', () => {
  it('TOTP 화면에서 423을 받으면 로그인 화면으로 옮겨 서버 메시지를 보이고 TOTP 화면으로 되돌아가지 않는다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/auth/me') {
        return json({ authenticated: true, user: adminUser(false) });
      }
      if (url === '/api/auth/login-notice') {
        return json({ notice: '' });
      }
      if (url === '/api/auth/totp/verify' && init?.method === 'POST') {
        return json({ status: 423, code: 'ACCOUNT_LOCKED', message: LOCKED_MESSAGE }, 423);
      }
      if (url === '/api/auth/login' && init?.method === 'POST') {
        return json(
          { status: 401, code: 'INVALID_CREDENTIALS', message: '아이디 또는 비밀번호가 올바르지 않습니다.' },
          401,
        );
      }
      return new Response('{}', { status: 404 });
    });
    renderAt('/login/totp', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByText('관리자 TOTP 2단계 인증')).toBeInTheDocument();
    await user.type(screen.getByLabelText('6자리 TOTP 인증 코드'), '000000');
    await user.click(screen.getByRole('button', { name: '인증 확인' }));

    // 로그인 화면: 아이디 입력 칸이 있고 서버의 423 메시지가 오류 자리에 보인다
    expect(await screen.findByLabelText('아이디')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(LOCKED_MESSAGE);
    // 남은 횟수는 보이지 않는다
    expect(screen.getByRole('alert').textContent).not.toMatch(/남은|\d+\s*회/);

    // 인증 상태가 비워졌으므로 로그인 화면이 TOTP 화면으로 다시 보내지 않는다
    await waitFor(() => {
      expect(screen.queryByText('관리자 TOTP 2단계 인증')).not.toBeInTheDocument();
    });
    expect(screen.queryByLabelText('6자리 TOTP 인증 코드')).not.toBeInTheDocument();
    expect(screen.getByLabelText('비밀번호')).toBeInTheDocument();

    // 다시 로그인을 시도하면 그 응답의 메시지로 바뀐다(잠금 안내가 남아 겹치지 않는다)
    await user.type(screen.getByLabelText('아이디'), 'admin');
    await user.type(screen.getByLabelText('비밀번호'), 'wrong-password');
    await user.click(screen.getByRole('button', { name: '로그인' }));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('아이디 또는 비밀번호가 올바르지 않습니다.');
    });
    expect(screen.queryByText(LOCKED_MESSAGE)).not.toBeInTheDocument();
  });

  it('TOTP 화면에서 400을 받으면 그 화면에 남아 다시 입력하게 한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/auth/me') {
        return json({ authenticated: true, user: adminUser(false) });
      }
      if (url === '/api/auth/totp/verify' && init?.method === 'POST') {
        return json({ status: 400, code: 'INVALID_TOTP_CODE', message: '인증 코드가 올바르지 않습니다.' }, 400);
      }
      return new Response('{}', { status: 404 });
    });
    renderAt('/login/totp', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByText('관리자 TOTP 2단계 인증')).toBeInTheDocument();
    await user.type(screen.getByLabelText('6자리 TOTP 인증 코드'), '000000');
    await user.click(screen.getByRole('button', { name: '인증 확인' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('인증 코드가 올바르지 않습니다.');
    expect(screen.getByText('관리자 TOTP 2단계 인증')).toBeInTheDocument();
    expect(screen.getByLabelText('6자리 TOTP 인증 코드')).toBeInTheDocument();
    expect(screen.queryByLabelText('아이디')).not.toBeInTheDocument();
  });

  it('감사 로그 화면: 새 유형 TOTP_FAILURE가 한국어 라벨로 보이고 유형 필터에 있다', async () => {
    expect(labelText('auditAction', 'TOTP_FAILURE')).toBe('2단계 인증 실패');
    expect(lookupLabel('auditAction', 'TOTP_FAILURE').known).toBe(true);

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/auth/me') {
        return json({ authenticated: true, user: adminUser(true) });
      }
      if (url.startsWith('/api/admin/audit-logs')) {
        return json({
          logs: [
            {
              id: 41,
              occurredAt: '2026-11-26T05:00:00Z',
              actorUsername: 'admin2',
              actorRole: 'ADMIN',
              actionType: 'TOTP_FAILURE',
              targetCaptureId: null,
              targetJobId: null,
              targetIncidentId: null,
              detailJson: '{"reason":"invalid_code","failedAttempts":3}',
              clientIp: '203.0.113.9',
            },
          ],
          actionTypes: ['LOGIN_FAILURE', 'ACCOUNT_LOCKED', 'TOTP_VERIFIED', 'TOTP_FAILURE'],
          selectedActionType: '',
          selectedActorUsername: '',
          selectedLimit: 100,
        });
      }
      return new Response('{}', { status: 404 });
    });
    renderAt('/admin/audit-logs', fetchMock);
    const user = userEvent.setup();

    const row = (await screen.findByText('admin2')).closest('tr')!;
    expect(within(row).getByText('2단계 인증 실패')).toBeInTheDocument();
    expect(within(row).queryByText('TOTP_FAILURE')).not.toBeInTheDocument();
    expect(row.querySelector('[title*="미등록 값"]')).toBeNull();

    const select = screen.getByLabelText('동작 유형') as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => [o.value, o.textContent]);
    expect(options).toContainEqual(['TOTP_FAILURE', '2단계 인증 실패']);

    await user.selectOptions(select, 'TOTP_FAILURE');
    await user.click(screen.getByRole('button', { name: '조회' }));
    const calls = fetchMock.mock.calls.map(([u]) => String(u));
    expect(calls.some((u) => u.startsWith('/api/admin/audit-logs') && u.includes('actionType=TOTP_FAILURE'))).toBe(true);
  });
});
