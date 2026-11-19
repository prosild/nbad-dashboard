import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

function renderAt(initialEntry: string) {
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

describe('인증, CSRF, 세션 만료 및 TOTP QR 등록', () => {
  it('비인증 상태에서 보호 경로 접근 시 /login으로 이동하고 CSRF 헤더와 함께 로그인한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') {
        return new Response(JSON.stringify({ authenticated: false, user: null }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === '/api/auth/csrf') {
        return new Response(
          JSON.stringify({
            headerName: 'X-XSRF-TOKEN',
            parameterName: '_csrf',
            token: 'csrf-token-123',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/auth/login') {
        return new Response(
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
            nextRoute: '/',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.startsWith('/api/incidents')) {
        return new Response(
          JSON.stringify({
            maskedView: false,
            allowedCaptures: ['cic17-wed'],
            selectedCaptureId: 'cic17-wed',
            selectedJob: null,
            captureJobs: [],
            incidents: [],
            availableModels: [],
            availableRoles: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    renderAt('/incidents');

    expect(await screen.findByRole('heading', { name: 'zeek_AD SOC Console' })).toBeInTheDocument();

    await user.type(screen.getByLabelText('아이디'), 'analyst1');
    await user.type(screen.getByLabelText('비밀번호'), 'Pass!1234');
    await user.click(screen.getByRole('button', { name: /로그인/ }));

    expect(await screen.findByRole('heading', { name: '이상탐지 조사 큐' })).toBeInTheDocument();

    const loginCall = fetchMock.mock.calls.find(([url]) => url === '/api/auth/login');
    expect(loginCall).toBeDefined();
    const init = loginCall![1] as RequestInit;
    expect(init.credentials).toBe('same-origin');
    const headers = init.headers as Headers;
    expect(headers.get('X-XSRF-TOKEN')).toBe('csrf-token-123');
  });

  it('API 401 SESSION_EXPIRED 응답 시 /login?expired 배너로 이동한다', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') {
        return new Response(
          JSON.stringify({
            authenticated: true,
            user: {
              username: 'viewer1',
              displayName: '조회자1',
              role: 'VIEWER',
              maskedView: true,
              totpEnabled: false,
              totpVerified: true,
              totpRequired: false,
              allowedCapturePatterns: ['cic17-*'],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.startsWith('/api/incidents')) {
        return new Response(
          JSON.stringify({
            status: 401,
            code: 'SESSION_EXPIRED',
            message: '세션이 만료되었습니다.',
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    vi.stubGlobal('fetch', fetchMock);
    renderAt('/incidents');

    expect(
      await screen.findByText('세션이 만료되었습니다. 다시 로그인해 주세요.'),
    ).toBeInTheDocument();
  });

  it('관리자 TOTP 미등록 상태에서 /login/totp/setup QR SVG와 시크릿을 렌더링하고 등록을 완료한다', async () => {
    document.cookie = 'XSRF-TOKEN=cookie-xsrf-xyz; path=/';

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') {
        return new Response(
          JSON.stringify({
            authenticated: true,
            user: {
              username: 'admin',
              displayName: '관리자',
              role: 'ADMIN',
              maskedView: false,
              totpEnabled: false,
              totpVerified: false,
              totpRequired: true,
              allowedCapturePatterns: ['*'],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/auth/totp/setup' && (!init?.method || init.method === 'GET')) {
        return new Response(
          JSON.stringify({
            secret: 'JBSWY3DPEHPK3PXP',
            otpauthUri: 'otpauth://totp/zeek_AD:admin?secret=JBSWY3DPEHPK3PXP&issuer=zeek_AD',
            issuer: 'zeek_AD',
            accountName: 'admin',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === '/api/auth/totp/setup' && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            succeeded: true,
            code: 'OK',
            message: 'TOTP 등록 완료',
            user: {
              username: 'admin',
              displayName: '관리자',
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
      }
      if (url.startsWith('/api/incidents')) {
        return new Response(
          JSON.stringify({
            maskedView: false,
            allowedCaptures: ['cic17-wed'],
            selectedCaptureId: 'cic17-wed',
            selectedJob: null,
            captureJobs: [],
            incidents: [],
            availableModels: [],
            availableRoles: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    renderAt('/incidents');

    expect(await screen.findByText('관리자 TOTP 최초 등록')).toBeInTheDocument();
    expect(await screen.findByRole('img', { name: '관리자 TOTP QR 코드' })).toBeInTheDocument();
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    await user.type(screen.getByLabelText('6자리 TOTP 인증 코드'), '123456');
    await user.click(screen.getByRole('button', { name: /TOTP 등록 완료/ }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: '이상탐지 조사 큐' })).toBeInTheDocument();
    });
  });
});
