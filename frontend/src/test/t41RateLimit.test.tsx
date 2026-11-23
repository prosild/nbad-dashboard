import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, apiRequest, errorNotice, RATE_LIMITED_MESSAGE, registerApiCallbacks } from '../api/client';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ErrorAlert } from '../components/ErrorBanner';
import { ToastProvider } from '../components/ToastContext';

/** T41: 요청 제한(429) 안내. 판단은 apiRequest·ApiError 한 곳, 화면은 값을 옮기기만 한다. */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
/** WAF(nginx limit_req)의 429는 본문이 JSON이 아니다 */
const wafRateLimited = () =>
  new Response('<html><head><title>429 Too Many Requests</title></head><body>429</body></html>', {
    status: 429,
    headers: { 'Content-Type': 'text/html' },
  });

const analystUser = {
  username: 'analyst1',
  displayName: '분석가1',
  role: 'ANALYST',
  maskedView: false,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['cic17-*'],
};

function stubFetch(impl: (url: string) => Response | Promise<Response>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => impl(typeof input === 'string' ? input : input.toString()));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

async function caught(p: Promise<unknown>): Promise<ApiError> {
  try {
    await p;
  } catch (e) {
    return e as ApiError;
  }
  throw new Error('예외가 나야 한다');
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T41 apiRequest의 429 판단', () => {
  it('429(JSON 아님): 요청 제한 안내, code는 HTTP_429, rateLimited 참', async () => {
    stubFetch(() => wafRateLimited());
    const err = await caught(apiRequest('/api/incidents/queue'));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(429);
    expect(err.code).toBe('HTTP_429');
    expect(err.message).toBe(RATE_LIMITED_MESSAGE);
    expect(err.message).toBe('요청이 많아 잠시 제한됐습니다. 잠시 뒤 다시 시도하세요.');
    expect(err.rateLimited).toBe(true);
  });

  it('429(JSON 본문): 본문 message가 있어도 요청 제한 안내, code는 본문 값', async () => {
    stubFetch(() => json({ status: 429, code: 'TOO_MANY', message: '서버 문구' }, 429));
    const err = await caught(apiRequest('/api/incidents/queue'));
    expect(err.message).toBe(RATE_LIMITED_MESSAGE);
    expect(err.code).toBe('TOO_MANY');
    expect(err.rateLimited).toBe(true);
  });

  it('다른 상태는 지금 그대로(본문 문구, JSON 아니면 일반 문구), rateLimited 거짓', async () => {
    stubFetch(() => json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500));
    let err = await caught(apiRequest('/api/x'));
    expect([err.status, err.code, err.message, err.rateLimited]).toEqual([500, 'INTERNAL', '서버 오류 문구', false]);

    stubFetch(() => new Response('bad gateway', { status: 502 }));
    err = await caught(apiRequest('/api/x'));
    expect([err.status, err.code, err.message, err.rateLimited]).toEqual([502, 'HTTP_502', '요청을 처리하지 못했습니다.', false]);
  });

  it('401·403·TOTP 콜백은 지금 그대로이고 429에서는 부르지 않는다', async () => {
    const onUnauthorized = vi.fn();
    const onTotpRequired = vi.fn();
    const unregister = registerApiCallbacks({ onUnauthorized, onTotpRequired });
    try {
      stubFetch(() => json({ status: 401, code: 'SESSION_EXPIRED', message: '세션 만료' }, 401));
      let err = await caught(apiRequest('/api/x'));
      expect(err.message).toBe('세션 만료');
      expect(err.rateLimited).toBe(false);
      expect(onUnauthorized).toHaveBeenCalledWith('SESSION_EXPIRED');

      stubFetch(() => json({ status: 403, code: 'TOTP_VERIFICATION_REQUIRED', message: 'OTP' }, 403));
      await caught(apiRequest('/api/x'));
      expect(onTotpRequired).toHaveBeenCalledWith('verify');

      stubFetch(() => json({ status: 403, code: 'TOTP_SETUP_REQUIRED', message: 'OTP' }, 403));
      await caught(apiRequest('/api/x'));
      expect(onTotpRequired).toHaveBeenCalledWith('setup');

      stubFetch(() => json({ status: 403, code: 'FORBIDDEN', message: '권한 없음' }, 403));
      err = await caught(apiRequest('/api/x'));
      expect([err.message, err.rateLimited]).toEqual(['권한 없음', false]);

      onUnauthorized.mockClear();
      onTotpRequired.mockClear();
      stubFetch(() => wafRateLimited());
      await caught(apiRequest('/api/x'));
      expect(onUnauthorized).not.toHaveBeenCalled();
      expect(onTotpRequired).not.toHaveBeenCalled();
    } finally {
      unregister();
    }
  });

  it('errorNotice: ApiError는 문구와 요청 제한 여부를 옮기고, 그 밖의 오류는 화면 문구', () => {
    expect(errorNotice(new ApiError(429, 'HTTP_429', RATE_LIMITED_MESSAGE), '기본')).toEqual({
      message: RATE_LIMITED_MESSAGE,
      rateLimited: true,
    });
    expect(errorNotice(new ApiError(500, 'X', '서버'), '기본')).toEqual({ message: '서버', rateLimited: false });
    expect(errorNotice(new TypeError('Failed to fetch'), '기본')).toEqual({ message: '기본', rateLimited: false });
  });
});

describe('T41 오류 배너', () => {
  it('429: 제목이 요청 제한이고 "관리자에게" 줄이 없다', () => {
    render(<ErrorAlert message={RATE_LIMITED_MESSAGE} rateLimited onRetry={() => undefined} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(alert).toHaveTextContent(RATE_LIMITED_MESSAGE);
    expect(alert).not.toHaveTextContent('관리자에게');
    expect(alert).not.toHaveTextContent('요청을 처리하지 못했습니다');
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument();
  });

  it('다른 오류는 지금 그대로', () => {
    render(<ErrorAlert message="서버 오류 문구" />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('요청을 처리하지 못했습니다');
    expect(alert).toHaveTextContent('잠시 후 다시 시도하세요. 계속되면 관리자에게 알려 주세요.');
    expect(alert).not.toHaveTextContent('요청이 잠시 제한됐습니다');
  });
});

function renderAt(path: string) {
  document.cookie = 'XSRF-TOKEN=t41-token; path=/';
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

describe('T41 화면의 429 안내', () => {
  it('로그인: 429면 요청 제한 안내를 보이고 비밀번호 문구와 섞이지 않는다. 423 잠금 안내는 그대로', async () => {
    let loginResponse: () => Response = wafRateLimited;
    stubFetch((url) => {
      if (url === '/api/auth/me') return json({ authenticated: false, user: null });
      if (url === '/api/auth/csrf') return json({ headerName: 'X-XSRF-TOKEN', parameterName: '_csrf', token: 't' });
      if (url === '/api/auth/login-notice') return json({ notice: '' });
      if (url === '/api/auth/login') return loginResponse();
      return json({}, 404);
    });
    const user = userEvent.setup();
    renderAt('/login');
    await user.type(await screen.findByLabelText('아이디'), 'demo');
    await user.type(screen.getByLabelText('비밀번호'), 'whatever');
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(RATE_LIMITED_MESSAGE);
    expect(alert).not.toHaveTextContent(/비밀번호|아이디/);
    expect(screen.getByRole('heading', { name: 'zeek_AD 보안 관제' })).toBeInTheDocument();

    loginResponse = () => json({ status: 423, code: 'ACCOUNT_LOCKED', message: '계정이 잠겼습니다.' }, 423);
    await user.click(screen.getByRole('button', { name: /로그인/ }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('계정이 잠겼습니다.'));
    expect(screen.getByRole('alert')).not.toHaveTextContent(RATE_LIMITED_MESSAGE);
  });

  const signedIn = (rest: (url: string) => Response) => (url: string) => {
    if (url === '/api/auth/me') return json({ authenticated: true, user: analystUser });
    if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
    return rest(url);
  };

  it('인시던트 큐: 429 배너 제목과 안내, 로그인 화면으로 튕기지 않는다', async () => {
    stubFetch(signedIn(() => wafRateLimited()));
    renderAt('/incidents');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(alert).toHaveTextContent(RATE_LIMITED_MESSAGE);
    expect(alert).not.toHaveTextContent('관리자에게');
    expect(screen.getByRole('heading', { name: '인시던트' })).toBeInTheDocument();
  });

  it('인시던트 상세: 429 배너', async () => {
    stubFetch(signedIn(() => wafRateLimited()));
    renderAt('/incidents/101/rank/2');
    // 상세 화면에는 이웃 이동 줄의 작은 알림("이동 목록을 불러오지 못했습니다")도 있어 상세 배너를 골라 본다
    const alert = await waitFor(() => {
      const found = screen.getAllByRole('alert').find((a) => a.textContent?.includes(RATE_LIMITED_MESSAGE));
      expect(found).toBeDefined();
      return found as HTMLElement;
    });
    expect(alert).toHaveTextContent('요청이 잠시 제한됐습니다');
    expect(alert).toHaveTextContent(RATE_LIMITED_MESSAGE);
  });

  it('운영 현황·에스컬레이션: 429 배너, 다른 오류는 일반 제목', async () => {
    stubFetch(signedIn(() => wafRateLimited()));
    const ops = renderAt('/operations');
    expect(await screen.findByRole('alert')).toHaveTextContent('요청이 잠시 제한됐습니다');
    ops.unmount();

    stubFetch(signedIn(() => wafRateLimited()));
    const rv = renderAt('/reviews');
    expect(await screen.findByRole('alert')).toHaveTextContent('요청이 잠시 제한됐습니다');
    rv.unmount();

    stubFetch(signedIn(() => json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500)));
    renderAt('/reviews');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('요청을 처리하지 못했습니다');
    expect(alert).toHaveTextContent('관리자에게');
  });
});
