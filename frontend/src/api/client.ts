import type { ApiErrorResponse, AuthCsrfResponse } from '../types/api';

/** T41: 요청 제한(HTTP 429) 안내. 조회·쓰기·로그인 공통. WAF(`limit_req`)는 `Retry-After`를 주지 않아 기다릴 시간은 적지 않는다. */
export const RATE_LIMITED_MESSAGE = '요청이 많아 잠시 제한됐습니다. 잠시 뒤 다시 시도하세요.';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** T41: HTTP 상태가 429(요청 제한)였는지. 화면은 문구가 아니라 이 값으로 가른다. */
  readonly rateLimited: boolean;

  constructor(status: number, code: string, message: string, rateLimited = status === 429) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.rateLimited = rateLimited;
  }
}

/** 화면 오류 배너에 넘기는 값: 문구와 요청 제한 여부 */
export interface ErrorNotice {
  message: string;
  rateLimited: boolean;
}

/** 오류 → 안내 값. 429 판단은 ApiError가 이미 했고 여기서는 옮기기만 한다. */
export function errorNotice(err: unknown, fallback: string): ErrorNotice {
  if (err instanceof ApiError) {
    return { message: err.message, rateLimited: err.rateLimited };
  }
  return { message: fallback, rateLimited: false };
}

interface ApiCallbacks {
  onUnauthorized?: (code: string) => void;
  onTotpRequired?: (mode: 'setup' | 'verify') => void;
}

let callbacks: ApiCallbacks = {};

export function registerApiCallbacks(next: ApiCallbacks): () => void {
  callbacks = next;
  return () => {
    callbacks = {};
  };
}

export function readCookie(name: string): string | null {
  if (typeof document === 'undefined' || !document.cookie) {
    return null;
  }
  const prefix = `${name}=`;
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      const raw = trimmed.slice(prefix.length);
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return null;
}

async function ensureCsrfToken(): Promise<{ headerName: string; token: string }> {
  const existingCookieToken = readCookie('XSRF-TOKEN');
  if (existingCookieToken && existingCookieToken.trim().length > 0) {
    return { headerName: 'X-XSRF-TOKEN', token: existingCookieToken };
  }

  const res = await fetch('/api/auth/csrf', {
    method: 'GET',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  const data = (await res.json().catch(() => null)) as AuthCsrfResponse | null;
  const cookieAfter = readCookie('XSRF-TOKEN');
  const headerName = data?.headerName || 'X-XSRF-TOKEN';
  const token = (cookieAfter && cookieAfter.trim().length > 0 ? cookieAfter : data?.token) || '';
  return { headerName, token };
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  skipAuthRedirect?: boolean;
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers = new Headers();
  headers.set('Accept', 'application/json');

  if (method !== 'GET') {
    const csrf = await ensureCsrfToken();
    if (csrf.token) {
      headers.set(csrf.headerName, csrf.token);
    }
  }

  let bodyString: string | undefined;
  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json');
    bodyString = JSON.stringify(options.body);
  }

  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    body: bodyString,
  });

  const payload = (await response.json().catch(() => null)) as (T & Partial<ApiErrorResponse>) | null;

  if (!response.ok) {
    const status = payload?.status ?? response.status;
    const code = payload?.code ?? `HTTP_${response.status}`;
    // T41: 429는 본문(WAF는 JSON이 아니다)과 상관없이 요청 제한 안내를 쓴다
    const rateLimited = response.status === 429;
    const message = rateLimited ? RATE_LIMITED_MESSAGE : (payload?.message ?? '요청을 처리하지 못했습니다.');

    if (!options.skipAuthRedirect) {
      if (status === 401) {
        callbacks.onUnauthorized?.(code);
      } else if (status === 403 && code === 'TOTP_SETUP_REQUIRED') {
        callbacks.onTotpRequired?.('setup');
      } else if (status === 403 && code === 'TOTP_VERIFICATION_REQUIRED') {
        callbacks.onTotpRequired?.('verify');
      }
    }

    throw new ApiError(status, code, message, rateLimited);
  }

  return payload as T;
}
