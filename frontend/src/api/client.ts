import type { ApiErrorResponse, AuthCsrfResponse } from '../types/api';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
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
    const message = payload?.message ?? '요청을 처리하지 못했습니다.';

    if (!options.skipAuthRedirect) {
      if (status === 401) {
        callbacks.onUnauthorized?.(code);
      } else if (status === 403 && code === 'TOTP_SETUP_REQUIRED') {
        callbacks.onTotpRequired?.('setup');
      } else if (status === 403 && code === 'TOTP_VERIFICATION_REQUIRED') {
        callbacks.onTotpRequired?.('verify');
      }
    }

    throw new ApiError(status, code, message);
  }

  return payload as T;
}
