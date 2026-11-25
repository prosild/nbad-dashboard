import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

/**
 * T48: 화면 제목 아래 설명 문장(페이지 부제)을 일곱 화면 모두에서 없앴다.
 * 머리말의 제목 묶음(h1의 부모)에는 h1 하나만 있고 h1 밖의 글이 없다.
 * 머리말은 화면 자료와 무관하게 그려지므로 화면 API는 모두 실패로 답한다(자료 모양에 기대지 않는다).
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const ADMIN = {
  username: 'admin',
  displayName: 'ADMIN',
  role: 'ADMIN',
  maskedView: false,
  totpEnabled: true,
  totpVerified: true,
  totpRequired: true,
  allowedCapturePatterns: ['*'],
};

function renderApp(path: string) {
  document.cookie = 'XSRF-TOKEN=t48-token; path=/';
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return json({ authenticated: true, user: ADMIN });
      if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
      calls.push(url);
      return json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500);
    }),
  );
  render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const SCREENS: Array<{ path: string; title: string }> = [
  { path: '/', title: '현황판' },
  { path: '/incidents', title: '인시던트' },
  { path: '/hosts', title: '호스트 위험도' },
  { path: '/reviews', title: '에스컬레이션' },
  { path: '/operations', title: '운영 현황' },
  { path: '/admin/users', title: '사용자 관리' },
  { path: '/admin/audit-logs', title: '감사 로그' },
];

describe('T48 화면 제목 아래 설명 문장이 없다', () => {
  it.each(SCREENS)('$title($path): 제목 묶음에 h1 밖의 글이 없다', async ({ path, title }) => {
    const { calls } = renderApp(path);
    const h1 = await screen.findByRole('heading', { level: 1, name: title });
    // 화면이 제 API를 부른 뒤(그 화면이 실제로 그려진 뒤)의 머리말을 본다
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);

    const group = h1.parentElement as HTMLElement;
    expect(group.closest('header')).not.toBeNull();
    expect(Array.from(group.children)).toEqual([h1]);
    expect(group.textContent).toBe(title);
    expect(h1.textContent).toBe(title);
  });
});
