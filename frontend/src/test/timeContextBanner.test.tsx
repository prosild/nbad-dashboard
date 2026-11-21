import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

/** T23 화면 맨 위 띠: 고정 스냅샷이면 모든 화면 맨 위에 "고정 스냅샷 · 기준 시각 <KST>"를 늘 보이고, now 모드면 보이지 않는다. */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const viewer = {
  username: 'demo',
  displayName: '공개 데모',
  role: 'VIEWER',
  maskedView: true,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['cic17-*'],
};

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

function renderAt(path: string, timeContext: () => Response) {
  document.cookie = 'XSRF-TOKEN=banner-test-token; path=/';
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      calls.push(url);
      if (url === '/api/auth/me') return json({ authenticated: true, user: viewer });
      if (url === '/api/time-context') return timeContext();
      return json({}, 404);
    }),
  );
  const utils = render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
          <LocationProbe />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { ...utils, calls };
}

describe('고정 스냅샷 띠(T23)', () => {
  it.each(['/', '/incidents', '/reviews', '/operations'])('latest-data 모드면 %s 맨 위에 기준 시각(KST)과 함께 보인다', async (path) => {
    const { container } = renderAt(path, () =>
      json({ anchor: '2026-11-19T02:05:00Z', anchorMode: 'latest-data', snapshot: true }),
    );
    const banner = await screen.findByText(/고정 스냅샷 · 기준 시각/);
    expect(banner.closest('[data-snapshot-banner]')).toHaveTextContent('고정 스냅샷 · 기준 시각 2026-11-19 11:05:00 KST');
    // 상단 바보다 앞(맨 위)에 있다
    const bannerEl = container.querySelector('[data-snapshot-banner]') as HTMLElement;
    const headerEl = container.querySelector('header') as HTMLElement;
    expect(bannerEl.compareDocumentPosition(headerEl) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('now 모드면 보이지 않는다', async () => {
    const { calls } = renderAt('/incidents', () => json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false }));
    await waitFor(() => expect(calls).toContain('/api/time-context'));
    await screen.findByRole('heading', { name: '인시던트' });
    expect(screen.queryByText(/고정 스냅샷 · 기준 시각/)).toBeNull();
  });

  it('기준 시각을 불러오지 못하면 띠를 보이지 않고 로그인 화면으로 보내지 않는다. 화면을 옮겨도 다시 부르지 않는다', async () => {
    const { calls } = renderAt('/', () => json({ code: 'UNAUTHORIZED', message: 'x' }, 401));
    await waitFor(() => expect(calls).toContain('/api/time-context'));
    await screen.findByRole('heading', { name: '현황판' });
    expect(screen.queryByText(/고정 스냅샷/)).toBeNull();
    expect(screen.getByTestId('loc')).toHaveTextContent('/');
    expect(calls.filter((u) => u === '/api/time-context')).toHaveLength(1);
  });
});
