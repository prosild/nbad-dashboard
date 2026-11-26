import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';

/**
 * T50: 없는 주소의 NotFound 화면(현황판으로 돌려보내지 않는다)과 로그인 안내문의 줄바꿈·링크.
 * 화면 API는 이 시험에 필요 없어 모두 실패로 답한다(자료 모양에 기대지 않는다).
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const VIEWER = {
  username: 'viewer1',
  displayName: '조회자1',
  role: 'VIEWER',
  maskedView: true,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
};

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderApp(path: string, opts: { user?: typeof VIEWER | null; notice?: unknown } = {}) {
  document.cookie = 'XSRF-TOKEN=t50-token; path=/';
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return opts.user ? json({ authenticated: true, user: opts.user }) : json({ authenticated: false, user: null });
      if (url === '/api/auth/csrf') return json({ headerName: 'X-XSRF-TOKEN', parameterName: '_csrf', token: 't' });
      if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
      if (url === '/api/auth/login-notice') return json(opts.notice ?? { notice: '' });
      calls.push(url);
      return json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500);
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

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T50 없는 주소의 NotFound 화면', () => {
  it.each(['/t50marker-nowhere', '/t50marker/deep/path?x=1', '/hosts/t50marker', '/admin/t50marker'])(
    '%s: 제목과 링크 둘을 보이고 현황판으로 옮겨 가지 않는다',
    async (path) => {
      const { calls } = renderApp(path, { user: VIEWER });
      const h1 = await screen.findByRole('heading', { level: 1, name: '페이지를 찾을 수 없습니다' });
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
      // T48: 제목 묶음에 h1 밖의 글이 없다
      expect((h1.parentElement as HTMLElement).textContent).toBe('페이지를 찾을 수 없습니다');

      const main = screen.getByRole('main');
      expect(within(main).getByText('주소가 바뀌었거나 없는 화면입니다.')).toBeInTheDocument();
      const links = within(main).getAllByRole('link');
      expect(links.map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
        ['현황판', '/'],
        ['인시던트 목록', '/incidents'],
      ]);

      // 주소는 그대로이고(현황판으로 돌려보내지 않는다) 현황판 화면이 그려지지 않는다
      expect(screen.getByTestId('location')).toHaveTextContent(path);
      expect(screen.queryByRole('heading', { name: '현황판' })).toBeNull();
      // 요청 주소를 화면에 옮겨 적지 않는다
      expect(main.textContent).not.toContain('t50marker');
      expect(document.body.querySelector('header')?.textContent ?? '').not.toContain('t50marker');
      // 화면 자료 API를 부르지 않는다
      await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(path));
      expect(calls).toEqual([]);
    },
  );

  it('로그인하지 않은 상태로 없는 경로에 닿으면 보호 경로와 같게 로그인으로 보낸다', async () => {
    renderApp('/t50marker-nowhere');
    expect(await screen.findByRole('button', { name: '로그인' })).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/login$/);
    expect(screen.queryByRole('heading', { name: '페이지를 찾을 수 없습니다' })).toBeNull();
  });

  it('목록 꼴에 맞지 않는 인시던트 주소는 지금처럼 상세 화면의 안내를 보인다(NotFound 화면이 아니다)', async () => {
    renderApp('/incidents/abc', { user: VIEWER });
    expect(await screen.findByText('잘못된 인시던트 경로입니다.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '페이지를 찾을 수 없습니다' })).toBeNull();
  });
});

describe('T50 로그인 안내문의 줄바꿈과 링크', () => {
  const NOTICE = '첫 줄입니다.\n둘째 줄입니다.\n셋째 줄입니다.';
  const LINK = { url: 'https://example.org/zeekad#readme', label: '소개와 구조 보기(README)' };

  it('링크가 있으면 안내문 아래에 새 창으로 여는 <a> 하나를 보이고 안내문의 줄바꿈을 유지한다', async () => {
    const { container } = renderApp('/login', { notice: { notice: NOTICE, link: LINK } });
    const note = await screen.findByRole('note', { name: '안내' });
    const text = within(note).getByText(NOTICE, { normalizer: (s) => s });
    expect(text.textContent).toBe(NOTICE);
    expect(text.className).toContain('whitespace-pre-line');

    const anchors = Array.from(container.querySelectorAll('a'));
    expect(anchors).toHaveLength(1);
    const a = anchors[0];
    expect(note.contains(a)).toBe(true);
    expect(a.getAttribute('href')).toBe(LINK.url);
    expect(a.getAttribute('target')).toBe('_blank');
    expect(a.getAttribute('rel')).toBe('noopener noreferrer');
    expect(a.textContent).toBe(LINK.label);
    // 새 창으로 열린다는 것을 화면 낭독기가 안다
    expect(screen.getByRole('link', { name: `${LINK.label} (새 창)` })).toBe(a);
    // 안내문 글 다음에 온다
    expect(text.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // 폼보다 위
    const form = container.querySelector('form') as HTMLFormElement;
    expect(a.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('링크 라벨은 일반 텍스트로만 그린다(HTML을 해석하지 않는다)', async () => {
    const label = '<b>굵게</b><img src=x onerror=alert(1)>';
    const { container } = renderApp('/login', { notice: { notice: NOTICE, link: { url: LINK.url, label } } });
    const note = await screen.findByRole('note', { name: '안내' });
    const a = await within(note).findByRole('link');
    expect(a.textContent).toBe(label);
    expect(container.querySelector('a b, a img, p img')).toBeNull();
  });

  it('링크가 없으면 <a>가 없고 안내문만 보인다', async () => {
    const { container } = renderApp('/login', { notice: { notice: NOTICE } });
    const note = await screen.findByRole('note', { name: '안내' });
    expect(note.textContent).toBe(NOTICE);
    expect(container.querySelectorAll('a')).toHaveLength(0);
  });

  it.each([
    ['https가 아닌 주소', { url: 'http://example.org/', label: '소개' }],
    ['javascript 주소', { url: 'javascript:alert(1)', label: '소개' }],
    ['상대 주소', { url: '/incidents', label: '소개' }],
    ['빈 라벨', { url: 'https://example.org/', label: '  ' }],
    ['문자열이 아닌 값', { url: 42, label: null }],
    ['객체가 아닌 값', 'https://example.org/'],
  ])('서버 검사를 지난 값만 그린다: %s이면 <a>가 없다', async (_name, link) => {
    const { container } = renderApp('/login', { notice: { notice: NOTICE, link } });
    const note = await screen.findByRole('note', { name: '안내' });
    expect(note.textContent).toBe(NOTICE);
    expect(container.querySelectorAll('a')).toHaveLength(0);
  });

  it('안내문이 비었으면 링크도 보이지 않는다', async () => {
    const { container } = renderApp('/login', { notice: { notice: '', link: LINK } });
    expect(await screen.findByRole('button', { name: '로그인' })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole('note', { name: '안내' })).toBeNull();
    expect(container.querySelectorAll('a')).toHaveLength(0);
  });
});
