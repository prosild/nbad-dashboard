import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { AppShell } from '../components/AppShell';
import { ToastProvider } from '../components/ToastContext';
import { baseDetail, DEFAULT_META } from './detailFixture';
import { fakeNeighbors } from './fakeQueueServer';

/**
 * T49: 상세의 조치 패널은 머리말과 한 상자 안에 놓인다(넓은 화면에서 그 상자가 화면 위에 붙고
 * 패널은 상자의 아래쪽 끝에 매달린다. 머리말 높이에 맞춘 고정 값이 없다).
 * jsdom은 배치를 재지 못하므로 여기서는 구조만 본다(위치는 브라우저 측정으로 본다).
 */

const PANEL = 'aside[aria-label="조치 패널"]';
/** 넓은 화면에서 머리말의 sticky를 푸는 클래스(패널이 있을 때만 붙는다) */
const HEADER_UNSTICK = 'xl:static';
/** 넓은 화면에서 본문 오른쪽(패널 22rem + 간격 1rem)을 비우는 클래스(패널이 있을 때만 붙는다) */
const BODY_RESERVE = 'xl:pr-[23rem]';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const ANALYST = {
  username: 'analyst1',
  displayName: '분석가1',
  role: 'ANALYST',
  maskedView: false,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
};

interface Gate {
  /** 상세 응답을 붙잡아 둔다(불러오는 중 상태를 만든다) */
  hold?: Promise<void>;
}

function stubApi(gate: Gate = {}) {
  document.cookie = 'XSRF-TOKEN=t49-token; path=/';
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') return json({ authenticated: true, user: ANALYST });
      if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
      const m = url.match(/^\/api\/incidents\/(\d+)\/rank\/(\d+)$/);
      if (m) {
        if (gate.hold) await gate.hold;
        const d = baseDetail();
        return json({
          maskedView: false,
          canDecideReview: true,
          detail: { ...d, incident: { ...d.incident, jobId: Number(m[1]), queueRank: Number(m[2]) } },
          queueMeta: DEFAULT_META,
          assignment: { assignee: null, assignedAt: null, assignedByDisplay: null },
          assignmentHistory: [],
          canAssign: true,
        });
      }
      if (url.startsWith('/api/incidents/queue/neighbors')) return json(fakeNeighbors(url, { items: [] }));
      if (/\/assignees$/.test(url)) return json({ assignees: [] });
      return json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500);
    }),
  );
}

function renderApp(path: string) {
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

const pageHeader = () => screen.getByRole('heading', { level: 1 }).closest('header') as HTMLElement;
const pageMain = () => document.querySelector('main') as HTMLElement;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T49 상세 조치 패널은 머리말과 한 상자 안에 있다', () => {
  it('상세: 조치 패널이 하나이고 머리말과 같은 부모 아래에 있으며 main 안에 없다', async () => {
    stubApi();
    renderApp('/incidents/42/rank/1');
    await screen.findByRole('region', { name: '조치' });

    const panels = document.querySelectorAll(PANEL);
    expect(panels).toHaveLength(1);
    const panel = panels[0] as HTMLElement;
    const header = pageHeader();
    expect(panel.parentElement).toBe(header.parentElement);
    // 머리말 다음에 온다(좁은 화면에서 머리말 → 패널 → 본문 순서로 흐른다)
    expect(header.nextElementSibling).toBe(panel);
    expect(pageMain().contains(panel)).toBe(false);
    expect(pageMain().querySelector(PANEL)).toBeNull();
    // 패널 내용(조치 칸)은 그 aside 바로 안에 있다
    expect(panel.contains(screen.getByRole('region', { name: '조치' }))).toBe(true);

    // 패널이 있을 때: 머리말은 넓은 화면에서 sticky를 풀고(감싼 상자가 붙는다) 본문은 오른쪽을 비운다
    expect(header.classList.contains(HEADER_UNSTICK)).toBe(true);
    expect((pageMain().firstElementChild as HTMLElement).classList.contains(BODY_RESERVE)).toBe(true);

    expect(document.body.querySelector('[style]')).toBeNull();
  });

  it('상세: 불러오는 중에는 패널과 본문 오른쪽 여백이 없고, 패널이 생기면 붙는다(머리말은 같은 노드)', async () => {
    let release: () => void = () => undefined;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    stubApi({ hold });
    renderApp('/incidents/42/rank/1');
    await screen.findByText('인시던트 정보를 불러오는 중...');

    const headerBefore = pageHeader();
    const body = pageMain().firstElementChild as HTMLElement;
    expect(document.querySelector(PANEL)).toBeNull();
    expect(body.classList.contains(BODY_RESERVE)).toBe(false);
    expect(headerBefore.classList.contains(HEADER_UNSTICK)).toBe(false);
    expect(headerBefore.classList.contains('sticky')).toBe(true);
    expect(document.body.querySelector('[style]')).toBeNull();

    await act(async () => {
      release();
      await hold;
    });
    await screen.findByRole('region', { name: '조치' });

    expect(document.querySelectorAll(PANEL)).toHaveLength(1);
    expect(pageHeader()).toBe(headerBefore);
    expect(pageMain().firstElementChild).toBe(body);
    expect(body.classList.contains(BODY_RESERVE)).toBe(true);
    expect(headerBefore.classList.contains(HEADER_UNSTICK)).toBe(true);
    expect(document.body.querySelector('[style]')).toBeNull();
  });

  it('AppShell: 패널을 넘기지 않았다가 넘겨도 header 요소가 다시 만들어지지 않는다', async () => {
    stubApi();
    const shell = (withPanel: boolean) => (
      <MemoryRouter initialEntries={['/incidents']}>
        <ToastProvider>
          <AuthProvider>
            <AppShell
              title="시험 화면"
              sidePanel={withPanel ? <div data-testid="t49-panel-body">패널 내용</div> : undefined}
              sidePanelLabel="조치 패널"
            >
              <p>본문</p>
            </AppShell>
          </AuthProvider>
        </ToastProvider>
      </MemoryRouter>
    );
    const view = render(shell(false));
    const headerBefore = pageHeader();
    const mainBefore = pageMain();
    const mainClassBefore = mainBefore.className;
    expect(document.querySelector(PANEL)).toBeNull();
    expect(headerBefore.classList.contains(HEADER_UNSTICK)).toBe(false);

    view.rerender(shell(true));
    const panel = document.querySelector(PANEL) as HTMLElement;
    expect(panel).not.toBeNull();
    expect(panel.contains(screen.getByTestId('t49-panel-body'))).toBe(true);
    expect(pageHeader()).toBe(headerBefore);
    expect(pageMain()).toBe(mainBefore);
    expect(panel.parentElement).toBe(headerBefore.parentElement);
    expect(headerBefore.classList.contains(HEADER_UNSTICK)).toBe(true);

    // 다시 빼면 머리말·본문의 클래스가 처음과 같다
    view.rerender(shell(false));
    expect(document.querySelector(PANEL)).toBeNull();
    expect(pageHeader()).toBe(headerBefore);
    expect(headerBefore.classList.contains(HEADER_UNSTICK)).toBe(false);
    expect(pageMain().className).toBe(mainClassBefore);
    expect(document.body.querySelector('[style]')).toBeNull();
  });

  it('패널이 없는 화면(인시던트 목록): 머리말에 sticky를 푸는 클래스가 없고 조치 패널이 없다', async () => {
    stubApi();
    renderApp('/incidents');
    await screen.findByRole('heading', { level: 1, name: '인시던트' });
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(2));

    const header = pageHeader();
    expect(header.classList.contains('sticky')).toBe(true);
    expect(header.classList.contains(HEADER_UNSTICK)).toBe(false);
    expect(document.querySelector(PANEL)).toBeNull();
    // 패널이 없는 화면의 main은 지금까지의 클래스 그대로다
    expect(pageMain().className).toBe('mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6');
    expect(document.body.querySelector('[style]')).toBeNull();
  });
});
