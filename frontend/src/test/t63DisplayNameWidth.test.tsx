import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { AssignmentSection } from '../components/incident/AssignmentSection';
import { ResponseActionSection } from '../components/incident/ResponseActionSection';
import { ToastProvider } from '../components/ToastContext';

/**
 * T63(T64 최종 검토 L1에서 넘어온 일): 표시 이름이 나오는 세 곳도 다른 이름 칸처럼 폭 규칙([overflow-wrap:anywhere])을 둔다.
 * 서버는 이름을 256 코드 포인트까지 보내므로(T63 글자 정책) 띄어쓰기 없는 256자 이름이 칸을 넘지 않아야 한다.
 */
const LONG_NAME = 'L'.repeat(256);

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T63 표시 이름 칸의 폭', () => {
  it('담당 지정자(assignedByDisplay)', () => {
    render(
      <ToastProvider>
        <AssignmentSection
          jobId={42}
          queueRank={1}
          assignment={{
            assignee: { username: 'kim', displayName: '김분석', enabled: true },
            assignedAt: '2026-11-26T00:00:00Z',
            assignedByDisplay: LONG_NAME,
          }}
          canAssign={false}
          closed={false}
          currentUsername="kim"
          onRefresh={async () => {}}
        />
      </ToastProvider>,
    );
    expect(screen.getByText(LONG_NAME)).toHaveClass('[overflow-wrap:anywhere]');
  });

  it('대응 조치 기록자(latest.actorDisplay)', () => {
    render(
      <ToastProvider>
        <ResponseActionSection
          jobId={42}
          queueRank={1}
          actions={[{ action: 'monitor', note: null, actorDisplay: LONG_NAME, recordedAt: '2026-11-26T00:00:00Z' }]}
          canRecord={false}
          notStarted={false}
          onRefresh={async () => {}}
        />
      </ToastProvider>,
    );
    expect(screen.getByText(LONG_NAME)).toHaveClass('[overflow-wrap:anywhere]');
  });

  it('사용자 관리 수정 폼 머리의 아이디(editingUser.username)', async () => {
    const user = userEvent.setup();
    document.cookie = 'XSRF-TOKEN=t63-token; path=/';
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url === '/api/auth/me') {
          return json({
            authenticated: true,
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
          });
        }
        if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
        if (url === '/api/admin/users') {
          return json({
            users: [
              {
                id: 7,
                username: LONG_NAME,
                displayName: '긴 아이디',
                role: 'ANALYST',
                totpEnabled: false,
                failedAttempts: 0,
                lockedUntil: null,
                enabled: true,
                createdAt: '2026-11-18T00:00:00Z',
                updatedAt: '2026-11-18T00:00:00Z',
                capturePatterns: ['cic17-*'],
              },
            ],
            roles: ['VIEWER', 'ANALYST', 'ADMIN'],
          });
        }
        return json({}, 404);
      }),
    );
    render(
      <MemoryRouter initialEntries={['/admin/users']}>
        <ToastProvider>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </ToastProvider>
      </MemoryRouter>,
    );
    await user.click(await screen.findByRole('button', { name: '수정' }));
    const header = await screen.findByText(/사용자 정보·권한 수정:/);
    const name = Array.from(header.querySelectorAll('span')).find((el) => el.textContent === LONG_NAME);
    expect(name, '수정 폼 머리의 아이디').toBeDefined();
    expect(name).toHaveClass('[overflow-wrap:anywhere]');
  });
});
