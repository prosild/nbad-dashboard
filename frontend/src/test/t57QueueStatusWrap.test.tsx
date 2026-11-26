import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import type { IncidentQueueItem, UnifiedQueueItem } from '../types/api';
import { fakeQueue, unified } from './fakeQueueServer';

/**
 * T57: 데스크톱 인시던트 목록 표의 "상태 · 판정" 칸. 종결 행은 상태 배지와 판정 배지 둘을 나란히 두어 칸이 86px → 142px가 되고
 * 1280·1536·1920px에서 표 상자가 넘쳤다(T62 측정). 두 배지를 칸 안에서 줄 바꿈(flex-wrap)할 수 있게 해 열이 넓은 배지 하나의 폭까지
 * 줄어들게 한다. 두 글은 그대로 보인다. 실제 폭은 jsdom이 재지 못해 브라우저 확인(handoff/T57/evidence/browser/)이 본다.
 */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => {
  vi.unstubAllGlobals();
});

function item(i: number, status: string, resolution: string | null): UnifiedQueueItem {
  const base: IncidentQueueItem = {
    jobId: 57,
    captureId: 'lab-20261122',
    bundleId: 'zeekad-fusion/3',
    queueRank: i,
    incidentId: `lab-20261122|10.57.0.${i}|originator|${i}`,
    hostIp: `10.57.0.${i}`,
    zeekadRole: 'originator',
    eventStart: '2026-11-20T00:00:00Z',
    eventEnd: '2026-11-20T00:30:00Z',
    zeekadPickedBy: 'ae_v2',
    zeekadAlsoFlaggedBy: [],
    connectionCount: 10 * i,
    hostName: [],
    zeekadStatus: status,
    zeekadResolution: resolution,
    statusUpdatedAt: null,
    zeekadReportJobId: null,
    hasReport: false,
    zeekadReportKind: null,
    zeekadVerificationPassed: null,
    zeekadWouldSend: false,
    zeekadReviewAction: null,
    zeekadReviewPending: false,
    alerted: false,
  };
  return unified(base, { priority: status === 'closed' ? null : 'medium', detectedAt: `2026-11-20T00:0${i}:00Z` });
}

function renderQueue(items: UnifiedQueueItem[]) {
  document.cookie = 'XSRF-TOKEN=t57-token; path=/';
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/auth/me') {
        return json({
          authenticated: true,
          user: {
            username: 'analyst',
            displayName: 'ANALYST',
            role: 'ANALYST',
            maskedView: false,
            totpEnabled: false,
            totpVerified: true,
            totpRequired: false,
            allowedCapturePatterns: ['*'],
          },
        });
      }
      if (url === '/api/time-context') return json({ anchor: '2026-11-21T00:00:00Z', anchorMode: 'now', snapshot: false });
      if (url.startsWith('/api/incidents/queue/new-count')) return json({ count: 0, latestDetectedAt: null, since: null });
      if (url.startsWith('/api/incidents/queue')) return json(fakeQueue(url, { items, anchor: '2026-11-21T00:00:00Z', maskedView: false }));
      return json({ status: 404, code: 'NOT_FOUND', message: '없음' }, 404);
    }),
  );
  render(
    <MemoryRouter initialEntries={['/incidents']}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('T57 큐 표의 상태 · 판정 칸', () => {
  it('종결 행의 상태·판정 배지 둘은 칸 안에서 줄을 바꿀 수 있고(flex-wrap) 두 글이 모두 보인다', async () => {
    renderQueue([item(1, 'open', null), item(2, 'closed', 'true_positive'), item(3, 'closed', 'false_positive')]);
    const table = await screen.findByRole('table');
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(3));
    const cells = Array.from(table.querySelectorAll<HTMLElement>('[data-col-content="status-verdict"]'));
    expect(cells).toHaveLength(3);
    for (const cell of cells) {
      expect(cell.className.split(/\s+/)).toEqual(expect.arrayContaining(['flex', 'flex-wrap', 'items-center', 'gap-1']));
      // 배지가 줄 바꿈되지 않게 막는 클래스는 없다
      expect(cell.className).not.toMatch(/flex-nowrap|whitespace-nowrap/);
    }
    const rowOf = (rank: number) =>
      within(table).getAllByRole('row').find((r) => r.querySelector(`a[href^="/incidents/57/rank/${rank}?"]`)) as HTMLElement;
    const closedCell = rowOf(2).querySelector<HTMLElement>('[data-col-content="status-verdict"]');
    expect(closedCell?.textContent).toContain('종결');
    expect(closedCell?.textContent).toContain('정탐');
    expect(rowOf(3).querySelector('[data-col-content="status-verdict"]')?.textContent).toContain('오탐');
    expect(rowOf(1).querySelector('[data-col-content="status-verdict"]')?.children).toHaveLength(1);
  });
});
