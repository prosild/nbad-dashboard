import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components/ToastContext';
import { labelText, lookupLabel } from '../utils/labels';

/** 서버 AuditActionType의 값 전부(T58 기준). 감사 로그 화면의 유형 필터는 이 목록으로 만든다 */
const ALL_ACTION_TYPES = [
  'LOGIN_SUCCESS',
  'LOGIN_FAILURE',
  'ACCOUNT_LOCKED',
  'TOTP_VERIFIED',
  'ACCESS_DENIED_IDOR',
  'INCIDENT_VIEW_UNMASKED',
  'INCIDENT_STATUS_TRANSITION',
  'ANALYST_REVIEW_DECISION',
  'INCIDENT_ASSIGNMENT',
  'USER_ADMIN_CHANGE',
  'AUDIT_RETENTION_PURGE',
];

const json = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

function renderAuditLogs() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/api/auth/me') {
      return json({
        authenticated: true,
        user: {
          username: 'admin',
          displayName: '최고관리자',
          role: 'ADMIN',
          maskedView: false,
          totpEnabled: true,
          totpVerified: true,
          totpRequired: true,
          allowedCapturePatterns: ['*'],
        },
      });
    }
    if (url.startsWith('/api/admin/audit-logs')) {
      return json({
        logs: [
          {
            // DB 함수 purge_expired_audit_logs가 남기는 행: 행위자 audit-retention, 역할 SYSTEM, 접속 IP 없음
            id: 31,
            occurredAt: '2026-11-26T00:00:03Z',
            actorUsername: 'audit-retention',
            actorRole: 'SYSTEM',
            actionType: 'AUDIT_RETENTION_PURGE',
            targetCaptureId: null,
            targetJobId: null,
            targetIncidentId: null,
            detailJson: '{"deleted" : 12, "cutoff" : "2026-08-28T00:00:03Z", "retentionDays" : 90}',
            clientIp: null,
          },
          {
            id: 30,
            occurredAt: '2026-11-25T03:00:00Z',
            actorUsername: 'analyst1',
            actorRole: 'ANALYST',
            actionType: 'INCIDENT_ASSIGNMENT',
            targetCaptureId: 'lab-20261122',
            targetJobId: 7,
            targetIncidentId: null,
            detailJson: null,
            clientIp: '203.0.113.9',
          },
        ],
        actionTypes: ALL_ACTION_TYPES,
        selectedActionType: '',
        selectedActorUsername: '',
        selectedLimit: 100,
      });
    }
    return new Response('{}', { status: 404 });
  });
  document.cookie = 'XSRF-TOKEN=admin-xsrf-token; path=/';
  vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
  render(
    <MemoryRouter initialEntries={['/admin/audit-logs']}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('T58 감사 로그 보관 기한: 새 동작 유형과 시스템 행위자', () => {
  it('사전에 새 유형·담당 지정·시스템 역할이 있고 서버 유형 가운데 미등록이 없다', () => {
    expect(labelText('auditAction', 'AUDIT_RETENTION_PURGE')).toBe('보관 기한 지난 기록 삭제');
    expect(labelText('auditAction', 'INCIDENT_ASSIGNMENT')).toBe('담당 지정');
    expect(labelText('userRole', 'SYSTEM')).toBe('시스템');
    for (const type of ALL_ACTION_TYPES) {
      expect(lookupLabel('auditAction', type).known, type).toBe(true);
    }
  });

  it('감사 로그 화면: 삭제 기록 행이 한국어 라벨·시스템 역할로 보이고 상세에서 지운 수와 기준 시각을 읽는다', async () => {
    renderAuditLogs();
    const user = userEvent.setup();

    const actor = await screen.findByText('audit-retention');
    const row = actor.closest('tr')!;
    expect(within(row).getByText('보관 기한 지난 기록 삭제')).toBeInTheDocument();
    expect(within(row).getByText('시스템')).toBeInTheDocument();
    // 코드 값이 그대로 보이거나 "미등록 값"으로 표시되지 않는다
    expect(within(row).queryByText('AUDIT_RETENTION_PURGE')).not.toBeInTheDocument();
    expect(within(row).queryByText('SYSTEM')).not.toBeInTheDocument();
    expect(row.querySelector('[title*="미등록 값"]')).toBeNull();

    await user.click(within(row).getByRole('button', { name: '상세 보기' }));
    const detail = document.querySelector('pre[data-raw]')!;
    expect(detail.textContent).toContain('"deleted" : 12');
    expect(detail.textContent).toContain('"cutoff" : "2026-08-28T00:00:03Z"');
    expect(detail.textContent).toContain('"retentionDays" : 90');

    // 담당 지정(T25) 행도 라벨로 보인다(이전에는 사전에 없어 "미등록 값"이었다)
    const assignRow = screen.getByText('analyst1').closest('tr')!;
    expect(within(assignRow).getByText('담당 지정')).toBeInTheDocument();
    expect(assignRow.querySelector('[title*="미등록 값"]')).toBeNull();
  });

  it('감사 로그 화면: 유형 필터에 새 유형이 한국어로 있고 골라서 조회하면 그 값으로 요청한다', async () => {
    const fetchMock = renderAuditLogs();
    const user = userEvent.setup();
    await screen.findByText('audit-retention');

    const select = screen.getByLabelText('동작 유형') as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => [o.value, o.textContent]);
    expect(options).toContainEqual(['AUDIT_RETENTION_PURGE', '보관 기한 지난 기록 삭제']);
    expect(options).toContainEqual(['INCIDENT_ASSIGNMENT', '담당 지정']);
    // 선택지에 코드 값이 그대로 보이는 유형이 없다
    for (const [value, text] of options) {
      if (value) expect(text, String(value)).not.toBe(value);
    }

    await user.selectOptions(select, 'AUDIT_RETENTION_PURGE');
    await user.click(screen.getByRole('button', { name: '조회' }));
    const calls = fetchMock.mock.calls.map(([u]) => String(u));
    expect(calls.some((u) => u.startsWith('/api/admin/audit-logs') && u.includes('actionType=AUDIT_RETENTION_PURGE'))).toBe(true);
  });
});
