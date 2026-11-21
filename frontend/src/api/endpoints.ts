import { apiRequest } from './client';
import type {
  ActionResultResponse,
  AssigneeCandidate,
  IncidentAssignment,
  AdminAuditLogsResponse,
  AdminUserMutationResponse,
  AdminUsersListResponse,
  AuthCsrfResponse,
  AuthLoginResponse,
  AuthMeResponse,
  LoginNoticeResponse,
  IncidentDetailApiResponse,
  IncidentQueueResponse,
  OperationsApiResponse,
  DashboardOverviewResponse,
  QueueNeighborsResponse,
  QueueNewCountResponse,
  TimeContextResponse,
  UnifiedQueueResponse,
  ReviewsApiResponse,
  TotpSetupResponse,
  TotpVerifyResponse,
  UserRole,
} from '../types/api';

function buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      search.set(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
}

export const authApi = {
  csrf: () => apiRequest<AuthCsrfResponse>('/api/auth/csrf', { skipAuthRedirect: true }),
  me: () => apiRequest<AuthMeResponse>('/api/auth/me', { skipAuthRedirect: true }),
  /** T21: 로그인 화면 안내 문구(로그인 전 공개 GET, 일반 텍스트) */
  loginNotice: () => apiRequest<LoginNoticeResponse>('/api/auth/login-notice', { skipAuthRedirect: true }),
  login: (username: string, password: string) =>
    apiRequest<AuthLoginResponse>('/api/auth/login', {
      method: 'POST',
      body: { username, password },
      skipAuthRedirect: true,
    }),
  logout: () =>
    apiRequest<ActionResultResponse>('/api/auth/logout', {
      method: 'POST',
      skipAuthRedirect: true,
    }),
  getTotpSetup: () => apiRequest<TotpSetupResponse>('/api/auth/totp/setup'),
  completeTotpSetup: (code: string) =>
    apiRequest<TotpVerifyResponse>('/api/auth/totp/setup', {
      method: 'POST',
      body: { code },
    }),
  verifyTotp: (code: string) =>
    apiRequest<TotpVerifyResponse>('/api/auth/totp/verify', {
      method: 'POST',
      body: { code },
    }),
};

export interface IncidentQueueFilters {
  captureId?: string;
  jobId?: number | string;
  pickedBy?: string;
  role?: string;
  asset?: string;
  status?: string;
  hasReport?: string;
  wouldSend?: string;
}

export const incidentsApi = {
  list: (filters: IncidentQueueFilters = {}) =>
    apiRequest<IncidentQueueResponse>(
      `/api/incidents${buildQuery({
        captureId: filters.captureId,
        jobId: filters.jobId,
        pickedBy: filters.pickedBy,
        role: filters.role,
        asset: filters.asset,
        status: filters.status,
        hasReport: filters.hasReport,
        wouldSend: filters.wouldSend,
      })}`,
    ),
  /** T23 통합 큐. params는 utils/triage.ts queueApiParams가 만든 값(빈 값은 빠진다). */
  queue: (params: Record<string, string | undefined>) =>
    apiRequest<UnifiedQueueResponse>(`/api/incidents/queue${buildQuery(params)}`),
  newCount: (params: Record<string, string | undefined>, since: string) =>
    apiRequest<QueueNewCountResponse>(`/api/incidents/queue/new-count${buildQuery({ ...params, since })}`),
  neighbors: (jobId: number | string, queueRank: number | string, params: Record<string, string | undefined>) =>
    apiRequest<QueueNeighborsResponse>(
      `/api/incidents/queue/neighbors${buildQuery({ jobId: String(jobId), queueRank: String(queueRank), ...params })}`,
    ),
  detail: (jobId: number | string, queueRank: number | string) =>
    apiRequest<IncidentDetailApiResponse>(`/api/incidents/${jobId}/rank/${queueRank}`),
  transition: (
    jobId: number | string,
    queueRank: number | string,
    body: { toStatus: string; resolution?: string | null; reason: string },
  ) =>
    apiRequest<ActionResultResponse>(`/api/incidents/${jobId}/rank/${queueRank}/transition`, {
      method: 'POST',
      body,
    }),
  reviewDecision: (
    jobId: number | string,
    queueRank: number | string,
    body: { action: 'confirm' | 'dismiss'; note?: string },
  ) =>
    apiRequest<ActionResultResponse>(`/api/incidents/${jobId}/rank/${queueRank}/review-decision`, {
      method: 'POST',
      body,
    }),
  /** T25 담당 지정·변경·해제. assignee null = 해제, expected = 화면이 본 담당자 */
  assign: (jobId: number | string, queueRank: number | string, body: { assignee: string | null; expected: string | null }) =>
    apiRequest<{ assignment: IncidentAssignment }>(`/api/incidents/${jobId}/rank/${queueRank}/assignment`, {
      method: 'POST',
      body,
    }),
  /** T25 담당자가 될 수 있는 사용자(분석가·관리자만 부른다) */
  assignees: (jobId: number | string, queueRank: number | string) =>
    apiRequest<{ assignees: AssigneeCandidate[] }>(`/api/incidents/${jobId}/rank/${queueRank}/assignees`),
};

export const timeApi = {
  /** T23: 기준 시각(그 사용자 허용 캡처 기준)과 고정 스냅샷 여부 */
  // 실패해도 로그인·TOTP 화면으로 보내지 않는다(띠만 보이지 않는다).
  context: () => apiRequest<TimeContextResponse>('/api/time-context', { skipAuthRedirect: true }),
};

export const reviewsApi = {
  list: (captureId?: string, pendingOnly = false) =>
    apiRequest<ReviewsApiResponse>(
      `/api/reviews${buildQuery({
        captureId,
        pendingOnly: pendingOnly ? 'true' : undefined,
      })}`,
    ),
  decide: (body: { jobId: number; incidentId: string; action: 'confirm' | 'dismiss'; note?: string }) =>
    apiRequest<ActionResultResponse>('/api/reviews/decide', {
      method: 'POST',
      body,
    }),
};

/** T24: 기간·수집원·캡처 조건. 빈 값은 빠진다 */
export interface ConditionParams {
  period?: string;
  source?: string;
  captureId?: string;
}

export const operationsApi = {
  get: (params: ConditionParams = {}) =>
    apiRequest<OperationsApiResponse>(
      `/api/operations${buildQuery({ period: params.period, source: params.source, captureId: params.captureId })}`,
    ),
};

export const dashboardApi = {
  /** T24 현황판: 탐지 추이·센서·캡처 상태·경보 발송 상태(수는 같은 조건 큐 API summary를 쓴다) */
  overview: (params: ConditionParams = {}) =>
    apiRequest<DashboardOverviewResponse>(
      `/api/dashboard/overview${buildQuery({ period: params.period, source: params.source, captureId: params.captureId })}`,
    ),
};

export const adminApi = {
  listUsers: () => apiRequest<AdminUsersListResponse>('/api/admin/users'),
  createUser: (body: {
    username: string;
    displayName: string;
    password: string;
    role: UserRole;
    capturePatterns: string[];
  }) =>
    apiRequest<AdminUserMutationResponse>('/api/admin/users', {
      method: 'POST',
      body,
    }),
  updateUser: (
    id: number,
    body: { displayName: string; role: UserRole; capturePatterns: string[] },
  ) =>
    apiRequest<AdminUserMutationResponse>(`/api/admin/users/${id}`, {
      method: 'PUT',
      body,
    }),
  toggleEnabled: (id: number) =>
    apiRequest<AdminUserMutationResponse>(`/api/admin/users/${id}/toggle-enabled`, {
      method: 'POST',
    }),
  unlockUser: (id: number) =>
    apiRequest<AdminUserMutationResponse>(`/api/admin/users/${id}/unlock`, {
      method: 'POST',
    }),
  resetTotp: (id: number) =>
    apiRequest<AdminUserMutationResponse>(`/api/admin/users/${id}/reset-totp`, {
      method: 'POST',
    }),
  listAuditLogs: (params: { actionType?: string; actorUsername?: string; limit?: number } = {}) =>
    apiRequest<AdminAuditLogsResponse>(
      `/api/admin/audit-logs${buildQuery({
        actionType: params.actionType,
        actorUsername: params.actorUsername,
        limit: params.limit,
      })}`,
    ),
};
