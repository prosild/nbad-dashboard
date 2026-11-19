import { apiRequest } from './client';
import type {
  ActionResultResponse,
  AdminAuditLogsResponse,
  AdminUserMutationResponse,
  AdminUsersListResponse,
  AuthCsrfResponse,
  AuthLoginResponse,
  AuthMeResponse,
  IncidentDetailApiResponse,
  IncidentQueueResponse,
  OperationsApiResponse,
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

export const operationsApi = {
  get: (captureId?: string) =>
    apiRequest<OperationsApiResponse>(`/api/operations${buildQuery({ captureId })}`),
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
