import { apiRequest } from './client';
import type { HostRiskResponse, RelatedHostIncidentsResponse } from '../types/hosts';

/** GET /api/hosts 파라미터(T46). 빈 값은 빠진다 */
export interface HostListParams {
  period: string;
  /** period=custom일 때만 */
  start?: string;
  end?: string;
  source?: string;
  captureId?: string;
  sort?: string;
  dir?: string;
  q?: string;
  roleTransitionOnly?: string;
  page?: string;
  size?: string;
}

function query(params: Record<string, string | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value.trim() !== '') {
      search.set(key, value);
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
}

export const hostsApi = {
  /** 호스트 위험도 목록: 현황판과 같은 조건의 인시던트를 호스트(조회자는 대역)로 묶은 값 */
  list: (params: HostListParams) =>
    apiRequest<HostRiskResponse>(`/api/hosts${query({ ...params })}`),
  /** 상세의 같은 호스트 인시던트(조회자는 같은 대역). 상세와 따로 부른다 */
  related: (jobId: number | string, queueRank: number | string) =>
    apiRequest<RelatedHostIncidentsResponse>(`/api/incidents/${jobId}/rank/${queueRank}/related-host-incidents`),
};
