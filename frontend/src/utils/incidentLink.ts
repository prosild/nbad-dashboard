/**
 * T27 인시던트 상세 주소. 번호가 있으면 고정 주소 `/incidents/{번호}`, 없으면 옛 주소 `/incidents/{작업}/rank/{순위}`.
 * 쿼리(`from=` 목록 조건, `tab=`)는 그대로 붙인다. 둘 다 없으면 null(링크를 숨긴다).
 */
export interface IncidentLinkKey {
  incidentNo?: number | null;
  jobId?: number | null;
  queueRank?: number | null;
}

export function incidentPath(key: IncidentLinkKey, query?: URLSearchParams | string | null): string | null {
  let base: string | null = null;
  if (typeof key.incidentNo === 'number' && key.incidentNo > 0) {
    base = `/incidents/${key.incidentNo}`;
  } else if (typeof key.jobId === 'number' && typeof key.queueRank === 'number') {
    base = `/incidents/${key.jobId}/rank/${key.queueRank}`;
  }
  if (base === null) return null;
  const qs = query == null ? '' : query.toString();
  return qs ? `${base}?${qs}` : base;
}

/** 링크 복사 값: `{origin}/incidents/{번호}`(쿼리 없음) */
export function incidentShareUrl(incidentNo: number, origin: string = window.location.origin): string {
  return `${origin}/incidents/${incidentNo}`;
}

/** 경로 조각이 인시던트 번호(양의 정수)인지 */
export function parseIncidentNo(raw: string | undefined): number | null {
  if (!raw || !/^[0-9]{1,15}$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}
