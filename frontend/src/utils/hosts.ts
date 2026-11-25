import { formatNumber } from './format';
import { hostIpKind } from './ipScope';
import { setPeriodParams, type PeriodSelection, type PresetPeriod } from './triage';

/** 호스트 위험도 화면 기본 기간(T46). 운영 현황과 같다. 서버 기본(24시간)과 달라 API에는 늘 period를 보낸다 */
export const HOSTS_DEFAULT_PERIOD: PresetPeriod = '7d';

export type HostSortKey = 'risk' | 'incidents' | 'connections' | 'lastDetected' | 'hostIp';
export type HostSortDir = 'asc' | 'desc';

export const HOST_SORT_KEYS: readonly HostSortKey[] = ['risk', 'incidents', 'connections', 'lastDetected', 'hostIp'];
export const HOST_DEFAULT_SORT: HostSortKey = 'risk';

/** 처음 정렬 방향(서버 기본과 같다): 주소만 오름, 나머지는 내림 */
export const HOST_DEFAULT_DIR: Record<HostSortKey, HostSortDir> = {
  risk: 'desc',
  incidents: 'desc',
  connections: 'desc',
  lastDetected: 'desc',
  hostIp: 'asc',
};

export const HOST_SORT_LABEL: Record<HostSortKey, string> = {
  risk: '미종결 우선순위',
  incidents: '인시던트 수',
  connections: '세션 수',
  lastDetected: '마지막 탐지',
  hostIp: '호스트 주소',
};

export function parseHostSortKey(raw: string | null | undefined): HostSortKey {
  return HOST_SORT_KEYS.find((k) => k === raw) ?? HOST_DEFAULT_SORT;
}

export function parseHostSortDir(raw: string | null | undefined, key: HostSortKey): HostSortDir {
  return raw === 'asc' || raw === 'desc' ? raw : HOST_DEFAULT_DIR[key];
}

/** 검색어 길이 상한(서버와 같다) */
export const HOST_QUERY_MAX = 100;

/**
 * 인시던트 목록의 호스트 조건(hostIp=)으로 쓸 수 있는 값인지: 온전한 IPv4나 가려진 대역(A.B.*.*)만이다(목록과 같은 판별 hostIpKind).
 * 그 밖의 값(IPv6 등)은 목록이 받지 않으므로 링크를 만들지 않고 글로 둔다.
 */
export function isHostIpFilterValue(hostIp: string | null | undefined): hostIp is string {
  return hostIpKind(hostIp) !== null;
}

/**
 * 호스트 줄 → 같은 조건(기간·수집원·캡처)의 인시던트 목록 주소. 기간은 늘 적는다(목록의 기본 기간은 24시간이라
 * 화면 기본값이라고 빼면 건수가 어긋난다). 호스트 조건으로 쓸 수 없는 값이면 null이다.
 */
export function hostIncidentsPath(
  hostIp: string | null | undefined,
  cond: { sel: PeriodSelection; source: string | null; captureId: string | null },
): string | null {
  if (!isHostIpFilterValue(hostIp)) return null;
  const q = setPeriodParams(new URLSearchParams(), cond.sel);
  if (cond.captureId) q.set('captureId', cond.captureId);
  else if (cond.source) q.set('source', cond.source);
  q.set('hostIp', hostIp);
  return `/incidents?${q.toString()}`;
}

/** 상세의 "전체 보기": 그 호스트의 전체 기간 인시던트 목록. 호스트 조건으로 쓸 수 없는 값이면 null */
export function hostAllIncidentsPath(hostIp: string | null | undefined): string | null {
  if (!isHostIpFilterValue(hostIp)) return null;
  const q = new URLSearchParams({ period: 'all' });
  q.set('hostIp', hostIp);
  return `/incidents?${q.toString()}`;
}

/**
 * 다른 인시던트의 발생 시각이 이 인시던트보다 앞인지 뒤인지와 간격.
 * 1분 미만 "같은 시각", 1시간 미만 "N분 전/뒤", 1일 미만 "N시간 전/뒤", 그 밖 "N일 전/뒤". 값이 없으면 null.
 */
export function relativeGapText(otherIso: string | null | undefined, selfIso: string | null | undefined): string | null {
  if (!otherIso || !selfIso) return null;
  const other = new Date(otherIso).getTime();
  const self = new Date(selfIso).getTime();
  if (Number.isNaN(other) || Number.isNaN(self)) return null;
  const diffSec = Math.floor(Math.abs(other - self) / 1000);
  if (diffSec < 60) return '같은 시각';
  const side = other < self ? '전' : '뒤';
  const minutes = Math.floor(diffSec / 60);
  if (minutes < 60) return `${minutes}분 ${side}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}시간 ${side}`;
  return `${formatNumber(Math.floor(hours / 24))}일 ${side}`;
}
