import type { StatusHistoryItem } from '../types/api';
import { normalizeStatus } from './triage';

/**
 * T53 종결한 인시던트 다시 열기(zeek_AD dashboard.reopen_incident). 화면 문구와 이력 판단을 한곳에 둔다.
 * 다시 열면 상태가 분석 중으로 돌아가고 판정이 비워진다. 앞선 종결과 판정은 이력에 남는다.
 */

/** 조치 패널의 종결 건 문구(분석가·관리자·조회자 같다) */
export const CLOSED_INCIDENT_TEXT = '종결된 인시던트입니다.';

/** 다시 열기 폼의 안내 두 줄 */
export const REOPEN_EFFECT_NOTE = '다시 열면 상태가 분석 중으로 돌아가고 판정이 비워집니다. 앞선 종결과 판정은 이력에 남습니다.';
export const REOPEN_ASSIGN_NOTE = '담당자가 없으면 다시 연 사람이 담당자로 지정됩니다.';

/** 이력 타임라인의 종결 → 분석 중 표지 */
export const REOPENED_LABEL = '다시 열림';

/** 이력 행이 다시 열기(종결 → 분석 중)인가 */
export function isReopenTransition(item: Pick<StatusHistoryItem, 'fromStatus' | 'toStatus'>): boolean {
  return (
    item.fromStatus !== null &&
    item.fromStatus !== undefined &&
    normalizeStatus(item.fromStatus) === 'closed' &&
    normalizeStatus(item.toStatus) === 'investigating'
  );
}

/**
 * 주어진 시각보다 늦은 다시 열기 이력이 있는가(T53). 오탐 종결 결정 뒤 사람이 다시 연 건을 가린다.
 * 시각이 없거나 읽을 수 없으면 false(지금처럼 둔다).
 */
export function reopenedAfter(history: StatusHistoryItem[], iso: string | null | undefined): boolean {
  if (!iso) return false;
  const after = new Date(iso).getTime();
  if (Number.isNaN(after)) return false;
  return history.some((item) => {
    if (!isReopenTransition(item) || !item.changedAt) return false;
    const at = new Date(item.changedAt).getTime();
    return !Number.isNaN(at) && at > after;
  });
}
