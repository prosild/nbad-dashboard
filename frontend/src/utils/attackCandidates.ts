import type { AttackCandidateItem, ReportView } from '../types/api';

/**
 * T64 ATT&CK 후보 접기. 후보는 검색으로 찾은 MITRE 자료이고 받은 순서가 파이프라인의 순위다(확정이 아닌 가설).
 * 앞 몇 개와 가능한 해석(possibleExplanations[].attackIds)이 인용한 후보는 늘 보이고 나머지는 접는다.
 * 상세 화면(요약·AI 리포트 탭)과 마크다운 요약이 같은 규칙을 쓴다. 서버는 개수를 자르지 않는다.
 */
export const ATTACK_VISIBLE_TOP = 3;

export interface AttackCandidateEntry {
  candidate: AttackCandidateItem;
  /** 받은 목록에서의 위치(순위 - 1) */
  index: number;
}

function normalizeId(id: string): string {
  return id.trim().toUpperCase();
}

export function splitAttackCandidates(
  report: Pick<ReportView, 'attackCandidates' | 'possibleExplanations'>,
): { shown: AttackCandidateEntry[]; folded: AttackCandidateEntry[] } {
  const cited = new Set(report.possibleExplanations.flatMap((item) => item.attackIds.map(normalizeId)));
  const shown: AttackCandidateEntry[] = [];
  const folded: AttackCandidateEntry[] = [];
  report.attackCandidates.forEach((candidate, index) => {
    const entry = { candidate, index };
    if (index < ATTACK_VISIBLE_TOP || cited.has(normalizeId(candidate.attackId))) shown.push(entry);
    else folded.push(entry);
  });
  return { shown, folded };
}
