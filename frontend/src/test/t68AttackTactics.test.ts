import { describe, expect, it } from 'vitest';
import { lookupLabel } from '../utils/labels';
import { attackFilterLabel } from '../utils/attackFilter';
import snapshot from './fixtures/public-attack-tactics.json';

/**
 * T68 추가 결정 2: ATT&CK 전술 사전(labels.ts attackTactic)이 공개 스냅샷의 전술 값을 모두 덮는다.
 * ATT&CK v19(2026-04)는 Defense Evasion을 Stealth(TA0005)와 Defense Impairment(TA0112)로 나눴다(MITRE 전술 페이지·v19 공지). 탐지 파이프라인은 stealth를 보낸다.
 */
describe('T68 ATT&CK 전술 표시 이름', () => {
  it('공개 스냅샷의 전술 값은 모두 사전에 있고 영어 원문으로 남지 않는다', () => {
    expect(snapshot.tactics.length).toBe(11);
    const missing = snapshot.tactics.filter((t) => !lookupLabel('attackTactic', t).known);
    expect(missing).toEqual([]);
    for (const t of snapshot.tactics) {
      expect(lookupLabel('attackTactic', t).text, t).toMatch(/^[가-힣 ]+$/);
    }
  });

  it('stealth → 은닉, defense-impairment → 방어 무력화(슬러그·제목 표기 모두), 옛 defense-evasion은 그대로', () => {
    for (const v of ['stealth', 'Stealth', 'STEALTH']) expect(lookupLabel('attackTactic', v)).toMatchObject({ text: '은닉', known: true });
    for (const v of ['defense-impairment', 'defense impairment', 'Defense Impairment']) {
      expect(lookupLabel('attackTactic', v)).toMatchObject({ text: '방어 무력화', known: true });
    }
    expect(lookupLabel('attackTactic', 'defense-evasion').text).toBe('방어 회피');
    // 인시던트 목록 ATT&CK 칩도 같은 사전을 쓴다
    expect(attackFilterLabel('stealth')).toEqual({ kind: 'tactic', label: 'ATT&CK 전술', value: '은닉' });
    expect(attackFilterLabel('Defense Impairment')).toEqual({ kind: 'tactic', label: 'ATT&CK 전술', value: '방어 무력화' });
  });
});
