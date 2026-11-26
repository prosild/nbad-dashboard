import { describe, expect, it } from 'vitest';
import type { AttackCandidateItem, ReportView } from '../types/api';
import { ATTACK_VISIBLE_TOP, splitAttackCandidates } from '../utils/attackCandidates';
import { hiddenCharMarker, markHiddenChars } from '../utils/hiddenChars';
import { baseDetail } from './detailFixture';

/**
 * T64 화면 쪽 도우미. 숨은 문자 집합과 표지 꼴은 서버 글자 정책(T63)과 같다(내보내기에 쓴다. 여러 줄 모드).
 * ATT&CK 후보 접기: 앞 3개와 해석이 인용한 후보만 보인다.
 */

describe('T64 숨은 문자 표지(여러 줄 모드)', () => {
  it('제어·서식·줄 구분 문자를 [U+XXXX]로 바꾼다', () => {
    const cases: Array<[string, string]> = [
      ['\u0000', '[U+0000]'],
      ['\u001B', '[U+001B]'],
      ['\u007F', '[U+007F]'],
      ['\u0085', '[U+0085]'],
      ['\u202E', '[U+202E]'],
      ['\u202A', '[U+202A]'],
      ['\u2066', '[U+2066]'],
      ['\u200B', '[U+200B]'],
      ['\u200D', '[U+200D]'],
      ['\uFEFF', '[U+FEFF]'],
      ['\u{E0001}', '[U+E0001]'],
      ['\u2028', '[U+2028]'],
      ['\u2029', '[U+2029]'],
    ];
    for (const [raw, marked] of cases) expect(markHiddenChars(`a${raw}b`), marked).toBe(`a${marked}b`);
  });

  it('Default_Ignorable_Code_Point(한글 채움 문자·변형 선택자·CGJ·연한 하이픈 등)도 숨은 문자다', () => {
    for (const raw of ['\u115F', '\u1160', '\u3164', '\uFFA0', '\uFE00', '\uFE0F', '\u{E0100}', '\u{E01EF}', '\u034F', '\u17B4', '\u17B5', '\u180B', '\u180F', '\u00AD']) {
      expect(markHiddenChars(raw), raw.codePointAt(0)?.toString(16)).toBe(hiddenCharMarker(raw.codePointAt(0) as number));
    }
    expect(markHiddenChars('\u{E0100}')).toBe('[U+E0100]');
  });

  it('짝 없는 서러게이트는 표지, 짝 맞은 쌍(이모지)은 그대로', () => {
    expect(markHiddenChars('a\uD800b')).toBe('a[U+D800]b');
    expect(markHiddenChars('a\uDC00')).toBe('a[U+DC00]');
    expect(markHiddenChars('😀bob')).toBe('😀bob');
  });

  it('여러 줄 모드: \\n·\\t는 남기고 \\r\\n은 \\n, 홀로 있는 \\r은 표지', () => {
    expect(markHiddenChars('a\nb\tc')).toBe('a\nb\tc');
    expect(markHiddenChars('a\r\nb')).toBe('a\nb');
    expect(markHiddenChars('a\rb')).toBe('a[U+000D]b');
    expect(markHiddenChars('a\r\r\nb')).toBe('a[U+000D]\nb');
  });

  it('결합 문자는 한 글자에 3개까지 남기고 넘는 몫만 표지(숨은 문자는 이어짐을 끊지 않는다)', () => {
    expect(markHiddenChars('e\u0301\u0302\u0303')).toBe('e\u0301\u0302\u0303');
    expect(markHiddenChars('e\u0301\u0302\u0303\u0304\u20DD')).toBe('e\u0301\u0302\u0303[U+0304][U+20DD]');
    expect(markHiddenChars('e\u0301\u0301\u200B\u0301\u0301')).toBe('e\u0301\u0301[U+200B]\u0301[U+0301]');
    // 새 기본 글자(줄바꿈 포함)에서 다시 센다
    expect(markHiddenChars('e\u0301\u0301\u0301a\u0301\u0301\u0301')).toBe('e\u0301\u0301\u0301a\u0301\u0301\u0301');
    expect(markHiddenChars('e\u0301\u0301\u0301\n\u0301')).toBe('e\u0301\u0301\u0301\n\u0301');
    // 한글 자모 조합·보통 글자는 그대로
    expect(markHiddenChars('한글 ᄒᆞᆫ글 café')).toBe('한글 ᄒᆞᆫ글 café');
  });

  it('보이는 공백·글자와 서버 표지는 바꾸지 않는다(두 번 처리해도 같다)', () => {
    const visible = 'a b　c [U+202E] …(39자 생략) [보이지 않는 문자 2개 제거] <b>&amp;</b>';
    expect(markHiddenChars(visible)).toBe(visible);
    const raw = 'x\u202E\u0000\r\ny\re\u0301\u0301\u0301\u0301\uD800\u3164';
    const once = markHiddenChars(raw);
    expect(markHiddenChars(once)).toBe(once);
    expect(once).toBe('x[U+202E][U+0000]\ny[U+000D]e\u0301\u0301\u0301[U+0301][U+D800][U+3164]');
  });

  it('표지는 16진 대문자 4~6자리', () => {
    expect(hiddenCharMarker(0x0)).toBe('[U+0000]');
    expect(hiddenCharMarker(0x202e)).toBe('[U+202E]');
    expect(hiddenCharMarker(0xe0001)).toBe('[U+E0001]');
    expect(hiddenCharMarker(0x10ffff)).toBe('[U+10FFFF]');
  });
});

const cand = (id: string): AttackCandidateItem => ({ attackId: id, name: id, tactics: [] });

function report(ids: string[], cited: string[][]): ReportView {
  return {
    ...baseDetail().report,
    attackCandidates: ids.map(cand),
    possibleExplanations: cited.map((attackIds) => ({ explanation: 'x', facts: [], attackIds })),
  };
}

describe('T64 ATT&CK 후보 나누기', () => {
  const ids = (list: Array<{ candidate: AttackCandidateItem }>) => list.map((e) => e.candidate.attackId);

  it('앞 3개 + 해석이 인용한 후보는 보이고, 나머지는 접는다(받은 순서 그대로, 원래 위치 유지)', () => {
    expect(ATTACK_VISIBLE_TOP).toBe(3);
    const split = splitAttackCandidates(report(['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7'], [['T6'], ['t5 ', 'T9']]));
    expect(ids(split.shown)).toEqual(['T1', 'T2', 'T3', 'T5', 'T6']);
    expect(ids(split.folded)).toEqual(['T4', 'T7']);
    expect(split.shown.map((e) => e.index)).toEqual([0, 1, 2, 4, 5]);
    expect(split.folded.map((e) => e.index)).toEqual([3, 6]);
  });

  it('후보가 3개 이하면 접을 것이 없다', () => {
    const split = splitAttackCandidates(report(['T1', 'T2'], []));
    expect(ids(split.shown)).toEqual(['T1', 'T2']);
    expect(split.folded).toEqual([]);
  });
});
