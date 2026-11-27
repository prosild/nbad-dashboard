/**
 * 화면에 다시 나오면 안 되는 옛 표기. 목록은 fixtures/screen-terms.json 한 곳에 있고 세 시험이 함께 읽는다.
 * - uiTerminology.test.tsx: 그린 화면 글(expectCleanText, OLD_TERMS)
 * - t68ScreenWording.test.ts: 화면 글이 든 소스의 문자열·템플릿·JSX 글(정적 검사, 주석 제외)
 * - T68ScreenWordingStaticTest.java: 서버 문자열 리터럴(정적 검사, 주석 제외)
 */
import terms from './fixtures/screen-terms.json';

/** T17·T18 표기 중 T18b~T27에서 바꾼 것(uiTerminology.test.tsx에 있던 목록 그대로) */
export const OLD_TERMS: string[] = terms.oldTerms.flatMap((g) => g.terms);

/** T68에서 없앤 말(설계자 답 M2의 닫힌 목록) */
export const T68_REMOVED_TERMS: string[] = terms.t68Terms.terms;

/** 정적 검사가 막는 낱말(겹침 제거) */
export const BANNED_SOURCE_TERMS: string[] = [...new Set([...OLD_TERMS, ...T68_REMOVED_TERMS])];
