/// <reference types="vite/client" />
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import { BANNED_SOURCE_TERMS, OLD_TERMS, T68_REMOVED_TERMS } from './screenTerms';

/**
 * T68 화면 문구 회귀 검사(정적): 화면 글이 든 소스의 문자열 리터럴, 템플릿 리터럴의 고정 부분, JSX 본문 글(JSXText),
 * JSX 속성 문자열에 옛 표기(OLD_TERMS)와 T68에서 없앤 말(닫힌 목록, fixtures/screen-terms.json)이 없어야 한다.
 * 빼는 것은 주석(`//`, 덩어리 주석, JSDoc)뿐이다(TypeScript 파서의 구문 트리에 주석은 없다). 그린 화면 시험은 시험 자료가
 * 그리는 글만 보므로(사실 사전·툴팁·화면 읽기 글이 빠지기 쉽다) 소스를 직접 읽는다(handoff/T68/designer-answer-1.md H2·M2).
 */
// import.meta.glob의 둘째 인자는 객체 리터럴이어야 한다(vite:import-glob). 시험 폴더는 utils·components·pages 밖에 있다.
const SOURCES: Record<string, string> = {
  ...(import.meta.glob('../utils/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
  ...(import.meta.glob('../components/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
  ...(import.meta.glob('../pages/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
};

/**
 * 허용 목록: 파일 + 정확한 글(공백은 한 칸으로 편 리터럴 전체) + 까닭. 계약 글이라 고치지 않는 것만 둔다.
 * 각 항목이 지금도 그 파일에 있는지 아래 시험이 단언한다(낡은 허용 항목이 남지 않게).
 */
const ALLOWED: { file: string; text: string; reason: string }[] = [
  {
    file: '../utils/labels.ts',
    text: '5분 구간의 통신 특징 42개(연결 수, 목적지 포트 수, 연결 실패 비율, 프로토콜 로그 등) 중 정상 기간에 거의 없던 값이 있는 정도. 가장 드문 특징 하나가 점수다. 정찰·스캔, 인증 실패 반복에 강하다.',
    reason: '탐지 저장소 계약 v2 모델 표시 문구(tail_rarity_v2 툴팁, docs/ui-terminology.md "탐지 모델 표시 이름")',
  },
];

interface Literal {
  text: string;
  line: number;
}

/** 소스의 문자열 리터럴(JSX 속성 글 포함)·템플릿 고정 부분·JSX 본문 글. 공백(줄바꿈 포함)은 한 칸으로 편다. */
function screenLiterals(fileName: string, source: string): Literal[] {
  const kind = fileName.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
  const out: Literal[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return;
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node) ||
      ts.isJsxText(node)
    ) {
      out.push({ text: node.text.replace(/\s+/g, ' ').trim(), line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1 });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function isAllowed(fileName: string, text: string): boolean {
  return ALLOWED.some((a) => a.file === fileName && a.text === text);
}

function findBanned(fileName: string, source: string): string[] {
  const hits: string[] = [];
  for (const lit of screenLiterals(fileName, source)) {
    if (isAllowed(fileName, lit.text)) continue;
    for (const term of BANNED_SOURCE_TERMS) {
      if (lit.text.includes(term)) hits.push(`${fileName}:${lit.line} "${term}" ← ${lit.text.slice(0, 80)}`);
    }
  }
  return hits;
}

describe('T68 화면 글 소스 정적 검사', () => {
  it('막는 낱말은 닫힌 목록이다(OLD_TERMS 전부 + 설계자 답 M2의 15개 + 추가 결정 "증적")', () => {
    expect(OLD_TERMS.length).toBe(44);
    expect(T68_REMOVED_TERMS).toEqual([
      '틀 문장',
      '거르기',
      '채점',
      '조사 중',
      '조사 시작',
      '조사를 시작',
      '자산 검색',
      '부푼',
      '기준 시각 기준',
      '쪽당',
      '함께 탐지한 모델',
      '이상 판정 구간',
      '첫 알림',
      '이동 목록',
      '사전에 없는',
      '증적',
    ]);
    for (const t of [...OLD_TERMS, ...T68_REMOVED_TERMS]) expect(BANNED_SOURCE_TERMS).toContain(t);
  });

  it('양성 대조: JSX 본문 글·JSX 속성 글·템플릿 리터럴·문자열 리터럴의 낱말은 잡고, 주석 속 낱말은 통과한다', () => {
    const sample = [
      '// 틀 문장은 한 줄 주석이라 괜찮다',
      '/* 거르기는 덩어리 주석이라 괜찮다 */',
      '/** 채점은 JSDoc이라 괜찮다 */',
      'const a = <p>마지막 채점</p>;',
      'const b = `${n}쪽당 ${m}건`;',
      "const c = '즉시 알림(틀 문장)';",
      'const d = <input aria-label="검색·거르기" />;',
      'const e = <p>조사를\n    시작하면</p>;',
    ].join('\n');
    const hits = findBanned('sample.tsx', sample);
    expect(hits.some((h) => h.startsWith('sample.tsx:4 "채점"'))).toBe(true);
    expect(hits.some((h) => h.startsWith('sample.tsx:5 "쪽당"'))).toBe(true);
    expect(hits.some((h) => h.startsWith('sample.tsx:6 "틀 문장"'))).toBe(true);
    expect(hits.some((h) => h.startsWith('sample.tsx:7 "거르기"'))).toBe(true);
    // 줄을 바꿔 쓴 JSX 글도 한 칸으로 펴서 잡는다
    expect(hits.some((h) => h.startsWith('sample.tsx:8 "조사를 시작"'))).toBe(true);
    expect(hits.filter((h) => /^sample\.tsx:[123] /.test(h))).toEqual([]);
  });

  it('허용 목록: 정확한 글만 통과하고 각 항목은 지금도 그 파일에 있다', () => {
    const allowed = ALLOWED[0];
    expect(findBanned(allowed.file, `const x = '${allowed.text}';`)).toEqual([]);
    // 같은 낱말이라도 허용 글과 다르면 잡는다
    expect(findBanned(allowed.file, "const y = '세션 연결 수';")).toHaveLength(1);
    expect(findBanned('../utils/other.ts', `const x = '${allowed.text}';`)).toHaveLength(1);
    for (const a of ALLOWED) {
      expect(SOURCES[a.file], a.file).toBeDefined();
      expect(screenLiterals(a.file, SOURCES[a.file]).map((l) => l.text), `${a.file} 허용 글(${a.reason})`).toContain(a.text);
    }
  });

  it('읽는 소스가 비지 않았다(utils 전체, components, pages)', () => {
    const names = Object.keys(SOURCES);
    for (const must of [
      '../utils/labels.ts',
      '../utils/factLabels.ts',
      '../utils/operations.ts',
      '../utils/periodRange.ts',
      '../utils/incidentExport.ts',
      '../components/incident/SlackThreadsSection.tsx',
      '../pages/DashboardPage.tsx',
    ]) {
      expect(names, must).toContain(must);
    }
    expect(names.some((n) => n.includes('/test/'))).toBe(false);
    expect(names.length).toBeGreaterThan(55);
  });

  it('화면 글 소스에 옛 표기와 T68에서 없앤 말이 없다', () => {
    const hits = Object.entries(SOURCES).flatMap(([name, src]) => findBanned(name, src));
    expect(hits, hits.join('\n')).toEqual([]);
  });
});
