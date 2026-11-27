/// <reference types="vite/client" />
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import { OLD_TERMS, T68_REMOVED_TERMS } from './screenTerms';

/**
 * T68 화면 문구 회귀 검사(정적): 화면 글이 든 소스의 문자열 리터럴·JSX 글(주석 제외)에
 * 옛 표기(OLD_TERMS, T18b~T27)와 T68에서 없앤 말(T68_REMOVED_TERMS)이 없어야 한다.
 * 그린 화면 시험은 시험 자료가 그리는 글만 보므로(사실 사전·툴팁·화면 읽기 글은 빠지기 쉽다) 소스를 직접 읽는다.
 */
// import.meta.glob의 둘째 인자는 객체 리터럴이어야 한다(vite:import-glob)
const SOURCES: Record<string, string> = {
  ...(import.meta.glob('../utils/{labels,factLabels,operations}.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
  ...(import.meta.glob('../components/**/*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
  ...(import.meta.glob('../pages/**/*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
};

/**
 * 검사에서 빼는 선언. 탐지 저장소(zeek_AD)가 확정한 모델 툴팁 글은 그대로 옮긴 글이라 화면 용어 재정비와 별개다
 * (docs/ui-terminology.md '탐지 모델 표시 이름': "연결 수" 같은 말을 그대로 둔다).
 */
const EXEMPT_DECLARATIONS = new Set(['DETECTION_MODEL_INFO']);

const BANNED = [...OLD_TERMS, ...T68_REMOVED_TERMS];

interface Literal {
  text: string;
  line: number;
}

/** 소스의 문자열 리터럴·템플릿 조각·JSX 글. 주석은 구문 트리에 없으므로 저절로 빠진다. 공백(줄바꿈 포함)은 한 칸으로 편다. */
function screenLiterals(fileName: string, source: string): Literal[] {
  const kind = fileName.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
  const out: Literal[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && EXEMPT_DECLARATIONS.has(node.name.text)) return;
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node) ||
      ts.isJsxText(node)
    ) {
      out.push({ text: node.text.replace(/\s+/g, ' '), line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1 });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function findBanned(fileName: string, source: string): string[] {
  const hits: string[] = [];
  for (const lit of screenLiterals(fileName, source)) {
    for (const term of BANNED) {
      if (lit.text.includes(term)) hits.push(`${fileName}:${lit.line} "${term}" ← ${lit.text.slice(0, 80)}`);
    }
  }
  return hits;
}

describe('T68 화면 글 소스 정적 검사', () => {
  it('검사 함수: 리터럴·템플릿·JSX 글의 옛 말은 잡고 주석과 예외 선언은 뺀다', () => {
    const sample = [
      "// 틀 문장은 주석이라 괜찮다",
      "/** 구간당 설명 */",
      "const a = '즉시 알림(틀 문장)';",
      'const b = `${n} 구간당 ${m}`;',
      'const c = <p>조사를\n    시작하면</p>;',
      "const DETECTION_MODEL_INFO = { x: '연결 수' };",
    ].join('\n');
    const hits = findBanned('sample.tsx', sample);
    expect(hits.some((h) => h.includes(':3 "틀 문장"'))).toBe(true);
    expect(hits.some((h) => h.includes(':4 "구간당"'))).toBe(true);
    expect(hits.some((h) => h.includes(':5 "조사를 시작"'))).toBe(true);
    expect(hits.some((h) => h.includes(':1 ') || h.includes(':2 '))).toBe(false);
    expect(hits.some((h) => h.includes('연결 수'))).toBe(false);
  });

  it('읽는 소스가 비지 않았다(labels·factLabels·operations, components, pages)', () => {
    const names = Object.keys(SOURCES);
    for (const must of ['../utils/labels.ts', '../utils/factLabels.ts', '../utils/operations.ts', '../components/incident/SlackThreadsSection.tsx', '../pages/DashboardPage.tsx']) {
      expect(names, must).toContain(must);
    }
    expect(names.length).toBeGreaterThan(40);
  });

  it('화면 글 소스에 옛 표기와 T68에서 없앤 말이 없다', () => {
    const hits = Object.entries(SOURCES).flatMap(([name, src]) => findBanned(name, src));
    expect(hits, hits.join('\n')).toEqual([]);
  });
});
