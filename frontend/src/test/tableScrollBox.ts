import { expect } from 'vitest';

/**
 * T26 휴대폰 폭 구조 시험 도우미: 화면의 모든 `table`은 가로 스크롤 상자(`overflow-x-auto`·`overflow-x-scroll` 클래스) 안에 있어야 한다.
 * 그래야 넓은 표가 휴대폰에서 페이지 전체를 넓히지(축소해 보이게 하지) 않는다.
 *
 * 한계: jsdom은 CSS를 적용하지 않으므로 클래스만 본다. 표가 아닌 넘침(줄바꿈되지 않는 긴 글자, `whitespace-nowrap` flex 행,
 * 넓은 SVG 등)은 여기서 잡을 수 없고 실제 휴대폰 폭 브라우저 측정으로만 잡힌다.
 */
const SCROLL_BOX_CLASS = /(^|\s)overflow-x-(auto|scroll)(\s|$)/;

/** 표를 사람이 알아볼 수 있게 적는다: 가장 가까운 aria-label 조상 · 캡션 · 첫 머리글. */
export function describeTable(table: HTMLTableElement): string {
  const labelled = table.closest('[aria-label]');
  const label = labelled ? labelled.getAttribute('aria-label') : null;
  const caption = table.caption?.textContent?.trim();
  const firstHeaders = Array.from(table.querySelectorAll('th'))
    .slice(0, 3)
    .map((th) => (th.textContent ?? '').trim())
    .join(' | ');
  return [label ? `영역 "${label}"` : null, caption ? `캡션 "${caption.slice(0, 30)}"` : null, `머리글 ${firstHeaders}`]
    .filter(Boolean)
    .join(' · ');
}

/** 화면 판독기 전용 표(`sr-only`, T24 탐지 추이 구간 표)는 1px 상자 안이라 페이지를 넓히지 않는다. */
function isScreenReaderOnly(table: Element): boolean {
  for (let el: Element | null = table; el; el = el.parentElement) {
    if ((el.getAttribute('class') ?? '').split(/\s+/).includes('sr-only')) return true;
  }
  return false;
}

/** 가로 스크롤 상자 조상이 없는 표 목록(설명 문자열). 화면 판독기 전용 표는 뺀다. */
export function tablesOutsideScrollBox(root: ParentNode = document.body): string[] {
  const out: string[] = [];
  for (const table of Array.from(root.querySelectorAll('table'))) {
    if (isScreenReaderOnly(table)) continue;
    let boxed = false;
    for (let el = table.parentElement; el; el = el.parentElement) {
      if (SCROLL_BOX_CLASS.test(el.getAttribute('class') ?? '')) {
        boxed = true;
        break;
      }
    }
    if (!boxed) out.push(describeTable(table));
  }
  return out;
}

/** 그려진 표가 하나 이상 있고, 모두 가로 스크롤 상자 안에 있다고 단언한다. */
export function expectAllTablesInScrollBox(root: ParentNode = document.body): void {
  expect(root.querySelectorAll('table').length).toBeGreaterThan(0);
  expect(tablesOutsideScrollBox(root)).toEqual([]);
}

/** `md` 미만에서 숨는 클래스(`hidden … md:block|md:table|…`)가 요소나 그 조상에 있는지. */
export function hiddenBelowMd(el: Element): boolean {
  for (let cur: Element | null = el; cur; cur = cur.parentElement) {
    const cls = (cur.getAttribute('class') ?? '').split(/\s+/);
    if (cls.includes('hidden') && cls.some((c) => /^md:(block|table|flex|grid|inline|inline-block|table-cell)$/.test(c))) {
      return true;
    }
  }
  return false;
}
