/**
 * T64 숨은 문자 표지(화면 쪽). 서버 글자 정책(T63)과 같은 집합과 표지 꼴을 쓴다. 내보내기(CSV·마크다운)가 칸마다 부른다.
 * 화면에 그리는 글은 서버가 이미 처리해 보내므로 여기서 다시 바꾸지 않는다.
 *
 * 숨은 문자: 제어 문자(Cc, 여러 줄 모드라 `\n`·`\t`는 뺀다), 서식 문자(Cf), 줄·문단 구분자(Zl·Zp),
 * Default_Ignorable_Code_Point(한글 채움 문자, 변형 선택자, CGJ, 연한 하이픈 등), 짝 없는 서러게이트(Cs),
 * 그리고 한 글자에 3개를 넘게 이어 붙은 결합 문자(Mn·Me)의 넘는 몫. `\r\n`은 `\n`으로, 홀로 있는 `\r`은 숨은 문자로 본다.
 * 표지는 `[U+202E]`(16진 대문자 4~6자리)이다. ASCII라 한 번 더 처리해도 바뀌지 않는다.
 */

const HIDDEN = /^[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Cs}]$/u;
const COMBINING = /^[\p{Mn}\p{Me}]$/u;

/** 한 글자에 남기는 결합 문자 수 */
export const MAX_COMBINING_MARKS = 3;

export function hiddenCharMarker(codePoint: number): string {
  return `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]`;
}

/**
 * 숨은 문자를 그 자리에 표지로 바꾼다(여러 줄 모드: `\n`·`\t`는 남는다).
 * 결합 문자는 마지막 기본 글자(결합 문자도 숨은 문자도 아닌 글자, 줄바꿈·탭 포함) 뒤로 센다. 숨은 문자는 세지 않고 이어짐도 끊지 않는다.
 */
export function markHiddenChars(value: string): string {
  const chars = Array.from(value); // 코드 포인트 단위. 짝 없는 서러게이트는 한 칸이다.
  let out = '';
  let marks = 0;
  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i];
    if (ch === '\r' && chars[i + 1] === '\n') continue;
    if (ch === '\n' || ch === '\t') {
      out += ch;
      marks = 0;
    } else if (HIDDEN.test(ch)) {
      out += hiddenCharMarker(ch.codePointAt(0) as number);
    } else if (COMBINING.test(ch)) {
      marks += 1;
      out += marks > MAX_COMBINING_MARKS ? hiddenCharMarker(ch.codePointAt(0) as number) : ch;
    } else {
      out += ch;
      marks = 0;
    }
  }
  return out;
}
