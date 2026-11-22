/**
 * T33 사유·메모 길이 상한(서버 FreeTextLimits와 같은 500자). 입력 칸 maxLength와 글자 수 표시에 쓴다.
 * maxLength는 UTF-16 단위로 세므로 화면 제한은 서버(코드 포인트)보다 같거나 엄격하다.
 */
export const FREE_TEXT_MAX = 500;

/** 앞뒤 공백을 뺀 글자 수(코드 포인트, 서버와 같은 기준) */
export function freeTextLength(value: string): number {
  return Array.from(value.trim()).length;
}
