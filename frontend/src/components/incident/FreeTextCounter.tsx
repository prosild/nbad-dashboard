import { FREE_TEXT_MAX, freeTextLength } from '../../utils/freeText';

/** T33 사유·메모 입력 칸 아래 글자 수 표시(입력 칸의 aria-describedby로 이어 준다) */
export function FreeTextCounter({ id, value }: { id: string; value: string }) {
  return (
    <p id={id} className="mt-1 text-right text-[11px] tabular-nums text-slate-500">
      {freeTextLength(value)}/{FREE_TEXT_MAX}자
    </p>
  );
}
