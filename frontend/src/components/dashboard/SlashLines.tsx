/**
 * T68 추가 결정 3: 판정·경보 카드 첫 줄("표본 부족 · 분석가 판정 5건 / 모델이 올린 인시던트 2,277건")을 아무 데서나 접지 않고
 * 첫 " / " 앞에서 두 줄로 보인다. 글은 그대로다: " / "는 화면 판독기·복사용으로 DOM에 남기고(시각적으로만 숨김) 두 조각을 줄로 쌓는다.
 * "/"가 없는 글("경보 없음" 등)은 한 줄이다. API 문장(FeedbackSummaryRecord)은 바꾸지 않는다.
 */
export function SlashLines({ text }: { text: string }) {
  const at = text.indexOf(' / ');
  if (at < 0) return <>{text}</>;
  return (
    <>
      <span className="block" data-line="1">
        {text.slice(0, at)}
        <span className="sr-only"> / </span>
      </span>
      <span className="block" data-line="2">
        {text.slice(at + 3)}
      </span>
    </>
  );
}
