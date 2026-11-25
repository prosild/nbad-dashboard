import { useEffect, useRef, useState } from 'react';

/** 상자 폭을 재기 전(시험 환경의 폭 0 포함)에 쓰는 폭 */
const FALLBACK_WIDTH = 640;

/**
 * 상자 폭을 재서 SVG viewBox를 맞추는 데 쓴다(탐지 추이 T24, 주요 통신 구조 T44).
 * 인라인 style 없이 폭에 맞추려면 SVG 기하 속성을 폭으로 계산해야 한다.
 */
export function useContainerWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(FALLBACK_WIDTH);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const measure = () => {
      const w = el.clientWidth;
      if (w > 0) setWidth(w);
    };
    measure();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(() => measure());
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}
