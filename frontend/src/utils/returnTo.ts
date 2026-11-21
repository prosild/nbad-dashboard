/**
 * T27 로그인 뒤 원래 주소. 라우터 상태(location.state.from)로만 넘기고 URL 쿼리에는 넣지 않는다.
 * 받는 값은 앱 안 경로뿐이다: '/'로 시작하고, '//'·'/\'로 시작하지 않고, '/login'으로 시작하지 않는다. 쿼리는 포함해도 된다.
 */
export function safeReturnPath(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return null;
  if (!value.startsWith('/')) return null;
  if (value.startsWith('//') || value.startsWith('/\\')) return null;
  if (value.startsWith('/login')) return null;
  // 제어 문자(줄바꿈 등)가 든 값은 받지 않는다
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return null;
  }
  return value;
}

/** location.state에서 원래 주소를 꺼낸다(검사를 통과한 값만) */
export function returnPathFromState(state: unknown): string | null {
  if (!state || typeof state !== 'object') return null;
  return safeReturnPath((state as { from?: unknown }).from);
}

/** 라우터 상태에 실을 값. 지금 주소가 앱 안 경로가 아니면(로그인 화면 등) 싣지 않는다 */
export function fromState(path: string): { from: string } | undefined {
  const safe = safeReturnPath(path);
  return safe ? { from: safe } : undefined;
}
