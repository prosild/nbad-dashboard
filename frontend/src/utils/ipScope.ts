/**
 * 상대 IP 대역 표지(T44). 앞 두 옥텟만으로 정해지는 구분만 보인다(네트워크 조회 없음).
 * 조회자에게 가려진 주소(`A.B.*.*`)도 앞 두 옥텟이 남아 같은 규칙으로 판별한다.
 * "외부"는 사설·특수 대역이 아니라는 뜻까지다. 공인 주소라고 단정하지 않는다(docs/ui-terminology.md).
 */
export type IpScope = 'private' | 'external';

export const IP_SCOPE_LABEL: Record<IpScope, { text: string; title: string }> = {
  private: { text: '사설', title: '사설 네트워크 대역' },
  external: { text: '외부', title: '사설·루프백·링크 로컬 대역 밖 외부 주소' },
};

const OCTET = /^(0|[1-9]\d{0,2})$/;

/** 온전한 IPv4면 네 옥텟, 가려진 IPv4(`A.B.*.*`)면 앞 두 옥텟. 그 밖은 null */
function ipv4Octets(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const masked = parts[2] === '*' && parts[3] === '*';
  const octets = masked ? parts.slice(0, 2) : parts;
  if (!octets.every((part) => OCTET.test(part) && Number(part) <= 255)) return null;
  return octets.map(Number);
}

function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]`).hostname !== '';
  } catch {
    return false;
  }
}

/** 복사 버튼을 붙일 주소 글인지: IPv4, 가려진 IPv4, IPv6. 포트가 붙은 글·`-`·가명은 아니다. */
export function isIpText(value: unknown): value is string {
  return typeof value === 'string' && (ipv4Octets(value) !== null || isIpv6(value));
}

/**
 * 사설(RFC 1918) / 외부. 표지를 달지 않는 특수 대역은 null:
 * `0/8`, 루프백 `127/8`, 링크 로컬 `169.254/16`, 통신사 공유 `100.64/10`, 벤치마크 `198.18/15`, 멀티캐스트·예약 `224/3`.
 * IPv6와 형식이 다른 글도 null.
 */
export function ipScope(ip: string): IpScope | null {
  const octets = ipv4Octets(ip);
  if (!octets) return null;
  const [a, b] = octets;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if (
    a === 0 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19))
  ) {
    return null;
  }
  return 'external';
}
