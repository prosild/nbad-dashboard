import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Link } from 'react-router-dom';
import { DetectionModelName, SocBadge } from '../StatusBadge';
import { detectionModelInfo } from '../../utils/labels';
import { hostIpKind, IP_SCOPE_LABEL, ipScope, isIpText } from '../../utils/ipScope';

/**
 * 조사 동선(T44·T45): 상세에서 한 번 눌러 옮겨 가거나 가져가는 것들.
 * 호스트 피벗(`HostPivot`)은 서버 `hostIp=` 정확 일치 필터(T45)를 쓴다. `asset=`은 부분 일치라 다른 호스트가 섞인다.
 */

/**
 * 호스트 IP → 그 호스트의 인시던트 목록(전체 기간, `hostIp` 정확 일치).
 * 온전한 IPv4면 그 호스트, 조회자에게 가려진 주소(`A.B.*.*`)면 같은 대역의 호스트 전부다(조회자는 원문을 모른다).
 * 그 밖의 글(IPv6 등 서버가 받지 않는 꼴)은 링크 없이 글로 둔다.
 */
export function HostPivot({ ip, className }: { ip: string; className: string }) {
  const kind = hostIpKind(ip);
  if (!kind) return <span className={className}>{ip}</span>;
  const label = kind === 'exact' ? `호스트 ${ip} 인시던트 보기` : `같은 대역(${ip}) 인시던트 보기`;
  return (
    <Link
      to={`/incidents?period=all&hostIp=${encodeURIComponent(ip)}`}
      title={label}
      aria-label={label}
      data-host-pivot={kind}
      className={`${className} rounded underline decoration-slate-600 underline-offset-2 hover:decoration-cyan-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50`}
    >
      {ip}
    </Link>
  );
}

/** 탐지 모델 이름 → 그 모델이 탐지한 인시던트 목록(전체 기간, `pickedBy` 정확 일치) */
export function ModelPivot({ id }: { id: string | null }) {
  const name = <DetectionModelName id={id} variant="detail" className="font-semibold text-slate-100" />;
  if (!id) return name;
  const label = `탐지 모델 ${detectionModelInfo(id).text} 인시던트 보기`;
  return (
    <Link
      to={`/incidents?period=all&pickedBy=${encodeURIComponent(id)}`}
      title={label}
      aria-label={label}
      className="min-w-0 rounded underline decoration-slate-600 underline-offset-2 hover:decoration-cyan-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
    >
      {name}
    </Link>
  );
}

type CopyState = 'idle' | 'copied' | 'failed';

/** 복사 결과(아이콘·판독기 글)를 보였다가 처음 모양으로 되돌리는 시간 */
export const COPY_FEEDBACK_MS = 2000;

const COPY_MESSAGE: Record<CopyState, string> = {
  idle: '',
  copied: '주소를 복사했습니다.',
  failed: '주소를 복사하지 못했습니다.',
};

/**
 * 주소 옆 대역 표지(사설·외부)와 복사 버튼. 주소가 아니면 아무것도 그리지 않는다.
 * `iconOnly`(주요 세션 표)는 보이는 글자 없이 버튼만 두고 대역은 툴팁에 적는다(칸 글자와 표 밀도를 그대로 둔다).
 * 복사 결과는 아이콘과 화면 판독기 글로 알리고 잠시 뒤 되돌린다. 알림 영역은 처음부터 빈 채로 둔다
 * (누를 때 새로 끼우면 판독기가 읽지 않을 수 있고, 비어 있으면 칸 글자에 더해지는 것이 없다).
 */
export function IpActions({
  ip,
  label = '상대',
  iconOnly = false,
}: {
  ip: unknown;
  label?: '상대' | '출발지' | '목적지';
  iconOnly?: boolean;
}) {
  const [state, setState] = useState<CopyState>('idle');
  const resetTimer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    },
    [],
  );
  if (!isIpText(ip)) return null;
  const scope = ipScope(ip);
  const scopeLabel = scope ? IP_SCOPE_LABEL[scope] : null;
  const action = `${label} IP ${ip} 복사`;

  function show(next: CopyState) {
    setState(next);
    if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => setState('idle'), COPY_FEEDBACK_MS);
  }

  async function copy(value: string) {
    try {
      if (!navigator.clipboard) throw new Error('clipboard');
      await navigator.clipboard.writeText(value);
      show('copied');
    } catch {
      show('failed');
    }
  }

  // relative: 알림 영역(.sr-only, 절대 위치)의 기준 상자를 여기로 잡는다. 없으면 가로 스크롤 표(주요 세션) 안에서
  // 스크롤 상자 밖 조상을 기준으로 놓여 휴대폰 폭에서 페이지를 넓힌다(360px에서 152px 넘침으로 측정됨).
  return (
    <span className="relative ml-1 inline-flex items-center gap-1 align-middle" data-ip-actions="">
      {!iconOnly && scopeLabel && <SocBadge title={scopeLabel.title}>{scopeLabel.text}</SocBadge>}
      <button
        type="button"
        aria-label={action}
        title={iconOnly && scopeLabel ? `${action} · ${scopeLabel.title}` : action}
        className="rounded p-0.5 text-slate-400 hover:text-cyan-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
        onClick={() => void copy(ip)}
      >
        {state === 'copied' ? (
          <Check className="h-3 w-3 text-emerald-300" aria-hidden="true" />
        ) : (
          <Copy className={`h-3 w-3 ${state === 'failed' ? 'text-amber-300' : ''}`} aria-hidden="true" />
        )}
      </button>
      <span aria-live="polite" className="sr-only" data-copy-result="">
        {COPY_MESSAGE[state]}
      </span>
    </span>
  );
}
