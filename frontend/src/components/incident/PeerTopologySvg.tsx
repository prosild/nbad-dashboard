/**
 * 증적 탭 "주요 통신 구조"(T44): 대상 호스트와 세션이 많은 상대 IP(최대 5개)를 선으로 잇는 작은 그림.
 * 엄격한 CSP(style-src 'self')를 지키려고 인라인 style 없이 상자 폭을 재서 SVG 기하 속성으로만 그린다(탐지 추이와 같은 방식).
 * 화살표는 인시던트의 통신 방향(출발지: 대상 호스트 → 상대 IP, 목적지: 상대 IP → 대상 호스트)이고 선 굵기는 세션 수다.
 * 그림은 화면 판독기에서 감추고 같은 내용을 .sr-only 표로 둔다(표를 .sr-only 상자로 감싸야 좁은 폭에서 페이지가 넓어지지 않는다).
 */
import { useId } from 'react';
import type { EvidenceView, IncidentQueueItem } from '../../types/api';
import { useContainerWidth } from '../../hooks/useContainerWidth';
import { formatNumber } from '../../utils/format';
import { portText } from '../../utils/incidentExport';
import { IP_SCOPE_LABEL, ipScope, type IpScope } from '../../utils/ipScope';
import { SocBadge } from '../StatusBadge';

export const TOPOLOGY_MAX_PEERS = 5;
export const TOPOLOGY_MAX_PORTS = 3;

const ROW = 52;
const NODE_HEIGHT = 42;
const NODE_PAD = 6;
/** 이 폭보다 좁으면(휴대폰) 상자를 넓히고 주소 글자를 줄여 15자 주소가 말줄임 없이 들어가게 한다 */
const NARROW_WIDTH = 420;
const ARROW = 9;
const MIN_STROKE = 1.5;
const MAX_STROKE = 5.5;
const DEFAULT_STROKE = 2;
const IP_FONT = 12;
const IP_FONT_NARROW = 11;
const SUB_FONT = 11;

interface Peer {
  ip: string;
  count: number;
  scope: IpScope | null;
}

/** 세션 수: 숫자가 아니거나 음수면 0 */
function sessionCount(value: unknown): number {
  const count = Math.max(0, Number(value) || 0);
  return Number.isFinite(count) ? count : 0;
}

/** 선 굵기: 최대 세션 수 대비 비율로 1.5~5.5. 최대가 0이면 기본 2 */
export function peerStrokeWidth(count: number, max: number): number {
  if (max <= 0) return DEFAULT_STROKE;
  return MIN_STROKE + (MAX_STROKE - MIN_STROKE) * Math.min(1, count / max);
}

/** SVG 글자는 스스로 줄지 않으므로 폭을 어림해(한글 1em, 그 밖 0.62em) 넘치면 말줄임한다 */
function charWidth(ch: string, fontSize: number): number {
  return (/[ᄀ-ￜ]/.test(ch) ? 1 : 0.62) * fontSize;
}

function fitsText(text: string, maxWidth: number, fontSize: number): boolean {
  let width = 0;
  for (const ch of text) width += charWidth(ch, fontSize);
  return width <= maxWidth;
}

function fitText(text: string, maxWidth: number, fontSize: number): string {
  if (fitsText(text, maxWidth, fontSize)) return text;
  const limit = maxWidth - charWidth('…', fontSize);
  let out = '';
  let width = 0;
  for (const ch of text) {
    width += charWidth(ch, fontSize);
    if (width > limit) break;
    out += ch;
  }
  return `${out}…`;
}

export function PeerTopologySvg({ incident, evidence }: { incident: IncidentQueueItem; evidence: EvidenceView }) {
  if (!evidence.available) return null;
  const peers: Peer[] = evidence.topPeers
    .flatMap((row) =>
      typeof row.ip === 'string' && row.ip.trim() !== ''
        ? [{ ip: row.ip, count: sessionCount(row.connections), scope: ipScope(row.ip) }]
        : [],
    )
    .slice(0, TOPOLOGY_MAX_PEERS);
  if (peers.length === 0) return null;
  return <Topology incident={incident} peers={peers} ports={evidence.topPorts.slice(0, TOPOLOGY_MAX_PORTS)} />;
}

function Topology({
  incident,
  peers,
  ports,
}: {
  incident: IncidentQueueItem;
  peers: Peer[];
  ports: EvidenceView['topPorts'];
}) {
  const [ref, width] = useContainerWidth<HTMLDivElement>();
  const markerId = `peer-arrow-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;
  const outbound = incident.zeekadRole === 'originator';
  const inbound = incident.zeekadRole === 'responder';
  const direction = outbound ? '대상 호스트 → 상대 IP' : inbound ? '상대 IP → 대상 호스트' : '방향 정보 없음';

  const height = peers.length * ROW;
  const narrow = width < NARROW_WIDTH;
  const ipFont = narrow ? IP_FONT_NARROW : IP_FONT;
  const nodeWidth = Math.round(Math.min(200, Math.max(96, width * (narrow ? 0.45 : 0.44))));
  const peerX = width - nodeWidth - 0.5;
  const hostY = height / 2;
  const textWidth = nodeWidth - NODE_PAD * 2;
  const maxCount = Math.max(...peers.map((p) => p.count));
  const hostName = incident.hostName[0] || '대상 호스트';
  const portBadges = ports.flatMap((row) => {
    const label = portText(row);
    return label ? [{ label, count: sessionCount(row.connections) }] : [];
  });

  return (
    <section className="soc-panel min-w-0 space-y-2 p-3 sm:p-4" aria-label="주요 통신 구조">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <h4 className="soc-subhead">주요 통신 구조</h4>
        <span className="text-[11px] text-slate-500">
          {direction} · 세션이 많은 상대 IP 최대 {TOPOLOGY_MAX_PEERS}개 · 선 굵기는 세션 수
        </span>
      </div>
      <div ref={ref} className="w-full min-w-0 max-w-2xl">
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block max-w-full" aria-hidden="true">
          <defs>
            <marker
              id={markerId}
              viewBox={`0 0 ${ARROW} 10`}
              refX="0"
              refY="5"
              markerWidth={ARROW}
              markerHeight="10"
              markerUnits="userSpaceOnUse"
              orient="auto"
            >
              <path d={`M0 0 L${ARROW} 5 L0 10 Z`} className="fill-cyan-400" />
            </marker>
          </defs>
          {peers.map((peer, index) => {
            const y = ROW / 2 + ROW * index;
            // 선은 보내는 쪽 상자 가장자리에서 받는 쪽 상자 가장자리로. 화살표가 있으면 화살촉 길이만큼 덜 긋는다.
            const from = inbound ? { x: peerX, y } : { x: nodeWidth, y: hostY };
            const to = inbound ? { x: nodeWidth, y: hostY } : { x: peerX, y };
            const length = Math.hypot(to.x - from.x, to.y - from.y) || 1;
            const cut = outbound || inbound ? Math.min(ARROW, length / 2) : 0;
            return (
              <line
                key={`${peer.ip}-${index}`}
                data-peer-line=""
                x1={from.x}
                y1={from.y}
                x2={to.x - ((to.x - from.x) / length) * cut}
                y2={to.y - ((to.y - from.y) / length) * cut}
                strokeWidth={Number(peerStrokeWidth(peer.count, maxCount).toFixed(2))}
                strokeLinecap="butt"
                className="stroke-cyan-400/80"
                markerEnd={outbound || inbound ? `url(#${markerId})` : undefined}
              />
            );
          })}
          <g data-topology-host="">
            <rect
              x="0.5"
              y={hostY - NODE_HEIGHT / 2}
              width={nodeWidth}
              height={NODE_HEIGHT}
              rx="6"
              className="fill-slate-800 stroke-slate-500"
            />
            <text x={0.5 + NODE_PAD} y={hostY - 3} fontSize={ipFont} className="fill-slate-50 font-mono font-semibold">
              <title>{incident.hostIp}</title>
              {fitText(incident.hostIp, textWidth, ipFont)}
            </text>
            <text x={0.5 + NODE_PAD} y={hostY + 12} fontSize={SUB_FONT} className="fill-slate-400">
              <title>{hostName}</title>
              {fitText(hostName, textWidth, SUB_FONT)}
            </text>
          </g>
          {peers.map((peer, index) => {
            const y = ROW / 2 + ROW * index;
            const scopeText = peer.scope ? `${IP_SCOPE_LABEL[peer.scope].text} · ` : '';
            const sub = `${scopeText}세션 ${formatNumber(peer.count)}건`;
            // 좁아서 다 들어가지 않으면 "세션"을 빼고 수를 남긴다(전체 글은 툴팁과 판독기 표에 있다)
            const subShown = fitsText(sub, textWidth, SUB_FONT) ? sub : `${scopeText}${formatNumber(peer.count)}건`;
            return (
              <g key={`${peer.ip}-${index}`} data-topology-peer="">
                <rect
                  x={peerX}
                  y={y - NODE_HEIGHT / 2}
                  width={nodeWidth}
                  height={NODE_HEIGHT}
                  rx="6"
                  className="fill-slate-900 stroke-slate-600"
                />
                <text x={peerX + NODE_PAD} y={y - 3} fontSize={ipFont} className="fill-slate-100 font-mono">
                  <title>{peer.ip}</title>
                  {fitText(peer.ip, textWidth, ipFont)}
                </text>
                <text x={peerX + NODE_PAD} y={y + 12} fontSize={SUB_FONT} className="fill-slate-400">
                  <title>{sub}</title>
                  {fitText(subShown, textWidth, SUB_FONT)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      {portBadges.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5" data-topology-ports="">
          <span className="text-[11px] text-slate-500">주요 포트</span>
          {portBadges.map((port, index) => (
            <SocBadge key={`${port.label}-${index}`}>
              <span className="font-mono">{port.label}</span>
              <span className="text-slate-400">세션 {formatNumber(port.count)}건</span>
            </SocBadge>
          ))}
        </div>
      )}
      <div className="sr-only">
        <table>
          <caption>주요 통신 구조</caption>
          <thead>
            <tr>
              <th scope="col">대상 호스트</th>
              <th scope="col">방향</th>
              <th scope="col">상대 IP</th>
              <th scope="col">세션 수</th>
            </tr>
          </thead>
          <tbody>
            {peers.map((peer, index) => (
              <tr key={`${peer.ip}-${index}`}>
                <td>{incident.hostIp}</td>
                <td>{direction}</td>
                <td>{peer.ip}</td>
                <td>{formatNumber(peer.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
