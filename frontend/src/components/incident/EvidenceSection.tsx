import { AlertTriangle, Database } from 'lucide-react';
import type { AssetNameRecord, EvidenceView, ProtocolLogEntry } from '../../types/api';
import { formatBytes, formatDateTime, formatNumber, formatSessionDuration } from '../../utils/format';
import { lookupLabel, unregisteredTitle, type LabelDictionaryName } from '../../utils/labels';
import { CodeLabel, LookupText } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

/** 증적에 키가 없어 null인 값. 0(관측했는데 0)과 구분해 보여 준다. */
const MISSING_LABEL = '값 없음';

function displayCount(value: number | null | undefined): string {
  return value === null || value === undefined ? MISSING_LABEL : formatNumber(value);
}

function displayBytes(value: number | null | undefined): string {
  return value === null || value === undefined ? MISSING_LABEL : formatBytes(value);
}

/** 사전으로 바꾼 이름표. 원래 키는 툴팁, 미등록 키는 흐린 원문 */
function labelProps(dict: LabelDictionaryName, key: string): { text: string; title?: string; dim: boolean } {
  const label = lookupLabel(dict, key);
  if (!label.known) {
    return { text: label.text, title: unregisteredTitle(label.raw), dim: true };
  }
  return { text: label.text, title: label.raw !== label.text ? label.raw : undefined, dim: false };
}

/** 송신·수신 바이트의 기준(zeek_AD evidence.network.bytes: 연결 방향이 아니라 인시던트 대상 호스트 기준) */
export const BYTES_BASIS_TOOLTIP = '인시던트 대상 호스트 기준';

export function StatCard({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="soc-panel p-3.5" title={title}>
      <div className="text-[11px] font-medium text-slate-400">{label}</div>
      <div
        className={`mt-1 text-xl font-bold tabular-nums ${value === MISSING_LABEL ? 'text-slate-500' : 'text-slate-100'}`}
      >
        {value}
      </div>
    </div>
  );
}

function formatMetricValue(value: unknown): string {
  if (value === null || value === undefined) {
    return MISSING_LABEL;
  }
  if (typeof value === 'number') {
    return formatNumber(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return '없음';
    }
    return value
      .map((item) =>
        item !== null && typeof item === 'object'
          ? Object.values(item as Record<string, unknown>)
              .map((v) => (typeof v === 'number' ? formatNumber(v) : String(v ?? MISSING_LABEL)))
              .join(' · ')
          : String(item),
      )
      .join(', ');
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

function ProtocolLogCard({ entry }: { entry: ProtocolLogEntry }) {
  const metrics = entry.metrics ? Object.entries(entry.metrics) : [];
  const hasActivity = metrics.some(([, v]) =>
    typeof v === 'number' ? v > 0 : Array.isArray(v) ? v.length > 0 : false,
  );
  return (
    <div
      data-testid={`protocol-log-${entry.protocol}`}
      className={`rounded-lg border px-3 py-2 text-xs ${
        hasActivity ? 'border-slate-600 bg-slate-800/60 text-slate-100' : 'border-slate-800 bg-[#090f1d] text-slate-400'
      }`}
    >
      <div className="mb-1 font-semibold uppercase">{entry.protocol}</div>
      {entry.metrics === null ? (
        <div className="text-slate-500">{MISSING_LABEL}</div>
      ) : metrics.length === 0 ? (
        <div className="text-slate-500">하위 수치 없음</div>
      ) : (
        <dl className="space-y-0.5">
          {metrics.map(([key, val]) => {
            const label = labelProps('protocolMetric', key);
            return (
              <div key={key} className="flex justify-between gap-3">
                <dt
                  title={label.title}
                  {...(label.dim ? { 'data-unregistered': '' } : {})}
                  className={label.dim ? 'font-mono text-slate-500' : 'text-slate-400'}
                >
                  {label.text}
                </dt>
                <dd className="break-all text-right font-bold tabular-nums">{formatMetricValue(val)}</dd>
              </div>
            );
          })}
        </dl>
      )}
    </div>
  );
}

function DistributionList({
  title,
  counts,
  tone,
  keyDict,
  softDict = false,
}: {
  title: string;
  counts: Record<string, unknown>;
  tone: 'cyan' | 'purple';
  /** 분포 키를 사전으로 바꿀 때(연결 상태 코드 등). 없으면 키(tcp 등 업계 약어) 그대로 */
  keyDict?: LabelDictionaryName;
  /** true면 사전에 없는 키를 미등록 표시 없이 그대로 보인다(http·dns 같은 프로토콜 이름) */
  softDict?: boolean;
}) {
  const entries = Object.entries(counts ?? {})
    .map(([key, val]) => ({ key, num: Number(val) }))
    .filter((entry) => Number.isFinite(entry.num))
    .sort((a, b) => b.num - a.num);

  const total = entries.reduce((acc, cur) => acc + Math.max(0, cur.num), 0);

  return (
    <div className="soc-panel p-4">
      <h4 className="soc-subhead mb-3">{title}</h4>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-500">관측 항목 없음</p>
      ) : (
        <div className="space-y-2.5">
          {entries.map((entry) => {
            const found = keyDict ? lookupLabel(keyDict, entry.key) : null;
            const label = found && softDict && !found.known ? null : found;
            return (
              <div key={entry.key} className="space-y-1">
                <div className="flex items-center justify-between gap-3 text-xs">
                  {label ? (
                    <LookupText label={label} className="text-slate-200" />
                  ) : (
                    <span className="text-slate-200">{entry.key}</span>
                  )}
                  <span className="soc-num text-slate-400">
                    {formatNumber(entry.num)} · {total > 0 ? ((entry.num / total) * 100).toFixed(1) : '0.0'}%
                  </span>
                </div>
                <SvgProgressBar
                  value={entry.num}
                  max={total > 0 ? total : 1}
                  tone={tone}
                  label={`${title} ${label ? label.text : entry.key}`}
                />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DynamicRecordTable({
  title,
  rows,
  emptyLabel,
}: {
  title: string;
  rows: Array<Record<string, unknown>>;
  emptyLabel: string;
}) {
  if (!rows || rows.length === 0) {
    return (
      <div className="soc-panel p-4">
        <h4 className="soc-subhead mb-2">{title}</h4>
        <p className="text-xs text-slate-500">{emptyLabel}</p>
      </div>
    );
  }

  const columns: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!columns.includes(key)) {
        columns.push(key);
      }
    }
  }

  return (
    <div className="soc-panel overflow-hidden">
      <div className="soc-subhead border-b border-slate-800 px-4 py-2.5">{title}</div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr>
              {columns.map((col) => {
                const label = labelProps('evidenceField', col);
                const numeric = rows.some((r) => typeof r[col] === 'number');
                return (
                  <th
                    key={col}
                    title={label.title}
                    {...(label.dim ? { 'data-unregistered': '' } : {})}
                    className={`soc-th ${numeric ? 'text-right' : ''} ${label.dim ? 'font-mono text-slate-500' : ''}`}
                  >
                    {label.text}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30">
                {columns.map((col) => {
                  const val = row[col];
                  if (val === null || val === undefined) {
                    return (
                      <td key={col} className="soc-td text-xs text-slate-500">
                        -
                      </td>
                    );
                  }
                  if (typeof val === 'number') {
                    return (
                      <td key={col} className="soc-td soc-num text-xs">
                        {col === 'port' ? String(val) : formatNumber(val)}
                      </td>
                    );
                  }
                  if (typeof val === 'object') {
                    // 상위 상대 IP·포트 표에 중첩 값이 오면 원문 그대로 보인다(주요 세션은 SessionTable이 필드별 열로 푼다).
                    return (
                      <td key={col} className="soc-td whitespace-nowrap font-mono text-xs" data-raw="">
                        {JSON.stringify(val)}
                      </td>
                    );
                  }
                  return (
                    <td key={col} className="soc-td whitespace-nowrap font-mono text-xs">
                      {String(val)}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ───────────── 주요 세션(필드별 열, T19) ───────────── */

function obj(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function str(value: unknown): string | null {
  return value === null || value === undefined || value === '' ? null : String(value);
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** IP:포트(IPv6는 [주소]:포트) */
function endpoint(ip: string | null, port: number | null): string {
  if (!ip) return '-';
  const host = ip.includes(':') ? `[${ip}]` : ip;
  return port === null ? host : `${host}:${port}`;
}

export interface SessionRow {
  uid: string | null;
  connState: string | null;
  start: string | null;
  duration: number | null;
  sourceIp: string | null;
  sourcePort: number | null;
  sourceBytes: number | null;
  destinationIp: string | null;
  destinationPort: number | null;
  destinationBytes: number | null;
  protocol: string | null;
  transport: string | null;
}

/** zeek_AD representative_connections 항목(zeek·event·source·destination·network)을 필드별 값으로 푼다. */
export function toSessionRow(raw: Record<string, unknown>): SessionRow {
  const zeek = obj(raw.zeek);
  const event = obj(raw.event);
  const source = obj(raw.source);
  const destination = obj(raw.destination);
  const network = obj(raw.network);
  return {
    uid: str(zeek.uid),
    connState: str(zeek.conn_state),
    start: str(event.start),
    duration: num(event.duration),
    sourceIp: str(source.ip),
    sourcePort: num(source.port),
    sourceBytes: num(source.bytes),
    destinationIp: str(destination.ip),
    destinationPort: num(destination.port),
    destinationBytes: num(destination.bytes),
    protocol: str(network.protocol),
    transport: str(network.transport),
  };
}

/**
 * 주요 세션 표. 바이트는 세션 기준(출발지·목적지)이라 증적 요약의 송신·수신 바이트(대상 호스트 기준)와 다르다(M2).
 * 세션 상태는 사전 표시 + 원 코드 툴팁, Zeek 세션 ID는 행 툴팁. VIEWER 마스킹은 서버가 하므로 받은 값을 그대로 쓴다.
 */
export function SessionTable({ rows }: { rows: Array<Record<string, unknown>> }) {
  const list = rows.slice(0, 10).map(toSessionRow);
  return (
    <div className="soc-panel overflow-hidden">
      <div className="soc-subhead border-b border-slate-800 px-4 py-2.5">주요 세션 (최대 10건)</div>
      {list.length === 0 ? (
        <p className="px-4 py-3 text-xs text-slate-500">주요 세션 정보 없음</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr>
                <th scope="col" className="soc-th-compact">시작 시각</th>
                <th scope="col" className="soc-th-compact">출발지 IP:포트</th>
                <th scope="col" className="soc-th-compact">목적지 IP:포트</th>
                <th scope="col" className="soc-th-compact">서비스 · 전송 계층</th>
                <th scope="col" className="soc-th-compact text-right">지속 시간</th>
                <th scope="col" className="soc-th-compact text-right">출발지 바이트</th>
                <th scope="col" className="soc-th-compact text-right">목적지 바이트</th>
                <th scope="col" className="soc-th-compact">세션 상태</th>
              </tr>
            </thead>
            <tbody>
              {list.map((row, idx) => {
                const service = row.protocol ? lookupLabel('serviceProtocol', row.protocol) : null;
                return (
                  <tr
                    key={`${row.uid ?? 'x'}-${idx}`}
                    className="hover:bg-slate-800/30"
                    title={row.uid ? `Zeek 세션 ID ${row.uid}` : undefined}
                  >
                    <td className="soc-td-compact whitespace-nowrap tabular-nums text-slate-200">{formatDateTime(row.start)}</td>
                    <td className="soc-td-compact whitespace-nowrap font-mono text-slate-100">
                      {endpoint(row.sourceIp, row.sourcePort)}
                    </td>
                    <td className="soc-td-compact whitespace-nowrap font-mono text-slate-100">
                      {endpoint(row.destinationIp, row.destinationPort)}
                    </td>
                    <td className="soc-td-compact whitespace-nowrap text-slate-300">
                      {service ? (service.known ? service.text : row.protocol) : '-'}
                      {row.transport && <span className="text-slate-500"> · {row.transport}</span>}
                    </td>
                    <td className="soc-td-compact soc-num text-slate-200">{formatSessionDuration(row.duration)}</td>
                    <td className="soc-td-compact soc-num text-slate-200">
                      {row.sourceBytes === null ? '-' : formatBytes(row.sourceBytes)}
                    </td>
                    <td className="soc-td-compact soc-num text-slate-200">
                      {row.destinationBytes === null ? '-' : formatBytes(row.destinationBytes)}
                    </td>
                    <td className="soc-td-compact whitespace-nowrap text-slate-300">
                      {row.connState ? <CodeLabel dict="connState" value={row.connState} /> : '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ───────────── 관측 계정(이름·종류·마지막 관측) ───────────── */

interface AccountRow {
  name: string;
  kind: string | null;
  fallbackKind: string | null;
  lastSeen: string | null;
}

function toAccountRows(records: AssetNameRecord[]): AccountRow[] {
  const rows: AccountRow[] = [];
  for (const rec of records) {
    const extra = rec.extraAttributes ?? {};
    const name = str(extra.zeekad_name);
    const lastSeen = str(extra.last_seen);
    if (name) {
      rows.push({ name, kind: str(extra.zeekad_name_kind), fallbackKind: null, lastSeen });
      continue;
    }
    if (rec.kerberosUser) rows.push({ name: rec.kerberosUser, kind: null, fallbackKind: 'Kerberos', lastSeen });
    if (rec.ntlmUser) rows.push({ name: rec.ntlmUser, kind: null, fallbackKind: 'NTLM', lastSeen });
  }
  return rows;
}

/** Kerberos·NTLM 관측 계정: 계정 이름·종류·마지막 관측만 보인다(출처 로그·관측 횟수 등은 화면에 두지 않는다). */
export function ObservedAccounts({ assetNames }: { assetNames: AssetNameRecord[] }) {
  const rows = toAccountRows(assetNames);
  return (
    <div className="soc-panel overflow-hidden">
      <div className="soc-subhead border-b border-slate-800 px-4 py-2.5">관측 계정</div>
      {rows.length === 0 ? (
        <p className="px-4 py-3 text-xs text-slate-500">관측된 Kerberos·NTLM 계정 이름이 없습니다.</p>
      ) : (
        // T26: 패널의 overflow-hidden(둥근 모서리)은 두고, 긴 계정 이름이 잘리지 않게 표만 가로 스크롤 상자로 감싼다.
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr>
                <th scope="col" className="soc-th-compact">계정 이름</th>
                <th scope="col" className="soc-th-compact">종류</th>
                <th scope="col" className="soc-th-compact">마지막 관측</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, idx) => (
                <tr key={`${row.name}-${idx}`}>
                  <td className="soc-td-compact font-mono text-slate-100">{row.name}</td>
                  <td className="soc-td-compact text-slate-300">
                    {row.kind ? <CodeLabel dict="assetNameKind" value={row.kind} /> : (row.fallbackKind ?? '-')}
                  </td>
                  <td className="soc-td-compact tabular-nums text-slate-300">{formatDateTime(row.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ───────────── 증적 탭 ───────────── */

export function EvidenceSection({
  evidence,
  assetNames = [],
}: {
  evidence: EvidenceView;
  assetNames?: AssetNameRecord[];
}) {
  const additionalEntries = Object.entries(evidence.additionalFields ?? {});

  return (
    <div className="space-y-4">
      {!evidence.available ? (
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <span>{evidence.statusMessage || '상세 증적을 불러오지 못했습니다. 기본 정보만 표시합니다.'}</span>
        </div>
      ) : (
        <>
          <h3 className="soc-subhead">증적 요약</h3>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
            <StatCard label="총 세션 수" value={displayCount(evidence.connectionCount)} />
            <StatCard label="송신 바이트" title={BYTES_BASIS_TOOLTIP} value={displayBytes(evidence.bytesSent)} />
            <StatCard label="수신 바이트" title={BYTES_BASIS_TOOLTIP} value={displayBytes(evidence.bytesReceived)} />
            <StatCard label="고유 상대 IP 수" value={displayCount(evidence.uniquePeers)} />
            <StatCard label="고유 목적지 포트 수" value={displayCount(evidence.uniquePorts)} />
            <StatCard label="페이로드 바이트가 부푼 세션 수" value={displayCount(evidence.payloadBytesInflated)} />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <DistributionList title="전송 계층 분포" counts={evidence.transportCounts} tone="cyan" />
            <DistributionList
              title="서비스 프로토콜 분포"
              counts={evidence.serviceProtocolCounts}
              tone="cyan"
              keyDict="serviceProtocol"
              softDict
            />
            <DistributionList title="세션 상태 분포" counts={evidence.connStateCounts} tone="purple" keyDict="connState" />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <DynamicRecordTable title="많이 통신한 상대 IP" rows={evidence.topPeers} emptyLabel="상대 IP 정보 없음" />
            <DynamicRecordTable title="많이 쓴 목적지 포트" rows={evidence.topPorts} emptyLabel="목적지 포트 정보 없음" />
          </div>

          <SessionTable rows={evidence.representativeConnections} />

          {evidence.protocolLogs.length > 0 && (
            <div>
              <h4 className="soc-subhead mb-2">프로토콜별 기록 수</h4>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {evidence.protocolLogs.map((entry) => (
                  <ProtocolLogCard key={entry.protocol} entry={entry} />
                ))}
              </div>
            </div>
          )}

          {evidence.limits.length > 0 && (
            <div className="soc-panel p-4">
              <h4 className="soc-subhead mb-2">증적의 한계</h4>
              <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
                {evidence.limits.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      <ObservedAccounts assetNames={assetNames} />

      {evidence.available && additionalEntries.length > 0 && (
        <details className="soc-panel p-4">
          <summary className="soc-subhead flex cursor-pointer items-center gap-1.5">
            <Database className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            원본 증적 데이터
            <span className="text-[11px] font-normal text-slate-500">기본으로 접혀 있습니다</span>
          </summary>
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {additionalEntries.map(([key, value]) => (
              <div key={key} className="rounded border border-slate-800 bg-[#090f1d] p-2.5 text-xs">
                <div className="font-mono font-semibold text-slate-400" data-raw="">
                  {key}
                </div>
                <div className="mt-1 break-all font-mono text-slate-200" data-raw="">
                  {typeof value === 'object' ? JSON.stringify(value) : String(value ?? '-')}
                </div>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
