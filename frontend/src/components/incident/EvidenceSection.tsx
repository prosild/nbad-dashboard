import { AlertTriangle, Database, Network } from 'lucide-react';
import type { EvidenceView, ProtocolLogEntry } from '../../types/api';
import { formatBytes, formatNumber } from '../../utils/format';
import { lookupLabel, unregisteredTitle, type LabelDictionaryName } from '../../utils/labels';
import { LookupText } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

/** 근거에 키가 없어 null인 값. 0(관측했는데 0)과 구분해 보여 준다. */
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

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="soc-panel p-3.5">
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
                    // 중첩 근거(대표 연결의 zeek·event·source 등)는 원문 그대로 보인다. 필드별 열 배치는 T19 범위다.
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

export function EvidenceSection({ evidence }: { evidence: EvidenceView }) {
  if (!evidence.available) {
    return (
      <section className="soc-card p-5">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Network className="h-4 w-4 text-slate-400" />
          근거 요약
        </div>
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <span>{evidence.statusMessage || '상세 근거를 불러오지 못했습니다. 기본 정보만 표시합니다.'}</span>
        </div>
      </section>
    );
  }

  const additionalEntries = Object.entries(evidence.additionalFields ?? {});

  return (
    <section className="soc-card space-y-5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Network className="h-4 w-4 text-slate-400" />
          근거 요약
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatCard label="총 연결 수" value={displayCount(evidence.connectionCount)} />
        <StatCard label="자산 송신 바이트" value={displayBytes(evidence.bytesSent)} />
        <StatCard label="자산 수신 바이트" value={displayBytes(evidence.bytesReceived)} />
        <StatCard label="고유 상대 IP 수" value={displayCount(evidence.uniquePeers)} />
        <StatCard label="고유 목적지 포트 수" value={displayCount(evidence.uniquePorts)} />
        <StatCard label="페이로드 바이트가 부푼 연결 수" value={displayCount(evidence.payloadBytesInflated)} />
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
        <DistributionList title="연결 상태 분포" counts={evidence.connStateCounts} tone="purple" keyDict="connState" />
      </div>

      <div>
        <h4 className="soc-subhead mb-2">프로토콜별 기록 수</h4>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {evidence.protocolLogs.map((entry) => (
            <ProtocolLogCard key={entry.protocol} entry={entry} />
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DynamicRecordTable title="많이 통신한 상대 IP" rows={evidence.topPeers} emptyLabel="상대 IP 정보 없음" />
        <DynamicRecordTable title="많이 쓴 목적지 포트" rows={evidence.topPorts} emptyLabel="목적지 포트 정보 없음" />
      </div>

      <DynamicRecordTable
        title="대표 연결 (최대 10건)"
        rows={evidence.representativeConnections.slice(0, 10)}
        emptyLabel="대표 연결 정보 없음"
      />

      {evidence.limits.length > 0 && (
        <div className="soc-panel p-4">
          <h4 className="soc-subhead mb-2">근거의 한계</h4>
          <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
            {evidence.limits.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {additionalEntries.length > 0 && (
        <div className="soc-panel p-4">
          <div className="soc-subhead mb-2 flex items-center gap-1.5">
            <Database className="h-3.5 w-3.5 text-slate-400" />
            원본 근거 데이터
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
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
        </div>
      )}
    </section>
  );
}
