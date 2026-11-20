import { AlertTriangle, Database, Network } from 'lucide-react';
import type { EvidenceView, ProtocolLogEntry } from '../../types/api';
import { formatBytes, formatNumber } from '../../utils/format';
import { SocBadge } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

/** 근거에 키가 없어 null인 값. 0(관측했는데 0)과 구분해 보여 준다. */
const MISSING_LABEL = '값 없음';

function displayCount(value: number | null | undefined): string {
  return value === null || value === undefined ? MISSING_LABEL : formatNumber(value);
}

function displayBytes(value: number | null | undefined): string {
  return value === null || value === undefined ? MISSING_LABEL : formatBytes(value);
}

function StatCard({ label, value, accent = false }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="soc-panel p-3.5">
      <div className="text-[11px] font-medium text-slate-400">{label}</div>
      <div
        className={`mt-1 font-mono text-xl font-bold tabular-nums ${
          value === MISSING_LABEL ? 'text-slate-500' : accent ? 'text-cyan-300' : 'text-slate-100'
        }`}
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
      className={`rounded-lg border px-3 py-2 font-mono text-xs ${
        hasActivity
          ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
          : 'border-slate-800 bg-[#090f1d] text-slate-400'
      }`}
    >
      <div className="mb-1 font-semibold">{entry.protocol}</div>
      {entry.metrics === null ? (
        <div className="text-slate-500">{MISSING_LABEL}</div>
      ) : metrics.length === 0 ? (
        <div className="text-slate-500">하위 수치 없음</div>
      ) : (
        <dl className="space-y-0.5">
          {metrics.map(([key, val]) => (
            <div key={key} className="flex justify-between gap-3">
              <dt className="text-slate-400">{key}</dt>
              <dd className="break-all text-right font-bold tabular-nums">{formatMetricValue(val)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function DistributionList({
  title,
  counts,
  tone,
}: {
  title: string;
  counts: Record<string, unknown>;
  tone: 'cyan' | 'purple';
}) {
  const entries = Object.entries(counts ?? {})
    .map(([key, val]) => ({ key, num: Number(val) }))
    .filter((entry) => Number.isFinite(entry.num))
    .sort((a, b) => b.num - a.num);

  const total = entries.reduce((acc, cur) => acc + Math.max(0, cur.num), 0);

  return (
    <div className="soc-panel p-4">
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-300">{title}</h4>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-500">관측 항목 없음</p>
      ) : (
        <div className="space-y-2.5">
          {entries.map((entry) => (
            <div key={entry.key} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-slate-200">{entry.key}</span>
                <span className="font-mono tabular-nums text-slate-400">
                  {formatNumber(entry.num)} ({total > 0 ? ((entry.num / total) * 100).toFixed(1) : '0.0'}%)
                </span>
              </div>
              <SvgProgressBar
                value={entry.num}
                max={total > 0 ? total : 1}
                tone={tone}
                label={`${title} ${entry.key}`}
              />
            </div>
          ))}
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
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-300">{title}</h4>
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
      <div className="border-b border-slate-800 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
        {title}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col} className="soc-th font-mono">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30">
                {columns.map((col) => {
                  const val = row[col];
                  const formatted =
                    val === null || val === undefined
                      ? '-'
                      : typeof val === 'object'
                        ? JSON.stringify(val)
                        : String(val);
                  return (
                    <td key={col} className="soc-td whitespace-nowrap font-mono text-xs tabular-nums">
                      {formatted}
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
          <Network className="h-4 w-4 text-cyan-400" />
          근거 요약 (evidence.v1)
        </div>
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <span>{evidence.statusMessage || '근거 API 연결 불가(DB 뷰 정보만 표시)'}</span>
        </div>
      </section>
    );
  }

  const additionalEntries = Object.entries(evidence.additionalFields ?? {});

  return (
    <section className="soc-card space-y-5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Network className="h-4 w-4 text-cyan-400" />
          근거 요약 (evidence.v1)
        </div>
        {evidence.statusMessage && <SocBadge tone="cyan">{evidence.statusMessage}</SocBadge>}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatCard label="총 연결 수" value={displayCount(evidence.connectionCount)} accent />
        <StatCard label="자산 송신 바이트" value={displayBytes(evidence.bytesSent)} />
        <StatCard label="자산 수신 바이트" value={displayBytes(evidence.bytesReceived)} />
        <StatCard label="고유 상대 IP 수" value={displayCount(evidence.uniquePeers)} />
        <StatCard label="고유 목적지 포트 수" value={displayCount(evidence.uniquePorts)} />
        <StatCard
          label="페이로드 바이트가 부푼 연결 수"
          value={displayCount(evidence.payloadBytesInflated)}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <DistributionList title="전송 계층 분포" counts={evidence.transportCounts} tone="cyan" />
        <DistributionList title="서비스 프로토콜 분포" counts={evidence.serviceProtocolCounts} tone="cyan" />
        <DistributionList title="연결 상태 (conn_state) 분포" counts={evidence.connStateCounts} tone="purple" />
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
          프로토콜 로그 수치
        </h4>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {evidence.protocolLogs.map((entry) => (
            <ProtocolLogCard key={entry.protocol} entry={entry} />
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DynamicRecordTable
          title="상위 상대 IP (Top Peers)"
          rows={evidence.topPeers}
          emptyLabel="상위 상대 IP 정보 없음"
        />
        <DynamicRecordTable
          title="상위 포트 (Top Ports)"
          rows={evidence.topPorts}
          emptyLabel="상위 포트 정보 없음"
        />
      </div>

      <DynamicRecordTable
        title="대표 연결 (최대 10건)"
        rows={evidence.representativeConnections.slice(0, 10)}
        emptyLabel="대표 연결 정보 없음"
      />

      {evidence.limits.length > 0 && (
        <div className="soc-panel p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-amber-300">
            관측 한계 (Limitations)
          </h4>
          <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
            {evidence.limits.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {additionalEntries.length > 0 && (
        <div className="soc-panel p-4">
          <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <Database className="h-3.5 w-3.5 text-slate-400" />
            추가 근거 필드
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {additionalEntries.map(([key, value]) => (
              <div key={key} className="rounded border border-slate-800 bg-[#090f1d] p-2.5 text-xs">
                <div className="font-mono font-semibold text-slate-400">{key}</div>
                <div className="mt-1 break-all font-mono text-slate-200">
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
