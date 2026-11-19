import { AlertTriangle, Database, Network } from 'lucide-react';
import type { EvidenceView } from '../../types/api';
import { formatBytes, formatNumber } from '../../utils/format';
import { SocBadge } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

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
        <div className="soc-panel p-3.5">
          <div className="text-[11px] font-medium text-slate-400">총 연결 수</div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-cyan-300">
            {formatNumber(evidence.connectionCount)}
          </div>
        </div>
        <div className="soc-panel p-3.5">
          <div className="text-[11px] font-medium text-slate-400">송신 바이트 (orig_bytes)</div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-slate-100">
            {formatBytes(evidence.origBytes)}
          </div>
        </div>
        <div className="soc-panel p-3.5">
          <div className="text-[11px] font-medium text-slate-400">수신 바이트 (resp_bytes)</div>
          <div className="mt-1 font-mono text-xl font-bold tabular-nums text-slate-100">
            {formatBytes(evidence.respBytes)}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <DistributionList title="전송 계층 / 프로토콜 분포" counts={evidence.transportCounts} tone="cyan" />
        <DistributionList title="연결 상태 (conn_state) 분포" counts={evidence.connStateCounts} tone="purple" />
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
          프로토콜 로그 수치
        </h4>
        <div className="flex flex-wrap gap-2">
          {evidence.protocolCounts.map((entry) => {
            const countNum = Number(entry.count);
            const hasActivity = Number.isFinite(countNum) && countNum > 0;
            return (
              <div
                key={entry.protocol}
                className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-xs ${
                  hasActivity
                    ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
                    : 'border-slate-800 bg-[#090f1d] text-slate-400'
                }`}
              >
                <span>{entry.protocol}</span>
                <span className="font-bold tabular-nums">{String(entry.count ?? 0)}</span>
              </div>
            );
          })}
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

      {evidence.limitations.length > 0 && (
        <div className="soc-panel p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-amber-300">
            관측 한계 (Limitations)
          </h4>
          <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
            {evidence.limitations.map((item, idx) => (
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
