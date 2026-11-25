import type { IncidentDetailView } from '../../types/api';
import { formatBytes, formatDuration, formatNumber } from '../../utils/format';
import { portText } from '../../utils/incidentExport';
import { isIpText } from '../../utils/ipScope';
import { labelText } from '../../utils/labels';
import { SvgProgressBar } from '../SvgProgressBar';
import { IpActions, ModelPivot } from './InvestigationLinks';
import { BYTES_BASIS_TOOLTIP } from './EvidenceSection';
import {
  ReportAttack,
  ReportClaims,
  ReportExplanations,
  ReportFollowUp,
  ReportLimitations,
  ReportVerificationProblems,
} from './ReportSection';

function first(rows: Array<Record<string, unknown>>): Record<string, unknown> | null {
  return rows.length > 0 ? rows[0] : null;
}

function text(value: unknown): string | null {
  return value === null || value === undefined || value === '' ? null : String(value);
}

/** 주요 상대 IP(상위 1건) */
export function topPeerText(rows: Array<Record<string, unknown>>): string | null {
  return text(first(rows)?.ip);
}

/** 주요 포트(상위 1건): "80/tcp" */
export function topPortText(rows: Array<Record<string, unknown>>): string | null {
  return portText(first(rows));
}

function KeyNumber({
  label,
  value,
  sub,
  title,
  mono = false,
  actions,
}: {
  label: string;
  value: string;
  sub?: string;
  title?: string;
  mono?: boolean;
  /** 값 아래 표지·버튼 줄(T44 상대 IP 대역 표지·복사) */
  actions?: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5" title={title}>
      <div className="text-[11px] text-slate-400">{label}</div>
      <div className={`mt-0.5 truncate text-base font-bold tabular-nums text-slate-100 ${mono ? 'font-mono' : ''}`}>{value}</div>
      {actions && <div className="-ml-1 mt-0.5 flex items-center">{actions}</div>}
      {sub && <div className="text-[11px] tabular-nums text-slate-500">{sub}</div>}
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-slate-100">{children}</h3>;
}

/**
 * 요약 탭(T19): "무슨 일인가 → 왜 의심스러운가 → 다음에 할 일".
 * 리포트가 없으면 증적 정형 칸으로 만든 자동 요약 한 줄을 보인다. 빈 칸은 한 줄로만 보인다(V-13).
 */
export function SummaryTab({ detail }: { detail: IncidentDetailView }) {
  const { incident, evidence, report } = detail;
  const sessions = evidence.available && evidence.connectionCount !== null ? evidence.connectionCount : incident.connectionCount;
  const peer = evidence.available ? topPeerText(evidence.topPeers) : null;
  const port = evidence.available ? topPortText(evidence.topPorts) : null;
  const peerCount = evidence.available ? first(evidence.topPeers)?.connections : null;
  const portCount = evidence.available ? first(evidence.topPorts)?.connections : null;
  const bytes =
    evidence.available && (evidence.bytesSent !== null || evidence.bytesReceived !== null)
      ? `${evidence.bytesSent === null ? '-' : formatBytes(evidence.bytesSent)} / ${
          evidence.bytesReceived === null ? '-' : formatBytes(evidence.bytesReceived)
        }`
      : '-';

  const autoSummary = [
    `${labelText('hostRole', incident.zeekadRole)} 호스트 ${incident.hostIp}에서 ${formatDuration(incident.eventStart, incident.eventEnd)} 동안 세션 ${formatNumber(sessions)}건이 관측되었습니다.`,
    peer ? `주요 상대 IP ${peer}` : null,
    port ? `주요 포트 ${port}` : null,
  ]
    .filter(Boolean)
    .join(' ');

  const hasWhy =
    report.present &&
    (report.claims.length > 0 || report.possibleExplanations.length > 0 || report.attackCandidates.length > 0);
  const hasNext = report.present && (report.followUp.length > 0 || report.limitations.length > 0);

  return (
    <div className="space-y-6">
      <section aria-labelledby="summary-what" className="space-y-3">
        <SectionTitle>
          <span id="summary-what">무슨 일인가</span>
        </SectionTitle>
        {report.present && report.observationSummary ? (
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100">{report.observationSummary}</p>
        ) : (
          <p className="text-sm text-slate-200">
            <span className="mr-1.5 rounded border border-slate-700 px-1 text-[11px] text-slate-400">자동 요약</span>
            {autoSummary}
          </p>
        )}
        {report.present && <ReportVerificationProblems report={report} />}
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
          <KeyNumber label="세션 수" value={formatNumber(sessions)} />
          <KeyNumber label="송신 / 수신 바이트" value={bytes} title={BYTES_BASIS_TOOLTIP} />
          <KeyNumber
            label="주요 상대 IP"
            value={peer ?? '-'}
            actions={isIpText(peer) ? <IpActions ip={peer} /> : undefined}
            sub={typeof peerCount === 'number' ? `세션 ${formatNumber(peerCount)}건` : undefined}
            mono
          />
          <KeyNumber
            label="주요 포트"
            value={port ?? '-'}
            sub={typeof portCount === 'number' ? `세션 ${formatNumber(portCount)}건` : undefined}
            mono
          />
        </div>
      </section>

      <section aria-labelledby="summary-why" className="space-y-3 border-t border-slate-800 pt-4">
        <SectionTitle>
          <span id="summary-why">왜 의심스러운가</span>
        </SectionTitle>
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-baseline gap-2">
            <h4 className="soc-subhead">모델별 탐지 윈도우</h4>
            <span className="text-[11px] text-slate-500">기준값을 넘은 윈도우 수 / 전체 윈도우 수</span>
          </div>
          {detail.modelScores.length === 0 ? (
            <p className="text-xs text-slate-400">모델별 탐지 윈도우 정보가 없습니다.</p>
          ) : (
            <ul className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2">
              {detail.modelScores.map((score) => {
                const cand = score.candidateWindows ?? 0;
                const total = score.windows ?? 0;
                const ratioLabel = score.windowRatioLabel || `${cand} / ${total}`;
                return (
                  <li key={score.zeekadModel} className="space-y-1">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <ModelPivot id={score.zeekadModel} />
                      <span className="font-bold tabular-nums text-slate-100">{ratioLabel}</span>
                    </div>
                    <SvgProgressBar
                      value={cand}
                      max={total > 0 ? total : 1}
                      tone="cyan"
                      label={`${labelText('detectionModel', score.zeekadModel)} 탐지 윈도우 ${ratioLabel}`}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        {hasWhy ? (
          <>
            <ReportClaims report={report} />
            <ReportExplanations report={report} />
            <ReportAttack report={report} />
          </>
        ) : (
          <p className="text-xs text-slate-400">
            {report.present ? '리포트에 확인된 사실·해석이 없습니다.' : 'AI 분석 리포트가 없어 탐지 모델 결과만 있습니다.'}
          </p>
        )}
      </section>

      <section aria-labelledby="summary-next" className="space-y-3 border-t border-slate-800 pt-4">
        <SectionTitle>
          <span id="summary-next">다음에 할 일</span>
        </SectionTitle>
        {hasNext ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <ReportFollowUp report={report} idPrefix="summary-tab" />
            <ReportLimitations report={report} />
          </div>
        ) : (
          <p className="text-xs text-slate-400">리포트에 추가 확인 권고가 없습니다. 증적 탭에서 세션과 상대 IP를 확인하세요.</p>
        )}
      </section>
    </div>
  );
}
