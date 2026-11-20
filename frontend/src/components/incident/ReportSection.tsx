import { AlertTriangle, FileText } from 'lucide-react';
import type { ReportView } from '../../types/api';
import { formatDateTime, formatNumber, formatSeconds } from '../../utils/format';
import { CodeLabel, SocBadge, VerificationBadge } from '../StatusBadge';
import { FactChips } from './FactChips';

function tokenText(report: ReportView): string {
  const parts: string[] = [];
  if (report.llmInputTokens !== null) parts.push(`입력 ${formatNumber(report.llmInputTokens)}`);
  if (report.llmOutputTokens !== null) parts.push(`출력 ${formatNumber(report.llmOutputTokens)}`);
  if (report.llmThinkingTokens !== null) parts.push(`추론 ${formatNumber(report.llmThinkingTokens)}`);
  return parts.length > 0 ? `${parts.join(' · ')} 토큰` : '-';
}

export function ReportSection({ report }: { report: ReportView }) {
  if (!report.present) {
    return (
      <section className="soc-card p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <FileText className="h-4 w-4 text-slate-400" />
          AI 분석 보고서
        </div>
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
          이 사건에는 AI 분석 보고서가 없습니다.
        </div>
      </section>
    );
  }

  const pseudonymEntries = Object.entries(report.pseudonyms ?? {});

  return (
    <section className="soc-card space-y-5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <FileText className="h-4 w-4 text-slate-400" />
          AI 분석 보고서
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SocBadge tone="neutral">
            <CodeLabel dict="reportKind" value={report.reportKind} />
          </SocBadge>
          <VerificationBadge passed={report.verificationPassed} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <div className="soc-panel p-3">
          <div className="text-slate-400">사용 모델(요청 / 응답)</div>
          <div className="mt-1 text-slate-200">
            <span className="font-mono" data-raw="">
              {report.llmModelRequested ?? '-'}
            </span>{' '}
            /{' '}
            <span className="font-mono" data-raw="">
              {report.llmModelVersion ?? '-'}
            </span>
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">소요 시간 · 토큰</div>
          <div className="mt-1 tabular-nums text-slate-200">
            {formatSeconds(report.llmSeconds)} · {tokenText(report)}
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">보고서 형식 · 입력 형식 · 실행 ID</div>
          <div className="mt-1 break-all text-slate-200">
            <span className="font-mono" data-raw="">
              {report.reportVersion ?? '-'}
            </span>{' '}
            ·{' '}
            <span className="font-mono" data-raw="">
              {report.inputVersion ?? '-'}
            </span>{' '}
            ·{' '}
            <span className="font-mono" data-raw="">
              {report.sourceRun ?? '-'}
            </span>
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">작성 시각</div>
          <div className="mt-1 tabular-nums text-slate-200">{formatDateTime(report.createdAt)}</div>
        </div>
      </div>

      {report.llmError && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
          <span className="font-semibold">AI 작성 오류: </span>
          {report.llmError}
        </div>
      )}

      {report.verificationPassed === false && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs text-amber-200">
          <div className="flex items-center gap-1.5 font-semibold">
            <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
            사실 검증 실패 사유: {report.verificationReason || '-'}
          </div>
          {report.verificationProblems.length > 0 && (
            <ul className="mt-1.5 list-disc space-y-0.5 pl-4">
              {report.verificationProblems.map((prob, idx) => (
                <li key={idx}>{prob}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {report.observationSummary && (
        <div className="soc-panel p-4">
          <h4 className="soc-subhead mb-2">관측 요약</h4>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100">{report.observationSummary}</p>
        </div>
      )}

      {report.claims.length > 0 && (
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-baseline gap-2">
            <h4 className="soc-subhead">확인된 사실</h4>
            <span className="text-[11px] text-slate-500">근거 번호를 누르면 근거 값을 볼 수 있습니다</span>
          </div>
          <div className="space-y-2">
            {report.claims.map((item, idx) => (
              <div key={idx} className="soc-panel p-3.5">
                <p className="text-sm text-slate-100">{item.claim}</p>
                <FactChips facts={item.facts} />
              </div>
            ))}
          </div>
        </div>
      )}

      {report.possibleExplanations.length > 0 && (
        <div className="space-y-2.5">
          <h4 className="soc-subhead">가능한 해석</h4>
          <div className="space-y-2">
            {report.possibleExplanations.map((item, idx) => (
              <div key={idx} className="soc-panel p-3.5">
                <p className="text-sm text-slate-100">{item.explanation}</p>
                {item.attackIds.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {item.attackIds.map((aid) => (
                      <SocBadge key={aid} tone="neutral">
                        <span className="font-mono">{aid}</span>
                      </SocBadge>
                    ))}
                  </div>
                )}
                <FactChips facts={item.facts} />
              </div>
            ))}
          </div>
        </div>
      )}

      {report.attackCandidates.length > 0 && (
        <div className="soc-panel space-y-3 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="soc-subhead">관련 ATT&amp;CK 기법 후보</h4>
            <SocBadge tone="neutral">확정이 아닌 가설</SocBadge>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {report.attackCandidates.map((cand, idx) => (
              <div key={`${cand.attackId}-${idx}`} className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-bold text-slate-100">{cand.attackId}</span>
                  <span className="text-slate-200">{cand.name}</span>
                </div>
                {cand.tactics.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {cand.tactics.map((tac) => (
                      <SocBadge key={tac} tone="muted">
                        <CodeLabel dict="attackTactic" value={tac} />
                      </SocBadge>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {report.sendRecommendation && (
        <div className="soc-panel p-4">
          <div className="mb-2 flex items-center justify-between gap-2">
            <h4 className="soc-subhead">보고서의 알림 권고</h4>
            {report.sendRecommendation.choice && (
              <SocBadge tone="neutral">
                <CodeLabel dict="sendChoice" value={report.sendRecommendation.choice} />
              </SocBadge>
            )}
          </div>
          {report.sendRecommendation.reason && <p className="text-sm text-slate-200">{report.sendRecommendation.reason}</p>}
          <FactChips facts={report.sendRecommendation.facts} />
        </div>
      )}

      {pseudonymEntries.length > 0 && (
        <div className="soc-panel p-4">
          <h4 className="soc-subhead mb-2">보고서 속 가명</h4>
          <div className="flex flex-wrap gap-2">
            {pseudonymEntries.map(([key, ip]) => (
              <div key={key} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-1.5 font-mono text-xs">
                <span className="font-semibold text-slate-100">{key}</span>
                <span className="mx-1.5 text-slate-500">→</span>
                <span className="text-slate-200">{ip}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {(report.limitations.length > 0 || report.followUp.length > 0) && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {report.limitations.length > 0 && (
            <div className="soc-panel p-4">
              <h4 className="soc-subhead mb-2">보고서의 한계</h4>
              <ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">
                {report.limitations.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}
          {report.followUp.length > 0 && (
            <div className="soc-panel p-4">
              <h4 className="soc-subhead mb-2">추가 확인 권고</h4>
              <ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">
                {report.followUp.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
