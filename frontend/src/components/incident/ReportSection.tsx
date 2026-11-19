import { AlertTriangle, CheckCircle2, FileText, ShieldAlert } from 'lucide-react';
import type { ReportView } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { SocBadge } from '../StatusBadge';
import { FactChips } from './FactChips';

export function ReportSection({ report }: { report: ReportView }) {
  if (!report.present) {
    return (
      <section className="soc-card p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <FileText className="h-4 w-4 text-cyan-400" />
          단계 5 사건 보고서
        </div>
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">보고서 없음</div>
      </section>
    );
  }

  const pseudonymEntries = Object.entries(report.pseudonyms ?? {});

  return (
    <section className="soc-card space-y-5 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <FileText className="h-4 w-4 text-cyan-400" />
          단계 5 사건 보고서
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SocBadge tone={report.reportKind === 'llm' ? 'cyan' : 'slate'}>
            {report.reportKind ?? '-'}
          </SocBadge>
          {report.reportVersion && <SocBadge tone="slate">{report.reportVersion}</SocBadge>}
          {report.verificationPassed === true && (
            <SocBadge tone="emerald">
              <CheckCircle2 className="h-3 w-3" />
              검증 통과
            </SocBadge>
          )}
          {report.verificationPassed === false && (
            <SocBadge tone="rose">
              <AlertTriangle className="h-3 w-3" />
              검증 실패
            </SocBadge>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <div className="soc-panel p-3">
          <div className="text-slate-400">요청 / 응답 모델</div>
          <div className="mt-1 font-mono text-slate-200">
            {report.llmModelRequested ?? '-'} / {report.llmModelVersion ?? '-'}
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">소요 시간 · 토큰</div>
          <div className="mt-1 font-mono tabular-nums text-slate-200">
            {report.llmSeconds !== null ? `${report.llmSeconds.toFixed(2)}s` : '-'} · in{' '}
            {report.llmInputTokens ?? '-'} / out {report.llmOutputTokens ?? '-'}
            {report.llmThinkingTokens !== null ? ` / think ${report.llmThinkingTokens}` : ''}
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">입력 버전 · 실행</div>
          <div className="mt-1 font-mono text-slate-200">
            {report.inputVersion ?? '-'} · {report.sourceRun ?? '-'}
          </div>
        </div>
        <div className="soc-panel p-3">
          <div className="text-slate-400">생성 시각</div>
          <div className="mt-1 font-mono tabular-nums text-slate-200">
            {formatDateTime(report.createdAt)}
          </div>
        </div>
      </div>

      {report.llmError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
          <span className="font-semibold">LLM 오류: </span>
          {report.llmError}
        </div>
      )}

      {report.verificationPassed === false && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-200">
          <div className="font-semibold">검증 실패 사유: {report.verificationReason || '-'}</div>
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
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            관측 요약 (Observation Summary)
          </h4>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100">
            {report.observationSummary}
          </p>
        </div>
      )}

      {report.claims.length > 0 && (
        <div className="space-y-2.5">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            주장 목록 (Claims · F* 클릭 시 근거 사실 펼침)
          </h4>
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
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            가능한 설명 (Possible Explanations)
          </h4>
          <div className="space-y-2">
            {report.possibleExplanations.map((item, idx) => (
              <div key={idx} className="soc-panel p-3.5">
                <p className="text-sm text-slate-100">{item.explanation}</p>
                {item.attackIds.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {item.attackIds.map((aid) => (
                      <SocBadge key={aid} tone="purple">
                        {aid}
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
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              ATT&amp;CK 후보 (MITRE ATT&amp;CK Candidates)
            </h4>
            <SocBadge tone="amber">
              <ShieldAlert className="h-3 w-3" />
              공격 정답이 아닌 가설
            </SocBadge>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {report.attackCandidates.map((cand, idx) => (
              <div key={`${cand.attackId}-${idx}`} className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-bold text-purple-300">{cand.attackId}</span>
                  <span className="text-slate-200">{cand.name}</span>
                </div>
                {cand.tactics.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {cand.tactics.map((tac) => (
                      <SocBadge key={tac} tone="slate">
                        {tac}
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
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              보고서 전송 권고 (Send Recommendation)
            </h4>
            {report.sendRecommendation.choice && (
              <SocBadge tone="cyan">{report.sendRecommendation.choice}</SocBadge>
            )}
          </div>
          {report.sendRecommendation.reason && (
            <p className="text-sm text-slate-200">{report.sendRecommendation.reason}</p>
          )}
          <FactChips facts={report.sendRecommendation.facts} />
        </div>
      )}

      {pseudonymEntries.length > 0 && (
        <div className="soc-panel p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            가명표 (Pseudonyms)
          </h4>
          <div className="flex flex-wrap gap-2">
            {pseudonymEntries.map(([key, ip]) => (
              <div
                key={key}
                className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-1.5 font-mono text-xs"
              >
                <span className="font-semibold text-cyan-300">{key}</span>
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
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-amber-300">
                보고서 한계
              </h4>
              <ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">
                {report.limitations.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}
          {report.followUp.length > 0 && (
            <div className="soc-panel p-4">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-cyan-300">
                추가 확인 항목 (Follow-up)
              </h4>
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
