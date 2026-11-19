import { AlertTriangle, Cpu, GitCompare, Scale, Sparkles } from 'lucide-react';
import type { SendDecisionView } from '../../types/api';
import { decisionChoiceLabel, formatPercent } from '../../utils/format';
import { SocBadge } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

export function SendDecisionSection({ sendDecision }: { sendDecision: SendDecisionView }) {
  if (!sendDecision.present) {
    return (
      <section className="soc-card p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <GitCompare className="h-4 w-4 text-cyan-400" />
          3자 전송 판단 비교
        </div>
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">전송 판단 없음</div>
      </section>
    );
  }

  const probEntries = Object.entries(sendDecision.decisionModelProbabilities ?? {}).sort(
    (a, b) => b[1] - a[1],
  );

  return (
    <section className="soc-card space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <GitCompare className="h-4 w-4 text-cyan-400" />
          3자 전송 판단 비교
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {sendDecision.wouldSend ? (
            <SocBadge tone="rose">최종 판단: 전송 대상 (would_send = true)</SocBadge>
          ) : (
            <SocBadge tone="slate">최종 판단: 보류 / 미전송 (would_send = false)</SocBadge>
          )}
          {sendDecision.decidedBy && <SocBadge tone="slate">결정 주체: {sendDecision.decidedBy}</SocBadge>}
        </div>
      </div>

      {sendDecision.opinionMismatch && (
        <div
          role="status"
          className="flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
          <span>정책 규칙, 일반 LLM, 판단 모델 간 의견 불일치가 감지되었습니다.</span>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="soc-panel flex flex-col justify-between p-4">
          <div>
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
                <Scale className="h-3.5 w-3.5 text-cyan-400" />
                정책 규칙 (Policy)
              </span>
              {sendDecision.policyMandatory && <SocBadge tone="rose">필수 규칙</SocBadge>}
            </div>
            <div className="mt-3 text-base font-bold text-slate-100">
              {decisionChoiceLabel(sendDecision.policyChoice)}
            </div>
            {sendDecision.policyId && (
              <div className="mt-1 font-mono text-[11px] text-slate-400">
                policy_id: {sendDecision.policyId}
              </div>
            )}
          </div>
          {sendDecision.policyReasons.length > 0 && (
            <ul className="mt-3 list-disc space-y-1 border-t border-slate-800 pt-3 pl-4 text-xs text-slate-300">
              {sendDecision.policyReasons.map((reason, idx) => (
                <li key={idx}>{reason}</li>
              ))}
            </ul>
          )}
        </div>

        <div className="soc-panel p-4">
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <Sparkles className="h-3.5 w-3.5 text-purple-400" />
            일반 LLM 권고
          </div>
          <div className="mt-3 text-base font-bold text-slate-100">
            {decisionChoiceLabel(sendDecision.llmChoice)}
          </div>
          <p className="mt-2 text-xs text-slate-400">
            단계 5 보고서 생성 모델이 판단한 권고 선택지입니다.
          </p>
        </div>

        <div className="soc-panel space-y-3 p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
              <Cpu className="h-3.5 w-3.5 text-emerald-400" />
              판단 모델 ({sendDecision.decisionModel ?? 'decision-model'})
            </span>
          </div>
          <div className="text-base font-bold text-slate-100">
            {decisionChoiceLabel(sendDecision.decisionModelChoice)}
          </div>

          {sendDecision.decisionModelConfidence !== null && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">선택 확률</span>
                <span className="font-mono font-semibold tabular-nums text-cyan-300">
                  {formatPercent(sendDecision.decisionModelConfidence)}
                </span>
              </div>
              <SvgProgressBar
                value={sendDecision.decisionModelConfidence}
                max={1}
                tone="cyan"
                label="판단 모델 선택 확률"
              />
            </div>
          )}

          {probEntries.length > 0 && (
            <div className="space-y-2 border-t border-slate-800 pt-2.5">
              <div className="text-[11px] font-semibold text-slate-400">선택지별 선택 확률</div>
              {probEntries.map(([choice, prob]) => (
                <div key={choice} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-300">{choice}</span>
                    <span className="font-mono tabular-nums text-slate-300">
                      {formatPercent(prob)}
                    </span>
                  </div>
                  <SvgProgressBar
                    value={prob}
                    max={1}
                    tone={choice === sendDecision.decisionModelChoice ? 'emerald' : 'slate'}
                    label={`${choice} 선택 확률`}
                  />
                </div>
              ))}
            </div>
          )}

          {sendDecision.decisionModelError && (
            <div className="rounded border border-rose-500/40 bg-rose-500/10 p-2 text-xs text-rose-200">
              {sendDecision.decisionModelError}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
