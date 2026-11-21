import { AlertTriangle, Cpu, GitCompare, Scale, Sparkles } from 'lucide-react';
import type { SendDecisionView } from '../../types/api';
import { formatPercent } from '../../utils/format';
import { labelText, policyReasonText } from '../../utils/labels';
import { CodeLabel, LookupText, SocBadge, WouldSendBadge } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';

export function SendDecisionSection({ sendDecision }: { sendDecision: SendDecisionView }) {
  if (!sendDecision.present) {
    return (
      <section className="soc-card p-5">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <GitCompare className="h-4 w-4 text-slate-400" />
          경보 발송 판단
        </div>
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
          이 인시던트는 경보 발송 판단 대상이 아닙니다.
        </div>
      </section>
    );
  }

  const probEntries = Object.entries(sendDecision.decisionModelProbabilities ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <section className="soc-card space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <GitCompare className="h-4 w-4 text-slate-400" />
          경보 발송 판단
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400">최종</span>
          <WouldSendBadge wouldSend={sendDecision.wouldSend} />
          {sendDecision.decidedBy && (
            <span className="text-slate-400">
              결정 근거 <CodeLabel dict="decidedBy" value={sendDecision.decidedBy} className="text-slate-200" />
            </span>
          )}
        </div>
      </div>

      {sendDecision.opinionMismatch && (
        <div
          role="status"
          className="flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
          <span>규칙, AI 리포트, 판단 모델의 의견이 서로 다릅니다.</span>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="soc-panel flex flex-col justify-between p-4">
          <div>
            <div className="flex items-center justify-between gap-2">
              <span
                className="soc-subhead flex items-center gap-1.5"
                title={sendDecision.policyId ? `규칙 ID: ${sendDecision.policyId}` : undefined}
              >
                <Scale className="h-3.5 w-3.5 text-slate-400" />
                규칙 의견
              </span>
              {sendDecision.policyMandatory && <SocBadge tone="neutral">반드시 적용되는 규칙</SocBadge>}
            </div>
            <div className="mt-3 text-base font-bold text-slate-100">
              <CodeLabel dict="sendChoice" value={sendDecision.policyChoice} />
            </div>
          </div>
          {sendDecision.policyReasons.length > 0 && (
            <ul className="mt-3 list-disc space-y-1 border-t border-slate-800 pl-4 pt-3 text-xs text-slate-300">
              {sendDecision.policyReasons.map((reason, idx) => (
                <li key={idx}>
                  <LookupText label={policyReasonText(reason)} />
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="soc-panel p-4">
          <div className="soc-subhead flex items-center gap-1.5">
            <Sparkles className="h-3.5 w-3.5 text-slate-400" />
            AI 리포트 의견
          </div>
          <div className="mt-3 text-base font-bold text-slate-100">
            <CodeLabel dict="sendChoice" value={sendDecision.llmChoice} />
          </div>
          <p className="mt-2 text-xs text-slate-400">AI 분석 리포트를 작성한 모델이 고른 선택지입니다.</p>
        </div>

        <div className="soc-panel space-y-3 p-4">
          <div className="flex items-center justify-between gap-2">
            <span
              className="soc-subhead flex items-center gap-1.5"
              title={sendDecision.decisionModel ? `판단 모델: ${sendDecision.decisionModel}` : undefined}
            >
              <Cpu className="h-3.5 w-3.5 text-slate-400" />
              판단 모델 의견
            </span>
          </div>
          <div className="text-base font-bold text-slate-100">
            <CodeLabel dict="sendChoice" value={sendDecision.decisionModelChoice} />
          </div>

          {sendDecision.decisionModelConfidence !== null && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">선택 확률</span>
                <span className="soc-num font-semibold text-slate-100">
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
                    <CodeLabel dict="sendChoice" value={choice} className="text-slate-300" />
                    <span className="soc-num text-slate-300">{formatPercent(prob)}</span>
                  </div>
                  <SvgProgressBar
                    value={prob}
                    max={1}
                    tone={choice === sendDecision.decisionModelChoice ? 'emerald' : 'slate'}
                    label={`${labelText('sendChoice', choice)} 선택 확률`}
                  />
                </div>
              ))}
            </div>
          )}

          {sendDecision.decisionModelError && (
            <div className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-200">
              {sendDecision.decisionModelError}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
