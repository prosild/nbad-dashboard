import { useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronUp, Cpu, Scale, Sparkles } from 'lucide-react';
import type { SendDecisionView } from '../../types/api';
import { formatPercent } from '../../utils/format';
import { labelText, policyReasonText } from '../../utils/labels';
import { CodeLabel, LookupText, SocBadge, WouldSendBadge } from '../StatusBadge';

/**
 * 발송 판단 탭(T19, T21 이름 정리): 최종 결과 + 세 의견(규칙·AI 리포트·판단 모델) 한 줄씩.
 * 의견이 갈릴 때만 강조하고, 같으면 "세 의견 모두 …" 한 줄을 먼저 보이고 펼친다.
 * 정책 ID·판단 모델 ID·선택지별 확률 막대는 화면에 두지 않는다(2026-11-21 결정). 판단 모델은 선택 확률 숫자 하나만.
 */
export function SendDecisionSection({ sendDecision }: { sendDecision: SendDecisionView }) {
  const agree = !sendDecision.opinionMismatch;
  const [open, setOpen] = useState(!agree);

  if (!sendDecision.present) {
    return <p className="text-sm text-slate-400">이 인시던트는 발송 판단 대상이 아닙니다.</p>;
  }

  const commonChoice = agree ? (sendDecision.policyChoice ?? sendDecision.llmChoice ?? sendDecision.decisionModelChoice) : null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400">최종 발송 판단</span>
        <WouldSendBadge wouldSend={sendDecision.wouldSend} />
        {sendDecision.decidedBy && (
          <span className="text-slate-400">
            결정 근거 <CodeLabel dict="decidedBy" value={sendDecision.decidedBy} className="text-slate-200" />
          </span>
        )}
      </div>

      {agree ? (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="flex w-full items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2 text-left text-sm text-slate-200 hover:border-slate-700"
        >
          <span>세 의견 모두 {labelText('sendChoice', commonChoice)}</span>
          {open ? <ChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" /> : <ChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />}
        </button>
      ) : (
        <div
          role="status"
          className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          규칙, AI 리포트, 판단 모델의 의견이 서로 다릅니다.
        </div>
      )}

      {open && (
        <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-[#090f1d] text-xs">
          <li className="space-y-1 px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <Scale className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <span className="w-24 shrink-0 text-slate-400">규칙 의견</span>
              <span className="font-semibold text-slate-100">
                <CodeLabel dict="sendChoice" value={sendDecision.policyChoice} />
              </span>
              {sendDecision.policyMandatory && <SocBadge tone="neutral">반드시 적용되는 규칙</SocBadge>}
            </div>
            {sendDecision.policyReasons.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-12 text-slate-300">
                {sendDecision.policyReasons.map((reason, idx) => (
                  <li key={idx}>
                    <LookupText label={policyReasonText(reason)} />
                  </li>
                ))}
              </ul>
            )}
          </li>
          <li className="flex flex-wrap items-center gap-2 px-3 py-2.5">
            <Sparkles className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            <span className="w-24 shrink-0 text-slate-400">AI 리포트 의견</span>
            <span className="font-semibold text-slate-100">
              <CodeLabel dict="sendChoice" value={sendDecision.llmChoice} />
            </span>
          </li>
          <li className="space-y-1 px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <Cpu className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <span className="w-24 shrink-0 text-slate-400">판단 모델 의견</span>
              <span className="font-semibold text-slate-100">
                <CodeLabel dict="sendChoice" value={sendDecision.decisionModelChoice} />
              </span>
              {sendDecision.decisionModelConfidence !== null && (
                <span className="text-slate-400">
                  선택 확률{' '}
                  <span className="soc-num font-semibold text-slate-200">
                    {formatPercent(sendDecision.decisionModelConfidence)}
                  </span>
                </span>
              )}
            </div>
            {sendDecision.decisionModelError && (
              <div className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-200">
                {sendDecision.decisionModelError}
              </div>
            )}
          </li>
        </ul>
      )}
    </div>
  );
}
