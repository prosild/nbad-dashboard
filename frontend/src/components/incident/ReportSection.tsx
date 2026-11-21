import { AlertTriangle } from 'lucide-react';
import type { ReportView } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { CodeLabel, SocBadge, VerificationBadge } from '../StatusBadge';
import { FactChips } from './FactChips';

/**
 * AI 리포트 조각들. 요약 탭과 AI 리포트 탭이 같은 조각을 쓴다.
 * 생성 정보(요청·응답 모델, 토큰, 소요 시간, 리포트·입력 버전, 실행 ID)와 가명 대응표는 화면에 두지 않는다(사용자 결정 2026-11-21).
 */

export function ReportClaims({ report }: { report: ReportView }) {
  if (report.claims.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h4 className="soc-subhead">확인된 사실</h4>
        <span className="text-[11px] text-slate-500">근거 번호를 누르면 근거 값을 볼 수 있습니다</span>
      </div>
      <ul className="space-y-1.5">
        {report.claims.map((item, idx) => (
          <li key={idx} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5">
            <p className="text-sm text-slate-100">{item.claim}</p>
            <FactChips facts={item.facts} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReportExplanations({ report }: { report: ReportView }) {
  if (report.possibleExplanations.length === 0) return null;
  return (
    <div className="space-y-2">
      <h4 className="soc-subhead">가능한 해석</h4>
      <ul className="space-y-1.5">
        {report.possibleExplanations.map((item, idx) => (
          <li key={idx} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5">
            <p className="text-sm text-slate-100">{item.explanation}</p>
            {item.attackIds.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {item.attackIds.map((aid) => (
                  <SocBadge key={aid} tone="neutral">
                    <span className="font-mono">{aid}</span>
                  </SocBadge>
                ))}
              </div>
            )}
            <FactChips facts={item.facts} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReportAttack({ report }: { report: ReportView }) {
  if (report.attackCandidates.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="soc-subhead">관련 ATT&amp;CK 기법 후보</h4>
        <SocBadge tone="neutral">확정이 아닌 가설</SocBadge>
      </div>
      <ul className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        {report.attackCandidates.map((cand, idx) => (
          <li key={`${cand.attackId}-${idx}`} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-bold text-slate-100">{cand.attackId}</span>
              <span className="text-right text-slate-200">{cand.name}</span>
            </div>
            {cand.tactics.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1">
                {cand.tactics.map((tac) => (
                  <SocBadge key={tac} tone="muted">
                    <CodeLabel dict="attackTactic" value={tac} />
                  </SocBadge>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** 추가 확인 권고: 체크 목록처럼 보인다. 표시는 이 화면에서만 유지되고 저장되지 않는다. */
export function ReportFollowUp({ report, idPrefix }: { report: ReportView; idPrefix: string }) {
  if (report.followUp.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h4 className="soc-subhead">추가 확인 권고</h4>
        <span className="text-[11px] text-slate-500">확인 표시는 저장되지 않습니다</span>
      </div>
      <ul className="space-y-1">
        {report.followUp.map((item, idx) => {
          const id = `${idPrefix}-followup-${idx}`;
          return (
            <li key={idx} className="flex items-start gap-2 text-sm text-slate-200">
              <input
                id={id}
                type="checkbox"
                className="mt-1 h-3.5 w-3.5 shrink-0 rounded border-slate-600 bg-slate-900 text-cyan-400 focus:ring-cyan-500/30"
              />
              <label htmlFor={id}>{item}</label>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function ReportLimitations({ report }: { report: ReportView }) {
  if (report.limitations.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <h4 className="soc-subhead">리포트의 한계</h4>
      <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-300">
        {report.limitations.map((item, idx) => (
          <li key={idx}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

/** 검증 실패일 때만 사유·문제 항목을 보인다. */
export function ReportVerificationProblems({ report }: { report: ReportView }) {
  if (report.verificationPassed !== false) return null;
  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200">
      <div className="flex items-center gap-1.5 font-semibold">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        검증 실패 사유: {report.verificationReason || '-'}
      </div>
      {report.verificationProblems.length > 0 && (
        <ul className="mt-1 list-disc space-y-0.5 pl-4">
          {report.verificationProblems.map((prob, idx) => (
            <li key={idx}>{prob}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** AI 리포트 탭: 리포트 전체(표시 항목만). */
export function ReportSection({ report }: { report: ReportView }) {
  if (!report.present) {
    return <p className="text-sm text-slate-400">이 인시던트에는 AI 분석 리포트가 없습니다.</p>;
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <SocBadge tone="neutral">
          <CodeLabel dict="reportKind" value={report.reportKind} />
        </SocBadge>
        <VerificationBadge passed={report.verificationPassed} />
        <span className="text-slate-400">
          작성 시각 <span className="tabular-nums text-slate-300">{formatDateTime(report.createdAt)}</span>
        </span>
      </div>

      {report.llmError && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200">
          <span className="font-semibold">AI 작성 오류: </span>
          {report.llmError}
        </div>
      )}

      <ReportVerificationProblems report={report} />

      {report.observationSummary && (
        <div className="space-y-1.5">
          <h4 className="soc-subhead">관측 요약</h4>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100">{report.observationSummary}</p>
        </div>
      )}

      <ReportClaims report={report} />
      <ReportExplanations report={report} />
      <ReportAttack report={report} />

      {report.sendRecommendation && (
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="soc-subhead">리포트의 경보 권고</h4>
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

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <ReportFollowUp report={report} idPrefix="report-tab" />
        <ReportLimitations report={report} />
      </div>
    </div>
  );
}
