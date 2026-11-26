import { AlertTriangle, ClipboardList } from 'lucide-react';
import type { ReportView } from '../../types/api';
import { splitAttackCandidates, type AttackCandidateEntry } from '../../utils/attackCandidates';
import { formatDateTime } from '../../utils/format';
import { CodeLabel, SocBadge, VerificationBadge } from '../StatusBadge';
import { describeProblem, describeVerificationReason, templateReplacedText } from '../../utils/factLabels';
import { REPORT_KIND_DESCRIPTION } from '../../utils/labels';
import { AllFactsTable, FactEvidence } from './FactEvidence';

/**
 * AI 리포트 조각들. 요약 탭과 AI 리포트 탭이 같은 조각을 쓴다.
 * 생성 정보(요청·응답 모델, 토큰, 소요 시간, 리포트·입력 버전, 실행 ID)와 가명 대응표는 화면에 두지 않는다(2026-11-21 결정).
 * T64: 리포트 글은 바깥 글(최대 4,000자, 띄어쓰기 없는 긴 글 포함)이라 글 요소마다 `[overflow-wrap:anywhere]`로 줄을 넘지 않게 한다.
 */

/** AI 리포트 탭 머리의 안내 한 줄(T64). LLM이 쓴 리포트일 때만 */
export const AI_WRITTEN_NOTE =
  'AI(LLM)가 쓴 글입니다. 근거 사실과 대조했지만 해석이 맞다는 뜻은 아닙니다. 판단은 증적으로 확인하세요.';

/** LLM이 쓴 리포트인가(kind `llm`). 템플릿 리포트·종류 없음은 아니다 */
export function isLlmReport(report: Pick<ReportView, 'present' | 'reportKind'>): boolean {
  return report.present && (report.reportKind ?? '').trim().toLowerCase() === 'llm';
}

/**
 * 리포트 종류 표지. AI 리포트 탭 머리와 요약 탭의 리포트 글 칸(T64)이 같은 규칙을 쓴다:
 * 템플릿으로 바꾼 리포트면 "템플릿 리포트" 표지, 아니면 종류 사전 값("AI 작성" 등).
 */
export function ReportKindBadge({ report }: { report: ReportView }) {
  if (isTemplateReplaced(report)) return <TemplateReportBadge title={REPORT_KIND_DESCRIPTION.template} />;
  return (
    <SocBadge tone="neutral">
      <CodeLabel dict="reportKind" value={report.reportKind} />
    </SocBadge>
  );
}

/** 조각 머리줄의 종류 표지. 요약 탭은 리포트 글 칸마다 붙이고, AI 리포트 탭은 탭 머리에 한 번만 둔다 */
function KindBadgeSlot({ report, show }: { report: ReportView; show: boolean }) {
  return show ? <ReportKindBadge report={report} /> : null;
}

export function ReportClaims({ report, kindBadge = false }: { report: ReportView; kindBadge?: boolean }) {
  if (report.claims.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h4 className="soc-subhead">확인된 사실</h4>
        <KindBadgeSlot report={report} show={kindBadge} />
        <span className="text-[11px] text-slate-500">문장 아래는 리포트가 인용한 근거 사실입니다. 끝의 번호는 근거 번호입니다</span>
      </div>
      <ul className="space-y-1.5">
        {report.claims.map((item, idx) => (
          <li key={idx} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5">
            <p className="text-sm text-slate-100 [overflow-wrap:anywhere]">{item.claim}</p>
            <FactEvidence facts={item.facts} pseudonyms={report.pseudonyms} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReportExplanations({ report, kindBadge = false }: { report: ReportView; kindBadge?: boolean }) {
  if (report.possibleExplanations.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h4 className="soc-subhead">가능한 해석</h4>
        <KindBadgeSlot report={report} show={kindBadge} />
      </div>
      <ul className="space-y-1.5">
        {report.possibleExplanations.map((item, idx) => (
          <li key={idx} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5">
            <p className="text-sm text-slate-100 [overflow-wrap:anywhere]">{item.explanation}</p>
            {item.attackIds.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {item.attackIds.map((aid) => (
                  <SocBadge key={aid} tone="neutral">
                    <span className="font-mono">{aid}</span>
                  </SocBadge>
                ))}
              </div>
            )}
            <FactEvidence facts={item.facts} pseudonyms={report.pseudonyms} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function AttackCandidateList({ entries }: { entries: AttackCandidateEntry[] }) {
  return (
    <ul className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
      {entries.map(({ candidate: cand, index }) => (
        <li key={`${cand.attackId}-${index}`} className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono font-bold text-slate-100">{cand.attackId}</span>
            <span className="min-w-0 text-right text-slate-200 [overflow-wrap:anywhere]">{cand.name}</span>
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
  );
}

/**
 * ATT&CK 후보: LLM 글이 아니라 검색으로 찾은 MITRE 자료라 "AI 작성" 표지를 붙이지 않는다("확정이 아닌 가설" 표지).
 * T64: 받은 순서(순위)대로 앞 3개와 가능한 해석이 인용한 후보는 늘 보이고 나머지는 접는다.
 */
export function ReportAttack({ report }: { report: ReportView }) {
  if (report.attackCandidates.length === 0) return null;
  const { shown, folded } = splitAttackCandidates(report);
  return (
    <div className="space-y-2" data-attack-candidates="">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="soc-subhead">관련 ATT&amp;CK 기법 후보</h4>
        <SocBadge tone="neutral">확정이 아닌 가설</SocBadge>
      </div>
      <AttackCandidateList entries={shown} />
      {folded.length > 0 && (
        <details>
          <summary className="cursor-pointer text-[11px] text-cyan-300 hover:text-cyan-200">나머지 후보 {folded.length}개</summary>
          <div className="mt-1.5">
            <AttackCandidateList entries={folded} />
          </div>
        </details>
      )}
    </div>
  );
}

/** 추가 확인 권고: 체크 목록처럼 보인다. 표시는 이 화면에서만 유지되고 저장되지 않는다. */
export function ReportFollowUp({
  report,
  idPrefix,
  kindBadge = false,
}: {
  report: ReportView;
  idPrefix: string;
  kindBadge?: boolean;
}) {
  if (report.followUp.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h4 className="soc-subhead">추가 확인 권고</h4>
        <KindBadgeSlot report={report} show={kindBadge} />
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
              <label htmlFor={id} className="min-w-0 [overflow-wrap:anywhere]">
                {item}
              </label>
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
      <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-300 [overflow-wrap:anywhere]">
        {report.limitations.map((item, idx) => (
          <li key={idx}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

/** T40 검증 실패 사유: 사전에 있는 값은 한국어(원문은 툴팁), 없는 값은 원문(data-raw) */
function VerificationReasonText({ reason }: { reason: string | null }) {
  const view = describeVerificationReason(reason);
  if (view === null) return <>-</>;
  if (view.known) {
    return <span title={`원래 값: ${view.raw}`}>{view.text}</span>;
  }
  return (
    <span className="font-mono" data-raw="">
      {view.text}
    </span>
  );
}

/**
 * T43 계약(zeek_AD data-contract-v2)대로의 템플릿 리포트인가: kind가 template이고 검증 실패(LLM 리포트를 버리고 템플릿으로 바꿈).
 * 계약에 없는 조합(llm + 검증 실패, template + 통과·값 없음)은 false이고 화면은 kind 표지와 검증 표지를 함께 보인다.
 */
export function isTemplateReplaced(report: Pick<ReportView, 'present' | 'reportKind' | 'verificationPassed'>): boolean {
  return report.present && (report.reportKind ?? '').trim().toLowerCase() === 'template' && report.verificationPassed === false;
}

/** T43 "템플릿 리포트" 표지(주의 색조, 실패의 빨강은 쓰지 않는다) */
export function TemplateReportBadge({ label = '템플릿 리포트', title }: { label?: string; title: string }) {
  return (
    <span role="img" aria-label={`${label}: ${title}`} title={title} className="inline-flex" data-template-report="">
      <SocBadge tone="attention">
        <ClipboardList className="h-3 w-3" aria-hidden="true" />
        {label}
      </SocBadge>
    </span>
  );
}

/** 검증 실패일 때만 사유·문제 항목을 보인다. T43: 템플릿 리포트면 그 문제들이 쓰지 않은 AI 리포트의 것임을 제목에 적는다. */
export function ReportVerificationProblems({ report }: { report: ReportView }) {
  if (report.verificationPassed !== false) return null;
  const template = isTemplateReplaced(report);
  // T37: 구조 목록(kind·value·where)을 문장으로 보인다. 옛 응답이면 글 목록을 원문 그대로 보인다.
  const problems = report.verificationProblemItems
    ? report.verificationProblemItems.map((item) => describeProblem(item, report.pseudonyms))
    : report.verificationProblems.map((text) => ({ text, known: false, where: null as string | null }));
  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200">
      <div className="flex items-center gap-1.5 font-semibold">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="[overflow-wrap:anywhere]">
          {template ? 'AI 리포트를 쓰지 않은 이유: ' : '검증 실패 사유: '}
          <VerificationReasonText reason={report.verificationReason} />
        </span>
      </div>
      {template && problems.length > 0 && (
        <p className="mt-1 text-amber-200/80">아래 항목은 쓰지 않은 AI 리포트 글의 것입니다. 화면의 템플릿 리포트 내용이 아닙니다.</p>
      )}
      {problems.length > 0 && (
        <ul className="mt-1 list-disc space-y-0.5 pl-4 [overflow-wrap:anywhere]">
          {problems.map((prob, idx) => (
            <li key={idx}>
              {prob.known ? (
                <>
                  {prob.text}
                  {prob.where && (
                    <span className="text-amber-200/80">
                      {' '}
                      (위치: <span className="font-mono" data-raw="">{prob.where}</span>)
                    </span>
                  )}
                </>
              ) : (
                <span className="font-mono" data-raw="">
                  {prob.text}
                </span>
              )}
            </li>
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

  const template = isTemplateReplaced(report);
  return (
    <div className="space-y-5">
      <div className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <ReportKindBadge report={report} />
          {!template && <VerificationBadge passed={report.verificationPassed} />}
          <span className="text-slate-400">
            작성 시각 <span className="tabular-nums text-slate-300">{formatDateTime(report.createdAt)}</span>
          </span>
        </div>
        {template && (
          <p className="text-xs text-slate-300" data-testid="template-report-note">
            {templateReplacedText(report.verificationReason)}
          </p>
        )}
        {isLlmReport(report) && (
          <p className="text-xs text-slate-300" data-testid="ai-written-note">
            {AI_WRITTEN_NOTE}
          </p>
        )}
      </div>

      {report.llmError && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200 [overflow-wrap:anywhere]">
          <span className="font-semibold">AI 작성 오류: </span>
          {report.llmError}
        </div>
      )}

      <ReportVerificationProblems report={report} />

      {report.observationSummary && (
        <div className="space-y-1.5">
          <h4 className="soc-subhead">관측 요약</h4>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-100 [overflow-wrap:anywhere]">
            {report.observationSummary}
          </p>
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
          {report.sendRecommendation.reason && (
            <p className="text-sm text-slate-200 [overflow-wrap:anywhere]">{report.sendRecommendation.reason}</p>
          )}
          <FactEvidence facts={report.sendRecommendation.facts} pseudonyms={report.pseudonyms} />
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <ReportFollowUp report={report} idPrefix="report-tab" />
        <ReportLimitations report={report} />
      </div>

      <AllFactsTable report={report} />
    </div>
  );
}
