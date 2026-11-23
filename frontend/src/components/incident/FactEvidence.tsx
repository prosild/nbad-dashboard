import { useId, useState } from 'react';
import type { FactItem, ReportView } from '../../types/api';
import { describeFact, FACT_GROUPS, type FactView, type Pseudonyms } from '../../utils/factLabels';

/**
 * AI 리포트 문장 아래 근거(T37). 한 항목은 "항목 이름 + 값"이고 사실 번호는 끝에 작게 붙인다(접근성 이름에도 넣는다).
 * 항목 이름·값은 utils/factLabels.ts 사전으로 바꾸고, 사전에 없는 이름·값 모양은 원문 그대로(data-raw) 보인다.
 * 원문 이름과 글 값은 항목 툴팁에 둔다(zeek_AD 쪽과 말을 맞출 때 쓴다). 모든 글은 일반 텍스트로만 그린다.
 */

/** 처음에 보이는 근거 수. 공개 데이터의 주장당 인용은 평균 4.1개·최대 19개다. */
export const FACT_PREVIEW_COUNT = 4;

function rawTooltip(fact: FactItem, view: FactView): string {
  const lines = [`근거 번호 ${view.id}`, `zeek_AD 이름: ${view.rawName}`];
  if (!view.missing) lines.push(`원문 값: ${fact.value ?? '-'}`);
  return lines.join('\n');
}

function FactName({ view }: { view: FactView }) {
  return view.nameKnown ? (
    <span className="text-slate-400">{view.label}</span>
  ) : (
    <span className="font-mono text-slate-500" data-raw="">
      {view.label}
    </span>
  );
}

function FactValue({ view }: { view: FactView }) {
  if (view.missing) {
    return <span className="text-amber-300">근거 정보 없음</span>;
  }
  return view.valueKnown ? (
    <span className="tabular-nums text-slate-100">{view.text}</span>
  ) : (
    <span className="font-mono text-slate-300" data-raw="">
      {view.text}
    </span>
  );
}

function FactNumber({ id }: { id: string }) {
  return (
    <>
      <span aria-hidden="true" className="font-mono text-[10px] text-slate-500">
        {id}
      </span>
      <span className="sr-only">근거 번호 {id}</span>
    </>
  );
}

function FactRow({ fact, pseudonyms }: { fact: FactItem; pseudonyms: Pseudonyms }) {
  const view = describeFact(fact, pseudonyms);
  if (view.missing) {
    return (
      <li className="flex flex-wrap items-baseline gap-x-2 text-xs" title={rawTooltip(fact, view)} data-fact-id={view.id}>
        <FactValue view={view} />
        <span className="ml-auto">
          <FactNumber id={view.id} />
        </span>
      </li>
    );
  }
  return (
    <li
      className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs [overflow-wrap:anywhere]"
      title={rawTooltip(fact, view)}
      data-fact-id={view.id}
    >
      <FactName view={view} />
      {view.wide ? (
        <>
          <span className="ml-auto">
            <FactNumber id={view.id} />
          </span>
          <span className="block min-w-0 basis-full pl-2">
            <FactValue view={view} />
          </span>
        </>
      ) : (
        <>
          <span className="min-w-0">
            <FactValue view={view} />
          </span>
          <span className="ml-auto">
            <FactNumber id={view.id} />
          </span>
        </>
      )}
    </li>
  );
}

/** 문장 아래 근거 목록. 인용이 FACT_PREVIEW_COUNT + 1개를 넘으면 처음 FACT_PREVIEW_COUNT개만 보이고 "근거 N개 더 보기"로 편다. */
export function FactEvidence({ facts, pseudonyms }: { facts: FactItem[]; pseudonyms: Pseudonyms }) {
  const [expanded, setExpanded] = useState(false);
  const listId = useId();
  if (!facts || facts.length === 0) return null;
  // 하나만 숨게 되면 버튼 대신 모두 보인다("근거 1개 더 보기"는 버튼이 근거 한 줄과 같은 자리를 차지한다).
  const collapsible = facts.length > FACT_PREVIEW_COUNT + 1;
  const hidden = collapsible ? facts.length - FACT_PREVIEW_COUNT : 0;
  const shown = expanded || !collapsible ? facts : facts.slice(0, FACT_PREVIEW_COUNT);
  return (
    <div className="mt-2 border-l-2 border-slate-700 pl-2.5">
      <ul id={listId} aria-label={`근거 사실 ${facts.length}개`} className="space-y-1">
        {shown.map((fact, idx) => (
          <FactRow key={`${fact.id}-${idx}`} fact={fact} pseudonyms={pseudonyms} />
        ))}
      </ul>
      {hidden > 0 && (
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={listId}
          onClick={() => setExpanded((v) => !v)}
          className="mt-1 text-[11px] text-cyan-300 hover:text-cyan-200 hover:underline"
        >
          {expanded ? '근거 접기' : `근거 ${hidden}개 더 보기`}
        </button>
      )}
    </div>
  );
}

/** 리포트가 인용한 사실 번호(주장·가능한 해석·경보 권고) */
export function citedFactIds(report: ReportView): Set<string> {
  const ids = new Set<string>();
  const add = (facts: FactItem[] | undefined) => facts?.forEach((f) => ids.add(f.id));
  report.claims.forEach((c) => add(c.facts));
  report.possibleExplanations.forEach((e) => add(e.facts));
  add(report.sendRecommendation?.facts);
  return ids;
}

/** AI 리포트 탭: 근거 사실 전체(기본 접힘). 번호·항목·값 표를 묶음별로 나누고, 리포트가 인용한 항목에 표시를 한다. */
export function AllFactsTable({ report }: { report: ReportView }) {
  const all = report.allFacts ?? [];
  if (all.length === 0) return null;
  const cited = citedFactIds(report);
  const views = all.map((fact) => ({ fact, view: describeFact(fact, report.pseudonyms) }));
  const citedCount = views.filter(({ view }) => cited.has(view.id)).length;
  return (
    <details className="rounded-lg border border-slate-800 bg-[#090f1d] px-3 py-2.5">
      <summary className="soc-subhead cursor-pointer">
        근거 사실 전체 ({all.length}개)
        <span className="ml-2 text-[11px] font-normal text-slate-500">리포트가 인용한 항목 {citedCount}개</span>
      </summary>
      <div className="mt-3 space-y-4">
        {FACT_GROUPS.map((group) => {
          const rows = views.filter(({ view }) => view.group === group.key);
          if (rows.length === 0) return null;
          return (
            <table key={group.key} className="w-full table-fixed border-collapse text-xs">
              <caption className="pb-1 text-left text-[11px] font-semibold text-slate-300">
                {group.label} ({rows.length}개)
              </caption>
              <thead>
                <tr className="border-b border-slate-800 text-left text-[11px] text-slate-500">
                  <th scope="col" className="w-14 py-1 pr-2 font-normal">
                    번호
                  </th>
                  <th scope="col" className="w-[38%] py-1 pr-2 font-normal">
                    항목
                  </th>
                  <th scope="col" className="py-1 font-normal">
                    값
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ fact, view }, idx) => {
                  const isCited = cited.has(view.id);
                  return (
                    <tr
                      key={`${view.id}-${idx}`}
                      className={`border-b border-slate-800/60 align-top ${isCited ? 'bg-cyan-500/5' : ''}`}
                      title={rawTooltip(fact, view)}
                    >
                      <td className="py-1 pr-2 font-mono text-[11px] text-slate-400 [overflow-wrap:anywhere]">
                        {view.id}
                        {isCited && (
                          <span className="mt-0.5 block w-fit rounded border border-cyan-500/40 px-1 font-sans text-[10px] text-cyan-300">
                            인용
                            <span className="sr-only">: 리포트가 인용한 근거</span>
                          </span>
                        )}
                      </td>
                      <td className="py-1 pr-2 [overflow-wrap:anywhere]">
                        <FactName view={view} />
                      </td>
                      <td className="py-1 [overflow-wrap:anywhere]">
                        <FactValue view={view} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          );
        })}
      </div>
    </details>
  );
}
