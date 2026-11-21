import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import type { FactItem } from '../../types/api';

export function FactChips({ facts }: { facts: FactItem[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (!facts || facts.length === 0) {
    return null;
  }

  const activeFact = facts.find((f) => f.id === expandedId) ?? null;

  return (
    <div className="mt-2 space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {facts.map((fact) => {
          const isOpen = expandedId === fact.id;
          return (
            <button
              key={fact.id}
              type="button"
              onClick={() => setExpandedId(isOpen ? null : fact.id)}
              aria-expanded={isOpen}
              title="근거 값 보기"
              className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-2 py-0.5 font-mono text-xs transition ${
                isOpen
                  ? 'border-cyan-400/60 bg-cyan-500/20 text-cyan-100'
                  : 'border-slate-700 bg-slate-900 text-cyan-300 hover:border-cyan-500/50 hover:bg-slate-800'
              }`}
            >
              <span>{fact.id}</span>
              {isOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
          );
        })}
      </div>

      {activeFact && (
        <div className="rounded-lg border border-cyan-500/30 bg-[#081020] px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono font-semibold text-cyan-300">{activeFact.id}</span>
            {/* 근거 사실 이름은 zeek_AD 리포트가 준 값 그대로다(데이터 원문). */}
            <span className="font-mono font-semibold text-slate-200" data-raw="">
              {activeFact.name}
            </span>
          </div>
          <div className="mt-1 break-all font-mono text-slate-300">{activeFact.value}</div>
        </div>
      )}
    </div>
  );
}
