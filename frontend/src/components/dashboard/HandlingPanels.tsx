import { Fragment } from 'react';
import { Link } from 'react-router-dom';
import { Timer, Users } from 'lucide-react';
import type { HandlingTimes, TimeStat, Workload } from '../../types/api';
import { formatElapsed, formatNumber } from '../../utils/format';
import { labelText } from '../../utils/labels';
import { AssigneeName } from '../incident/AssignmentBits';
import { SocBadge } from '../StatusBadge';

/** 표본 부족 기준(T20 규칙과 같다): 건수가 이보다 적으면 값은 보이되 "표본 부족"을 붙인다 */
export const HANDLING_SAMPLE_MIN = 10;

export const HANDLING_METRIC_TOOLTIP = {
  detection:
    '탐지 지연(MTTD): 트래픽 발생 시각에서 탐지 시각(처음 탐지된 분석 완료)까지. 실습망만 셉니다(가져온 데이터는 발생 시각이 원본 데이터셋 시각이라 뺍니다). 기간은 탐지 시각 기준입니다.',
  acknowledge:
    '착수 시간(MTTA): 탐지 시각에서 착수(처음 조사 중으로 바뀐 시각)까지. 기간은 착수 시각 기준입니다. 조사 중 기록 없이 종결된 건은 제외에 셉니다. 담당 지정은 착수로 치지 않습니다.',
  resolve:
    '처리 시간(MTTR): 탐지 시각에서 종결 시각까지. 기간은 종결 시각 기준이고 판정별로도 봅니다.',
} as const;

const STAT_NOTE =
  '중앙값·p90은 가장 가까운 순위(정렬 뒤 ceil(p·n)번째)입니다. 평균은 며칠 묵은 몇 건에 크게 끌려가므로 쓰지 않습니다. 제외는 값이 음수이거나 필요한 시각이 없는 건입니다.';

function StatCells({ stat }: { stat: TimeStat }) {
  const empty = stat.n === 0;
  return (
    <>
      <td className="soc-td soc-num tabular-nums text-slate-200">{formatNumber(stat.n)}</td>
      <td className="soc-td soc-num tabular-nums text-slate-100">{empty ? '-' : formatElapsed(stat.medianSeconds)}</td>
      <td className="soc-td soc-num tabular-nums text-slate-100">{empty ? '-' : formatElapsed(stat.p90Seconds)}</td>
      <td className="soc-td soc-num tabular-nums text-slate-400">{formatNumber(stat.excluded)}</td>
      <td className="soc-td">
        {stat.smallSample && (
          <SocBadge tone="muted" title={`건수가 ${HANDLING_SAMPLE_MIN}건 미만이라 값이 흔들릴 수 있습니다`}>
            표본 부족
          </SocBadge>
        )}
      </td>
    </>
  );
}

/** 운영 현황 "처리 시간" 패널(T25): 기간 안 탐지 지연·착수 시간·처리 시간(판정별 하위 행) */
export function HandlingTimesPanel({ times, scope }: { times: HandlingTimes; scope: string }) {
  const rows: { key: keyof typeof HANDLING_METRIC_TOOLTIP; label: string; note?: string; stat: TimeStat }[] = [
    { key: 'detection', label: '탐지 지연(MTTD)', note: '실습망만', stat: times.detection },
    { key: 'acknowledge', label: '착수 시간(MTTA)', stat: times.acknowledge },
    { key: 'resolve', label: '처리 시간(MTTR)', stat: times.resolve.all },
  ];
  return (
    <section className="soc-card space-y-3 p-4" aria-label="처리 시간">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Timer className="h-4 w-4 text-slate-400" aria-hidden="true" />
          처리 시간
          <span className="text-xs font-normal text-slate-400">{scope}</span>
        </h2>
        <span className="text-[11px] text-slate-400" title={STAT_NOTE}>
          중앙값·p90 · 기준 시각 기준
        </span>
      </div>
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[34rem] border-collapse text-left text-xs">
          <thead>
            <tr>
              <th scope="col" className="soc-th">지표</th>
              <th scope="col" className="soc-th text-right">건수</th>
              <th scope="col" className="soc-th text-right">중앙값</th>
              <th scope="col" className="soc-th text-right">p90</th>
              <th scope="col" className="soc-th text-right" title="값이 음수이거나 필요한 시각이 없는 건">제외</th>
              <th scope="col" className="soc-th"><span className="sr-only">표본</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <Fragment key={r.key}>
                <tr data-metric={r.key}>
                  <th scope="row" className="soc-td font-medium text-slate-100" title={HANDLING_METRIC_TOOLTIP[r.key]}>
                    {r.label}
                    {r.note && <span className="ml-1.5 text-[11px] font-normal text-slate-400">{r.note}</span>}
                  </th>
                  <StatCells stat={r.stat} />
                </tr>
                {r.key === 'resolve' &&
                  times.resolve.byResolution.map((b) => (
                    <tr key={b.resolution} data-resolution={b.resolution}>
                      <th scope="row" className="soc-td pl-6 font-normal text-slate-300">
                        {b.resolution === 'none' ? '판정 없음' : labelText('resolution', b.resolution)}
                      </th>
                      <StatCells stat={b.stat} />
                    </tr>
                  ))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] leading-relaxed text-slate-400">{STAT_NOTE}</p>
    </section>
  );
}

/** 운영 현황 "담당 현황" 패널(T25): 지금 값(기간 무관). 착수 지연은 큐로 가는 링크다. */
export function WorkloadPanel({ workload, overdueLink }: { workload: Workload; overdueLink: string }) {
  const cells = [
    { label: '미종결', value: workload.unclosed, hint: '신규·조사 중 인시던트' },
    { label: '배정', value: workload.assigned },
    { label: '미배정', value: workload.unassigned },
  ];
  return (
    <section className="soc-card space-y-3 p-4" aria-label="담당 현황">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Users className="h-4 w-4 text-slate-400" aria-hidden="true" />
          담당 현황
          <span className="text-xs font-normal text-slate-400">지금(기간과 무관)</span>
        </h2>
      </div>
      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {cells.map((c) => (
          <div key={c.label} className="rounded-lg border border-slate-800 px-3 py-2" title={c.hint}>
            <dt className="text-[11px] text-slate-400">{c.label}</dt>
            <dd className="text-lg font-bold tabular-nums text-slate-100">{formatNumber(c.value)}</dd>
          </div>
        ))}
        <div className="rounded-lg border border-slate-800 px-3 py-2">
          <dt className="text-[11px] text-slate-400">착수 지연</dt>
          <dd className="text-lg font-bold tabular-nums">
            <Link
              to={overdueLink}
              className={`${workload.ackOverdue > 0 ? 'text-rose-300' : 'text-slate-300'} hover:underline`}
              aria-label={`착수 지연 ${workload.ackOverdue}건 인시던트 큐에서 보기`}
            >
              {formatNumber(workload.ackOverdue)}
            </Link>
          </dd>
        </div>
      </dl>
      {workload.byAssignee.length === 0 ? (
        <p className="text-xs text-slate-400">담당 중인 인시던트 없음</p>
      ) : (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[22rem] border-collapse text-left text-xs">
            <caption className="sr-only">담당자별 미종결 인시던트 수</caption>
            <thead>
              <tr>
                <th scope="col" className="soc-th">담당자</th>
                <th scope="col" className="soc-th text-right">{labelText('incidentStatus', 'open')}</th>
                <th scope="col" className="soc-th text-right">{labelText('incidentStatus', 'investigating')}</th>
                <th scope="col" className="soc-th text-right">합계</th>
              </tr>
            </thead>
            <tbody>
              {workload.byAssignee.map((l) => (
                <tr key={l.username}>
                  <th scope="row" className="soc-td font-normal">
                    <AssigneeName assignee={l} className="text-xs" />
                  </th>
                  <td className="soc-td soc-num tabular-nums text-slate-200">{formatNumber(l.open)}</td>
                  <td className="soc-td soc-num tabular-nums text-slate-200">{formatNumber(l.investigating)}</td>
                  <td className="soc-td soc-num tabular-nums text-slate-100">{formatNumber(l.open + l.investigating)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
