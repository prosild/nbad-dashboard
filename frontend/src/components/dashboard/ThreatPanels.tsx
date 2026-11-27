import { Link } from 'react-router-dom';
import { Crosshair, MessagesSquare, Network } from 'lucide-react';
import type { DashboardOverviewResponse, TopHostRow, TopThreadRow } from '../../types/api';
import { formatCompactDateTime, formatDateTime, formatNumber } from '../../utils/format';
import { hostIpKind } from '../../utils/ipScope';
import { labelText, lookupLabel } from '../../utils/labels';
import { DetectionModelName } from '../StatusBadge';
import { SvgProgressBar } from '../SvgProgressBar';
import { PanelHeader } from './PanelHeader';

/**
 * 현황판 위협 가시성 세 패널(T45b): ATT&CK 전술·기법 후보, 통신 방향별 위험 호스트, 주요 알림 묶음.
 * 값은 모두 같은 overview 응답에서 오고(따로 부르지 않는다) 각 수는 눌러서 가는 인시던트 목록의 건수와 같다.
 * 새 필드가 없는 응답은 빈 값으로 그린다.
 */

const ROW_LINK =
  'rounded px-1 py-1 text-xs transition hover:bg-slate-800/40 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70';
const EMPTY_TEXT = 'px-2 py-4 text-center text-xs text-slate-400';
const SUBHEAD = 'text-[11px] font-semibold text-slate-400';

export const ATTACK_NOTE_TITLE =
  '리포트의 관련 ATT&CK 기법 후보를 센 값입니다. 공격으로 확정된 것이 아니라 가설입니다. 한 인시던트가 여러 전술·기법에 들어갈 수 있어 합은 인시던트 수와 다릅니다.';
export const TOP_HOSTS_NOTE_TITLE =
  '미종결 High, Medium, Low 건수가 많은 순서입니다. 위험 점수를 새로 매긴 값이 아닙니다. 전체 건수에는 종결도 들어갑니다.';
export const MASKED_RANGE_NOTE = '가려진 주소(A.B.*.*)는 호스트 하나가 아니라 그 대역의 호스트를 묶은 줄입니다.';
export const TOP_THREADS_NOTE_TITLE =
  '같은 Slack 스레드로 묶인 알림입니다. 공격으로 확정된 묶음이 아닙니다. 줄을 누르면 기간과 상관없이 묶음 전체를 표시합니다.';
export const THREAD_COUNT_TITLE =
  '기간 내는 지금 기간·수집원·캡처 조건 안의 인시던트 수이고, 전체는 그 알림 묶음 전체의 인시던트 수입니다.';

type ListQuery = (extra: Record<string, string>) => string;

export function ThreatPanels({ overview, listQuery }: { overview: DashboardOverviewResponse; listQuery: ListQuery }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <AttackPanel overview={overview} listQuery={listQuery} />
      <TopHostsPanel overview={overview} listQuery={listQuery} />
      <TopThreadsPanel overview={overview} />
    </div>
  );
}

/* ───────────────────────── ATT&CK 전술·기법 후보 ───────────────────────── */

function AttackPanel({ overview, listQuery }: { overview: DashboardOverviewResponse; listQuery: ListQuery }) {
  const attack = overview.attack;
  const tactics = attack?.tactics ?? [];
  const techniques = attack?.techniques ?? [];
  const more = (attack?.techniqueCount ?? 0) - techniques.length;
  const maxTactic = tactics.reduce((m, t) => Math.max(m, t.count), 0);
  return (
    <section className="soc-card min-w-0 space-y-3 p-4" aria-label={'ATT&CK 전술·기법 후보'}>
      <PanelHeader
        icon={Crosshair}
        title={'ATT&CK 전술·기법 후보'}
        note={`확정이 아닌 가설 · 후보가 있는 인시던트 ${formatNumber(attack?.incidentsWithCandidates ?? 0)}건`}
        noteTitle={ATTACK_NOTE_TITLE}
      />
      {tactics.length === 0 && techniques.length === 0 ? (
        <p className={EMPTY_TEXT} data-empty="attack">
          이 조건의 인시던트에는 ATT&amp;CK 기법 후보가 없습니다.
        </p>
      ) : (
        <>
          {tactics.length > 0 && (
            <div className="space-y-1">
              <h3 className={SUBHEAD}>전술</h3>
              <ul aria-label={'ATT&CK 전술 후보'}>
                {tactics.map((t) => {
                  const label = lookupLabel('attackTactic', t.tactic);
                  return (
                    <li key={t.tactic}>
                      <Link
                        to={`/incidents?${listQuery({ attack: t.tactic })}`}
                        className={`grid grid-cols-[minmax(0,7rem)_minmax(0,1fr)_auto] items-center gap-2 ${ROW_LINK}`}
                        title="이 전술이 후보에 있는 인시던트 목록으로 갑니다(지금 조건 유지)"
                        data-attack-tactic={t.tactic}
                      >
                        {label.known ? (
                          <span className="min-w-0 truncate text-slate-100">{label.text}</span>
                        ) : (
                          <span className="min-w-0 truncate font-mono text-slate-400" data-raw="">
                            {t.tactic}
                          </span>
                        )}
                        <span aria-hidden="true">
                          <SvgProgressBar value={t.count} max={maxTactic} tone="cyan" />
                        </span>
                        <span className="whitespace-nowrap tabular-nums text-slate-200">{formatNumber(t.count)}건</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          {techniques.length > 0 && (
            <div className="space-y-1">
              <h3 className={SUBHEAD}>기법</h3>
              <ul aria-label={'ATT&CK 기법 후보'}>
                {techniques.map((t) => (
                  <li key={t.attackId}>
                    <Link
                      to={`/incidents?${listQuery({ attack: t.attackId })}`}
                      className={`flex min-w-0 items-baseline gap-2 ${ROW_LINK}`}
                      title="이 기법이 후보에 있는 인시던트 목록으로 갑니다(지금 조건 유지)"
                      data-attack-technique={t.attackId}
                    >
                      <span className="shrink-0 font-mono text-slate-100">{t.attackId}</span>
                      <span className="min-w-0 flex-1 truncate text-slate-300" title={t.name ?? undefined} data-raw="">
                        {t.name ?? ''}
                      </span>
                      <span className="shrink-0 whitespace-nowrap tabular-nums text-slate-200">{formatNumber(t.count)}건</span>
                    </Link>
                  </li>
                ))}
              </ul>
              {more > 0 && (
                <p className="px-1 text-[11px] text-slate-400" data-attack-more="">
                  외 {formatNumber(more)}개
                </p>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}

/* ───────────────────────── 위험 호스트 상위 5 ───────────────────────── */

function PriorityCount({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <span className={`whitespace-nowrap tabular-nums ${value > 0 ? tone : 'text-slate-500'}`}>
      {label} {formatNumber(value)}
    </span>
  );
}

function HostRow({
  row,
  direction,
  anchor,
  listQuery,
}: {
  row: TopHostRow;
  direction: 'originator' | 'responder';
  anchor: string;
  listQuery: ListQuery;
}) {
  const body = (
    <>
      <span className="min-w-0 break-all font-mono text-slate-100">{row.hostIp}</span>
      <span className="flex flex-wrap items-center gap-x-2 text-[11px]">
        <PriorityCount label={labelText('priority', 'high')} value={row.high} tone="text-rose-200" />
        <PriorityCount label={labelText('priority', 'medium')} value={row.medium} tone="text-slate-50" />
        <PriorityCount label={labelText('priority', 'low')} value={row.low} tone="text-slate-400" />
        <span className="whitespace-nowrap tabular-nums text-slate-300">전체 {formatNumber(row.total)}건</span>
      </span>
      <span
        className="ml-auto whitespace-nowrap text-[11px] tabular-nums text-slate-400"
        title={`마지막 탐지 시각 ${formatDateTime(row.lastDetectedAt)}`}
      >
        {formatCompactDateTime(row.lastDetectedAt, anchor)}
      </span>
    </>
  );
  const layout = 'flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5';
  // 큐 hostIp 조건은 온전한 IPv4와 가려진 IPv4(A.B.*.*)만 받는다. 그 밖의 값은 링크 없이 글로 둔다
  if (hostIpKind(row.hostIp) === null) {
    return (
      <div className={`${layout} px-1 py-1 text-xs`} data-host-row={direction}>
        {body}
      </div>
    );
  }
  return (
    <Link
      to={`/incidents?${listQuery({ role: direction, hostIp: row.hostIp })}`}
      className={`${layout} ${ROW_LINK}`}
      title="이 호스트의 인시던트 목록으로 갑니다(지금 조건 유지)"
      data-host-row={direction}
    >
      {body}
    </Link>
  );
}

function TopHostsPanel({ overview, listQuery }: { overview: DashboardOverviewResponse; listQuery: ListQuery }) {
  const groups = (['originator', 'responder'] as const).map((direction) => ({
    direction,
    label: labelText('hostRole', direction),
    rows: overview.topHosts?.[direction] ?? [],
  }));
  const empty = groups.every((g) => g.rows.length === 0);
  return (
    <section className="soc-card min-w-0 space-y-3 p-4" aria-label="위험 호스트 상위 5">
      <PanelHeader icon={Network} title="위험 호스트 상위 5" note="미종결 우선순위 건수 순" noteTitle={TOP_HOSTS_NOTE_TITLE} />
      {overview.maskedView && !empty && (
        <p className="text-[11px] text-slate-400" data-masked-range-note="">
          {MASKED_RANGE_NOTE}
        </p>
      )}
      {empty ? (
        <p className={EMPTY_TEXT} data-empty="hosts">
          이 조건에는 통신 방향이 출발지나 목적지인 인시던트가 없습니다.
        </p>
      ) : (
        groups.map((g) => (
          <div key={g.direction} className="space-y-1">
            <h3 className={SUBHEAD}>{g.label}</h3>
            {g.rows.length === 0 ? (
              <p className="px-1 text-xs text-slate-500">없음</p>
            ) : (
              <ul aria-label={`${g.label} 위험 호스트`}>
                {g.rows.map((row) => (
                  <li key={row.hostIp}>
                    <HostRow row={row} direction={g.direction} anchor={overview.anchor} listQuery={listQuery} />
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))
      )}
    </section>
  );
}

/* ───────────────────────── 주요 알림 묶음 ───────────────────────── */

/** 건수 글: 기간 내와 전체가 다르면 둘 다, 같으면 묶음 건수 하나 */
export function threadCountText(row: Pick<TopThreadRow, 'periodIncidentCount' | 'totalMemberCount'>): string {
  return row.periodIncidentCount !== row.totalMemberCount
    ? `기간 내 ${formatNumber(row.periodIncidentCount)}건 · 전체 ${formatNumber(row.totalMemberCount)}건`
    : `묶음 ${formatNumber(row.totalMemberCount)}건`;
}

function TopThreadsPanel({ overview }: { overview: DashboardOverviewResponse }) {
  const threads = overview.topThreads ?? [];
  return (
    <section className="soc-card min-w-0 space-y-3 p-4" aria-label="주요 알림 묶음">
      <PanelHeader icon={MessagesSquare} title="주요 알림 묶음" note="Slack 스레드로 묶인 알림" noteTitle={TOP_THREADS_NOTE_TITLE} />
      {overview.topThreadsOmitted ? (
        <p className={EMPTY_TEXT} data-threads-omitted="">
          알림 묶음이 많아 묶음 계산을 생략했습니다. 기간이나 수집원을 좁혀 보세요.
        </p>
      ) : threads.length === 0 ? (
        <p className={EMPTY_TEXT} data-empty="threads">
          이 조건의 인시던트가 든 알림 묶음이 없습니다.
        </p>
      ) : (
        <ul aria-label="주요 알림 묶음 목록">
          {threads.map((t) => (
            <li key={t.headIncidentNo}>
              <Link
                // 묶음 전체를 본다: 현황판의 기간·수집원 조건을 유지하지 않는다
                to={`/incidents?period=all&thread=${t.headIncidentNo}`}
                className={`flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 ${ROW_LINK}`}
                title={`최초 알림 인시던트 #${t.headIncidentNo}의 알림 묶음 전체 보기(기간 조건을 유지하지 않습니다)`}
                data-thread-row=""
              >
                <span className="font-mono text-cyan-200">#{t.headIncidentNo}</span>
                {t.headHostIp ? (
                  <span className="min-w-0 break-all font-mono text-slate-100">{t.headHostIp}</span>
                ) : (
                  <span className="text-slate-500" title="최초 알림 인시던트가 지금 인시던트 목록에 없습니다">
                    -
                  </span>
                )}
                {t.headPickedBy && <DetectionModelName id={t.headPickedBy} className="min-w-0 break-words text-slate-300" />}
                <span className="ml-auto whitespace-nowrap tabular-nums text-slate-200" title={THREAD_COUNT_TITLE} data-thread-count="">
                  {threadCountText(t)}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
