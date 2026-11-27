import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowDown, ArrowUp, ArrowUpDown, Info, RotateCcw, Shuffle } from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../api/client';
import { hostsApi, type HostListParams } from '../api/hosts';
import { useAuth } from '../auth/AuthContext';
import { AppShell } from '../components/AppShell';
import { PeriodButtons, SourceField, sourceSelectChanges, sourceSelectValue, withoutLastDetected } from '../components/ConditionBar';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import { CriticalAssetBadge, DetectionModelName, SocBadge, type BadgeTone } from '../components/StatusBadge';
import type { QueueSource } from '../types/api';
import type { HostRiskItem, HostRiskResponse } from '../types/hosts';
import {
  DISPLAY_TIME_ZONE_LABEL,
  formatCompactDateTime,
  formatDateTime,
  formatNumber,
  formatRelativeTo,
} from '../utils/format';
import {
  HOSTS_DEFAULT_PERIOD,
  HOST_DEFAULT_DIR,
  HOST_DEFAULT_SORT,
  HOST_QUERY_MAX,
  HOST_SORT_KEYS,
  HOST_SORT_LABEL,
  hostIncidentsPath,
  parseHostSortDir,
  parseHostSortKey,
  type HostSortDir,
  type HostSortKey,
} from '../utils/hosts';
import { labelText } from '../utils/labels';
import {
  DEFAULT_PAGE_SIZE,
  customUrlChanges,
  parsePage,
  parsePageSize,
  parsePeriodSelection,
  parseSource,
  periodApiParams,
  periodScopeText,
  presetUrlChanges,
  type PeriodSelection,
} from '../utils/triage';
import { Pagination } from './IncidentQueuePage';

/** 전환 표지 글과 뜻(화면 용어: "전이"라고 쓰지 않는다) */
export const ROLE_TRANSITION_LABEL = '목적지 → 출발지 전환';
export const ROLE_TRANSITION_TOOLTIP =
  '먼저 목적지로 탐지된 호스트가 같은 캡처에서 뒤에 출발지로 탐지됐습니다. 침해 뒤 내부 확산일 수 있어 먼저 보라는 표시이며 확정이 아닙니다.';
/** 조회자 안내: 가려진 주소 한 줄의 단위 */
export const MASKED_RANGE_NOTICE =
  '주소 한 줄은 호스트 하나가 아니라 같은 대역(A.B.*.*)의 호스트 전부입니다. 대역 단위로는 방향 전환을 판정하지 않습니다.';

/** 받은 값과 그 조건 키·받은 시각(T42 규칙) */
interface Loaded {
  condKey: string;
  res: HostRiskResponse;
  loadedAt: string;
}

/** 줄 링크가 유지할 지금 조건 */
interface LinkCond {
  sel: PeriodSelection;
  source: string | null;
  captureId: string | null;
}

export function HostsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  /** 조회자: 주소가 대역으로 가려지고 전환 거르기·표지를 두지 않는다 */
  const masked = Boolean(user?.maskedView) || user?.role === 'VIEWER';

  const [loaded, setLoaded] = useState<Loaded | null>(null);
  /** 조건 줄의 수집원 목록(마지막 성공 값, 조건과 상관없이) */
  const [barSources, setBarSources] = useState<QueueSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<{ condKey: string; notice: ErrorNotice } | null>(null);
  /** 늦게 온 앞 요청의 응답을 버리기 위한 요청 순번 */
  const seq = useRef(0);

  // URL이 상태의 원본이다
  const sel = parsePeriodSelection(searchParams, HOSTS_DEFAULT_PERIOD);
  const period = sel.period;
  const rangeStart = sel.range?.start;
  const rangeEnd = sel.range?.end;
  const source = parseSource(searchParams.get('source'));
  const captureId = searchParams.get('captureId') || null;
  const sortKey = parseHostSortKey(searchParams.get('sort'));
  const sortDir = parseHostSortDir(searchParams.get('dir'), sortKey);
  const q = (searchParams.get('q') ?? '').trim().slice(0, HOST_QUERY_MAX);
  const transitionInUrl = searchParams.get('roleTransitionOnly') === 'true';
  // 조회자는 전환만 보기를 서버에 보내지 않는다(보내면 원인을 알 수 없는 빈 목록이 된다)
  const transitionOnly = transitionInUrl && !masked;
  const page = parsePage(searchParams.get('page'));
  const size = parsePageSize(searchParams.get('size'));

  // 분석가가 준 링크의 roleTransitionOnly는 조회자 화면에서 URL에서도 뺀다
  const hasTransitionParam = searchParams.has('roleTransitionOnly');
  useEffect(() => {
    if (masked && hasTransitionParam) {
      const next = new URLSearchParams(searchParams);
      next.delete('roleTransitionOnly');
      setSearchParams(next, { replace: true });
    }
  }, [masked, hasTransitionParam, searchParams, setSearchParams]);

  const apiParams = useMemo<HostListParams>(
    () => ({
      // 화면 기본 기간(7일)과 서버 기본(24시간)이 달라 period를 늘 보낸다
      ...periodApiParams({ period, range: rangeStart && rangeEnd ? { start: rangeStart, end: rangeEnd } : null }),
      source: captureId ? undefined : (source ?? undefined),
      captureId: captureId ?? undefined,
      sort: sortKey,
      dir: sortDir,
      q: q || undefined,
      roleTransitionOnly: transitionOnly ? 'true' : undefined,
      page: String(page),
      size: String(size),
    }),
    [period, rangeStart, rangeEnd, source, captureId, sortKey, sortDir, q, transitionOnly, page, size],
  );
  const condKey = JSON.stringify(apiParams);

  const loadHosts = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const res = await hostsApi.list(apiParams);
      if (my !== seq.current) return;
      setLoaded({ condKey, res, loadedAt: new Date().toISOString() });
      setBarSources(res.sources ?? []);
      setFailure(null);
    } catch (err) {
      if (my !== seq.current) return;
      setFailure({ condKey, notice: errorNotice(err, '호스트 위험도 목록을 불러오지 못했습니다.') });
    } finally {
      if (my === seq.current) setLoading(false);
    }
    // apiParams는 condKey와 같이 바뀐다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [condKey]);

  useEffect(() => {
    void loadHosts();
  }, [loadHosts]);

  function updateParams(changes: Record<string, string | null>, opts: { keepPage?: boolean } = {}) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!opts.keepPage && !('page' in changes)) next.delete('page');
    setSearchParams(next);
  }

  // 검색어 입력(적용을 눌러야 조건이 된다)
  const [draft, setDraft] = useState(q);
  useEffect(() => {
    setDraft(q);
  }, [q]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    updateParams({ q: draft.trim() || null });
  }

  function sortChanges(key: HostSortKey, dir: HostSortDir): Record<string, string | null> {
    return {
      sort: key === HOST_DEFAULT_SORT ? null : key,
      dir: dir === HOST_DEFAULT_DIR[key] ? null : dir,
    };
  }

  function handleSort(key: HostSortKey) {
    const dir: HostSortDir = key === sortKey ? (sortDir === 'asc' ? 'desc' : 'asc') : HOST_DEFAULT_DIR[key];
    updateParams(sortChanges(key, dir));
  }

  // T42: 지금 조건으로 받은 값만 그린다. 실패를 0건·빈 목록으로 그리지 않는다
  const current = loaded !== null && loaded.condKey === condKey ? loaded : null;
  const data = current?.res ?? null;
  const failed = failure !== null && failure.condKey === condKey ? failure.notice : null;
  /** 같은 조건의 값을 남긴 채 다시 읽기가 실패한 상태(최신 값이 아니다) */
  const stale = failed !== null && current !== null;

  const scope = periodScopeText(sel, data?.anchor);
  const linkCond: LinkCond = { sel, source, captureId };
  const unit = masked ? '대역' : '호스트';
  const anyFilter = q !== '' || transitionOnly;

  return (
    <AppShell title="호스트 위험도">
      <div className="space-y-4">
        <section className="soc-card space-y-2.5 px-3 py-2.5" aria-label="보기 조건">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <PeriodButtons
              value={period}
              range={sel.range}
              onChange={(p) => updateParams(presetUrlChanges(p, HOSTS_DEFAULT_PERIOD))}
              onApplyRange={(r) => updateParams(customUrlChanges(r))}
              current={{ periodStart: data?.periodStart, periodEnd: data?.periodEnd, anchor: data?.anchor }}
            />
            <SourceField
              id="hosts-source"
              sources={withoutLastDetected(barSources)}
              value={sourceSelectValue(source, captureId)}
              onChange={(v) => updateParams(sourceSelectChanges(v))}
            />
            <div className="ml-auto flex flex-wrap gap-x-3 gap-y-1 text-xs tabular-nums text-slate-400">
              {data && (
                <span data-testid="hosts-anchor">
                  {data.snapshot ? (
                    <>
                      기준 시각 <span className="text-slate-200">{formatDateTime(data.anchor)}</span> {DISPLAY_TIME_ZONE_LABEL}
                    </>
                  ) : (
                    '기준 시각: 현재'
                  )}
                </span>
              )}
              <span data-testid="hosts-total">
                {scope} {unit} {data ? `${formatNumber(data.total)}개` : '-'}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap items-end gap-x-3 gap-y-2">
            <form onSubmit={handleSearch} className="min-w-0 flex-1 basis-full sm:basis-auto sm:flex-none">
              <label htmlFor="hosts-q" className="mb-1 block text-[11px] font-medium text-slate-400">
                호스트 주소·이름·계정 검색
              </label>
              <div className="flex gap-1.5">
                <input
                  id="hosts-q"
                  type="text"
                  value={draft}
                  maxLength={HOST_QUERY_MAX}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="주소, 호스트 이름 또는 계정"
                  className="soc-input min-w-0 py-1.5 text-xs sm:w-64"
                />
                <button type="submit" className="soc-btn-secondary shrink-0 px-3 py-1.5 text-xs">
                  적용
                </button>
              </div>
            </form>
            {!masked && (
              <label
                className="flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700/80 bg-[#090f1d] px-3 py-1.5 text-xs text-slate-200"
                title={ROLE_TRANSITION_TOOLTIP}
              >
                <input
                  type="checkbox"
                  checked={transitionOnly}
                  onChange={(e) => updateParams({ roleTransitionOnly: e.target.checked ? 'true' : null })}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-cyan-400 focus:ring-cyan-500/30"
                />
                <span>{ROLE_TRANSITION_LABEL}만</span>
              </label>
            )}
            {/* 좁은 화면에는 표 머리글이 없어 정렬을 여기서 고른다 */}
            <label className="flex items-center gap-1.5 text-xs text-slate-400 md:hidden">
              <span>정렬</span>
              <select
                value={sortKey}
                onChange={(e) => {
                  const key = parseHostSortKey(e.target.value);
                  updateParams(sortChanges(key, HOST_DEFAULT_DIR[key]));
                }}
                className="soc-select py-1 pl-2 pr-7 text-xs"
                aria-label="정렬 기준"
              >
                {HOST_SORT_KEYS.map((k) => (
                  <option key={k} value={k}>
                    {HOST_SORT_LABEL[k]}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </section>

        {masked && (
          <p role="note" className="flex items-start gap-1.5 text-xs text-slate-400" data-testid="hosts-range-notice">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            {MASKED_RANGE_NOTICE}
          </p>
        )}

        {failed && stale && (
          <StaleNotice notice={failed} loadedAt={current?.loadedAt ?? null} loading={loading} onRetry={() => void loadHosts()} />
        )}
        {failed && !stale && (
          <ErrorAlert message={failed.message} rateLimited={failed.rateLimited} onRetry={() => void loadHosts()} />
        )}

        {!data ? (
          loading ? <LoadingPanel label="호스트 위험도 목록을 불러오는 중..." /> : null
        ) : (
          <div className="soc-card overflow-hidden">
            {data.items.length === 0 ? (
              <EmptyHosts
                unit={unit}
                scope={scope}
                anyFilter={anyFilter}
                allPeriod={period === 'all'}
                onAllPeriod={() => updateParams(presetUrlChanges('all', HOSTS_DEFAULT_PERIOD))}
                onClear={() => updateParams({ q: null, roleTransitionOnly: null })}
              />
            ) : (
              <>
                <HostTable
                  rows={data.items}
                  masked={masked}
                  anchor={data.anchor}
                  cond={linkCond}
                  sortKey={sortKey}
                  sortDir={sortDir}
                  onSort={handleSort}
                />
                <HostMobileList rows={data.items} masked={masked} anchor={data.anchor} cond={linkCond} />
              </>
            )}
            <Pagination
              total={data.total}
              page={data.page}
              pageCount={data.pageCount}
              pageSize={data.size}
              onPage={(p) => updateParams({ page: p === 1 ? null : String(p) }, { keepPage: true })}
              onSize={(s) => updateParams({ size: s === DEFAULT_PAGE_SIZE ? null : String(s) })}
            />
          </div>
        )}
      </div>
    </AppShell>
  );
}

/* ───────────────────────── 빈 결과 ───────────────────────── */

function EmptyHosts({
  unit,
  scope,
  anyFilter,
  allPeriod,
  onAllPeriod,
  onClear,
}: {
  unit: string;
  scope: string;
  anyFilter: boolean;
  allPeriod: boolean;
  onAllPeriod: () => void;
  onClear: () => void;
}) {
  // 조사까지 붙인 주어("호스트가" / "대역이")
  const subject = unit === '대역' ? '대역이' : `${unit}가`;
  return (
    <div className="space-y-2 px-4 py-12 text-center text-sm text-slate-300" data-empty={anyFilter ? 'filter' : 'none'}>
      <p>
        {anyFilter
          ? `검색·필터 조건에 맞는 ${subject} 없습니다.`
          : `${scope} 동안 인시던트가 탐지된 ${subject} 없습니다.`}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-2">
        {anyFilter && (
          <button type="button" onClick={onClear} className="soc-btn-secondary px-3 py-1.5 text-xs">
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            검색·필터 지우기
          </button>
        )}
        {!allPeriod && (
          <button type="button" onClick={onAllPeriod} className="soc-btn-secondary px-3 py-1.5 text-xs">
            기간: 전체로 보기
          </button>
        )}
      </div>
    </div>
  );
}

/* ───────────────────────── 줄의 조각 ───────────────────────── */

const PRIORITY_CHIPS: readonly { key: 'high' | 'medium' | 'low'; tone: BadgeTone }[] = [
  { key: 'high', tone: 'danger' },
  { key: 'medium', tone: 'emphasis' },
  { key: 'low', tone: 'muted' },
];

/**
 * T52 중요 자산 표지(우선순위 건수 옆). 분석가·관리자 줄은 그 호스트, 조회자 줄은 대역 안의 호스트 하나라도 중요 자산이면 붙는다.
 * 줄은 우선순위 하나가 아니라 수의 묶음이라 올림 글은 없다
 */
function HostCriticalBadge({ item, masked }: { item: HostRiskItem; masked: boolean }) {
  if (!item.assetCritical) return null;
  return <CriticalAssetBadge name={item.criticalAssetName} band={masked} masked={masked} />;
}

/** 미종결 우선순위별 건수. 색은 우선순위 배지와 같고 0은 흐리게 둔다 */
function PriorityCounts({ item }: { item: HostRiskItem }) {
  return (
    <span className="inline-flex items-center gap-1" data-priority-counts="">
      {PRIORITY_CHIPS.map(({ key, tone }) => {
        const count = item[key];
        const label = labelText('priority', key);
        return (
          <SocBadge key={key} tone={count > 0 ? tone : 'muted'} title={`미종결 ${label} ${formatNumber(count)}건`}>
            <span className={count > 0 ? '' : 'text-slate-600'}>
              {label} <span className="tabular-nums">{formatNumber(count)}</span>
            </span>
          </SocBadge>
        );
      })}
    </span>
  );
}

/** 앞 값 하나와 "외 N". 전체(받은 5개까지)와 남은 수는 툴팁에 둔다 */
function FirstAndMore({
  values,
  total,
  className,
  testAttr,
}: {
  values: string[];
  total: number;
  className: string;
  testAttr: 'names' | 'accounts';
}) {
  if (values.length === 0) {
    return <span className="text-slate-600">-</span>;
  }
  const more = total - 1;
  const hidden = total - values.length;
  const title = `${values.join(', ')}${hidden > 0 ? ` 외 ${formatNumber(hidden)}개` : ''}`;
  return (
    <span className={`inline-flex min-w-0 max-w-full items-baseline gap-1 ${className}`} title={title} data-host-list={testAttr}>
      <span className="min-w-0 truncate font-mono">{values[0]}</span>
      {more > 0 && <span className="shrink-0 text-slate-500">외 {formatNumber(more)}</span>}
    </span>
  );
}

/** 탐지 모델 표시 이름(건수 많은 순). 표(compact)는 한 줄에 첫 모델과 "외 N", 카드는 둘까지 보인다 */
function ModelList({ models, compact = false }: { models: string[]; compact?: boolean }) {
  if (models.length === 0) {
    return <span className="text-slate-600">-</span>;
  }
  const shown = models.slice(0, compact ? 1 : 2);
  const rest = models.slice(shown.length);
  return (
    <span className={`inline-flex items-baseline gap-x-1.5 gap-y-0.5 ${compact ? 'whitespace-nowrap' : 'flex-wrap'}`}>
      {shown.map((id) => (
        <DetectionModelName key={id} id={id} />
      ))}
      {rest.length > 0 && (
        <span className="text-slate-500" title={modelNames(rest)}>
          외 {formatNumber(rest.length)}
        </span>
      )}
    </span>
  );
}

function modelNames(ids: string[]): string {
  return ids.map((id) => labelText('detectionModel', id)).join(', ');
}

/** 좁은 폭에서 숨긴 열(세션 수·탐지 모델)의 값을 줄 툴팁에 둔다 */
function hiddenInfoTitle(item: HostRiskItem): string {
  return `세션 ${formatNumber(item.connections)}건 · 탐지 모델 ${item.models.length > 0 ? modelNames(item.models) : '-'}`;
}

function TransitionBadge() {
  return (
    <SocBadge tone="attention" title={ROLE_TRANSITION_TOOLTIP}>
      <Shuffle className="h-3 w-3" aria-hidden="true" />
      {ROLE_TRANSITION_LABEL}
    </SocBadge>
  );
}

function linkLabel(item: HostRiskItem, masked: boolean): string {
  return `${masked ? '대역' : '호스트'} ${item.hostIp}의 인시던트 ${formatNumber(item.incidents)}건 보기`;
}

/* ───────────────────────── 표(넓은 화면) ───────────────────────── */

function HostSortHeader({
  column,
  label,
  sortKey,
  sortDir,
  onSort,
  align = 'left',
  className = '',
}: {
  column: HostSortKey;
  label: string;
  sortKey: HostSortKey;
  sortDir: HostSortDir;
  onSort: (key: HostSortKey) => void;
  align?: 'left' | 'right';
  className?: string;
}) {
  const active = column === sortKey;
  const Icon = !active ? ArrowUpDown : sortDir === 'asc' ? ArrowUp : ArrowDown;
  const dirText = sortDir === 'asc' ? '오름차순' : '내림차순';
  return (
    <th
      scope="col"
      aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`soc-th-compact ${align === 'right' ? 'text-right' : ''} ${className}`}
    >
      <button
        type="button"
        onClick={() => onSort(column)}
        className={`inline-flex items-center gap-1 rounded hover:text-slate-100 ${active ? 'text-slate-100' : ''}`}
        aria-label={`${HOST_SORT_LABEL[column]} 기준 정렬${active ? `, 지금 ${dirText}` : ''}`}
      >
        {label}
        <Icon className={`h-3 w-3 ${active ? 'text-cyan-300' : 'text-slate-600'}`} aria-hidden="true" />
      </button>
    </th>
  );
}

function HostTable({
  rows,
  masked,
  anchor,
  cond,
  sortKey,
  sortDir,
  onSort,
}: {
  rows: HostRiskItem[];
  masked: boolean;
  anchor: string | null;
  cond: LinkCond;
  sortKey: HostSortKey;
  sortDir: HostSortDir;
  onSort: (key: HostSortKey) => void;
}) {
  const navigate = useNavigate();

  function open(e: React.MouseEvent<HTMLTableRowElement>, url: string) {
    // 글자를 끌어 고른 경우(주소 복사 등)는 이동하지 않는다
    const selection = window.getSelection?.();
    if (selection && selection.toString().length > 0) return;
    if (e.ctrlKey || e.metaKey) {
      window.open(url, '_blank', 'noopener');
      return;
    }
    navigate(url);
  }

  const headerProps = { sortKey, sortDir, onSort };
  // 1536px(2xl) 미만에서는 세션 수·탐지 모델 열을 숨겨 1280px에서 표가 한 화면에 들어오게 한다(값은 줄 툴팁과 인시던트 목록에 있다).
  // 지금 정렬 기준인 열은 숨기지 않는다(인시던트 목록 표와 같은 규칙).
  const connectionsCell = sortKey === 'connections' ? '' : 'hidden 2xl:table-cell';
  const modelsCell = 'hidden 2xl:table-cell';
  return (
    <div className="hidden overflow-x-auto md:block" data-hosts-table-wrap="">
      <table className="w-full border-collapse text-left">
        <caption className="sr-only">
          호스트 위험도 목록. 주소 링크나 줄을 누르거나 줄에서 Enter 키를 누르면 그 호스트의 인시던트 목록으로 갑니다.
        </caption>
        <thead>
          <tr>
            <HostSortHeader column="hostIp" label={masked ? '호스트 대역' : '호스트'} {...headerProps} />
            <HostSortHeader column="risk" label="미종결 우선순위" {...headerProps} />
            {/* 먼저 볼 호스트 표시라 우선순위 바로 옆에 둔다(좁은 폭에서도 가려지지 않게) */}
            {!masked && (
              <th scope="col" className="soc-th-compact" title={ROLE_TRANSITION_TOOLTIP}>
                방향 전환
              </th>
            )}
            <HostSortHeader column="incidents" label="인시던트" align="right" {...headerProps} />
            <HostSortHeader column="connections" label="세션 수" align="right" className={connectionsCell} {...headerProps} />
            <th scope="col" className={`soc-th-compact ${modelsCell}`}>
              탐지 모델
            </th>
            <th scope="col" className="soc-th-compact">
              관측 계정
            </th>
            <HostSortHeader column="lastDetected" label="마지막 탐지" {...headerProps} />
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => {
            const url = hostIncidentsPath(item.hostIp, cond);
            return (
              <tr
                key={item.hostIp}
                title={hiddenInfoTitle(item)}
                tabIndex={url ? 0 : undefined}
                onClick={url ? (e) => open(e, url) : undefined}
                onKeyDown={
                  url
                    ? (e) => {
                        if (e.key === 'Enter' && e.target === e.currentTarget) {
                          e.preventDefault();
                          navigate(url);
                        }
                      }
                    : undefined
                }
                className={`transition focus:outline-none ${
                  url
                    ? 'cursor-pointer hover:bg-slate-800/40 focus-visible:bg-slate-800/50 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-cyan-400/70'
                    : ''
                }`}
              >
                <td className="soc-td-compact">
                  {/* 주소는 줄이지 않는다(긴 IPv6도 그대로). 폭 제한은 호스트 이름에만 둔다 */}
                  <div className="flex items-baseline gap-1.5">
                    {url ? (
                      <Link
                        to={url}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={linkLabel(item, masked)}
                        className="shrink-0 font-mono font-semibold text-slate-100 hover:text-cyan-200 hover:underline focus:outline-none focus-visible:underline"
                      >
                        {item.hostIp}
                      </Link>
                    ) : (
                      <span className="shrink-0 font-mono font-semibold text-slate-100" data-host-no-link="">
                        {item.hostIp}
                      </span>
                    )}
                    <span className="inline-flex min-w-0 max-w-[5.5rem] 2xl:max-w-[13rem]">
                      <FirstAndMore
                        values={item.hostNames}
                        total={item.hostNameCount}
                        className="text-[11px] text-slate-400"
                        testAttr="names"
                      />
                    </span>
                  </div>
                </td>
                <td className="soc-td-compact">
                  <span className="inline-flex items-center gap-1">
                    <PriorityCounts item={item} />
                    <HostCriticalBadge item={item} masked={masked} />
                  </span>
                </td>
                {!masked && (
                  <td className="soc-td-compact">
                    {item.roleTransition ? <TransitionBadge /> : <span className="text-slate-600">-</span>}
                  </td>
                )}
                <td className="soc-td-compact soc-num text-slate-100">{formatNumber(item.incidents)}</td>
                <td className={`soc-td-compact soc-num text-slate-300 ${connectionsCell}`}>{formatNumber(item.connections)}</td>
                <td className={`soc-td-compact text-slate-300 ${modelsCell}`}>
                  <ModelList models={item.models} compact />
                </td>
                <td className="soc-td-compact">
                  <div className="max-w-[8rem] 2xl:max-w-[12rem]">
                    <FirstAndMore
                      values={item.accounts}
                      total={item.accountCount}
                      className="text-slate-200"
                      testAttr="accounts"
                    />
                  </div>
                </td>
                <td className="soc-td-compact tabular-nums text-slate-300" title={`마지막 탐지 ${formatDateTime(item.lastDetectedAt)}`}>
                  {item.lastDetectedAt ? (
                    formatCompactDateTime(item.lastDetectedAt, anchor)
                  ) : (
                    <span className="text-slate-600">-</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ───────────────────────── 카드(휴대폰) ───────────────────────── */

function HostMobileList({
  rows,
  masked,
  anchor,
  cond,
}: {
  rows: HostRiskItem[];
  masked: boolean;
  anchor: string | null;
  cond: LinkCond;
}) {
  return (
    <ul className="divide-y divide-slate-800/80 md:hidden" aria-label="호스트 위험도 목록">
      {rows.map((item) => {
        const url = hostIncidentsPath(item.hostIp, cond);
        const body = (
          <>
            <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
              <span className="break-all font-mono text-sm font-semibold text-slate-100">{item.hostIp}</span>
              <span className="min-w-0 flex-1 basis-24">
                <FirstAndMore
                  values={item.hostNames}
                  total={item.hostNameCount}
                  className="text-[11px] text-slate-400"
                  testAttr="names"
                />
              </span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
              <PriorityCounts item={item} />
              <HostCriticalBadge item={item} masked={masked} />
              {!masked && item.roleTransition && <TransitionBadge />}
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
              <span>
                인시던트 <span className="tabular-nums text-slate-100">{formatNumber(item.incidents)}건</span>
              </span>
              <span>
                세션 <span className="tabular-nums text-slate-300">{formatNumber(item.connections)}건</span>
              </span>
              <span title={`마지막 탐지 ${formatDateTime(item.lastDetectedAt)}`}>
                마지막 탐지{' '}
                <span className="tabular-nums text-slate-300">
                  {item.lastDetectedAt ? formatRelativeTo(item.lastDetectedAt, anchor) : '-'}
                </span>
              </span>
            </div>
            <div className="mt-1.5 flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1 text-xs text-slate-400">
              <span className="inline-flex flex-wrap items-baseline gap-x-1.5">
                <span className="text-[11px] text-slate-500">탐지 모델</span>
                <span className="text-slate-300">
                  <ModelList models={item.models} />
                </span>
              </span>
              <span className="inline-flex min-w-0 max-w-full items-baseline gap-x-1.5">
                <span className="shrink-0 text-[11px] text-slate-500">관측 계정</span>
                <FirstAndMore values={item.accounts} total={item.accountCount} className="text-slate-200" testAttr="accounts" />
              </span>
            </div>
          </>
        );
        return (
          <li key={item.hostIp}>
            {url ? (
              <Link
                to={url}
                aria-label={linkLabel(item, masked)}
                className="block px-3 py-2.5 transition hover:bg-slate-800/40 focus:outline-none focus-visible:bg-slate-800/50"
              >
                {body}
              </Link>
            ) : (
              <div className="px-3 py-2.5" data-host-no-link="">
                {body}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
