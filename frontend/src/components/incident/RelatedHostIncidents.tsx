import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../../api/client';
import { hostsApi } from '../../api/hosts';
import type { RelatedHostIncident, RelatedHostIncidentsResponse } from '../../types/hosts';
import { formatDateTime, formatNumber } from '../../utils/format';
import { hostAllIncidentsPath, relativeGapText } from '../../utils/hosts';
import { incidentPath } from '../../utils/incidentLink';
import { captureInfo, captureShortName } from '../../utils/labels';
import {
  CodeLabel,
  CriticalAssetBadge,
  DetectionModelName,
  IncidentStatusBadge,
  PriorityBadge,
  ResolutionBadge,
} from '../StatusBadge';

/** 불러오기 실패 안내(구역 안에만 보인다) */
export const RELATED_LOAD_FAILED_TEXT = '같은 호스트의 인시던트를 불러오지 못했습니다.';

/** 응답이 약속한 모양인지(모르는 응답을 0건으로 그리지 않는다) */
function isRelatedResponse(value: unknown): value is RelatedHostIncidentsResponse {
  const v = value as Partial<RelatedHostIncidentsResponse> | null;
  return v !== null && typeof v === 'object' && Array.isArray(v.items) && typeof v.total === 'number';
}

type State =
  | { key: string; status: 'loading'; data: RelatedHostIncidentsResponse | null }
  | { key: string; status: 'ok'; data: RelatedHostIncidentsResponse }
  | { key: string; status: 'error'; notice: ErrorNotice };

/**
 * 요약 탭 맨 아래 구역(T46): 같은 호스트(조회자는 같은 대역)의 다른 인시던트를 발생 시각이 가까운 것부터 최대 10건.
 * 상세와 따로 부른다(상세를 늦추지 않고, 실패해도 이 구역에만 보인다). reloadKey가 바뀌면(상세를 다시 불러오면) 다시 부른다.
 */
export function RelatedHostIncidents({
  jobId,
  queueRank,
  hostIp,
  eventStart,
  maskedView,
  reloadKey,
}: {
  jobId: number;
  queueRank: number;
  /** 이 인시던트의 호스트(조회자는 가려진 대역). 응답이 오기 전 제목에 쓴다 */
  hostIp: string;
  eventStart: string | null;
  maskedView: boolean;
  reloadKey: string | null;
}) {
  const key = `${jobId}|${queueRank}`;
  const [state, setState] = useState<State>({ key, status: 'loading', data: null });
  const seq = useRef(0);

  const load = useCallback(async () => {
    const my = ++seq.current;
    // 같은 인시던트를 다시 읽는 동안에는 앞 값을 남겨 두고, 다른 인시던트의 값은 남기지 않는다
    setState((prev) => ({ key, status: 'loading', data: prev.key === key && prev.status !== 'error' ? prev.data : null }));
    try {
      const res: unknown = await hostsApi.related(jobId, queueRank);
      if (my !== seq.current) return;
      if (!isRelatedResponse(res)) {
        setState({ key, status: 'error', notice: { message: RELATED_LOAD_FAILED_TEXT, rateLimited: false } });
        return;
      }
      setState({ key, status: 'ok', data: res });
    } catch (err) {
      if (my !== seq.current) return;
      setState({ key, status: 'error', notice: errorNotice(err, RELATED_LOAD_FAILED_TEXT) });
    }
  }, [key, jobId, queueRank]);

  useEffect(() => {
    void load();
  }, [load, reloadKey]);

  const current = state.key === key ? state : null;
  const data = current && current.status !== 'error' ? current.data : null;
  const shownHost = data?.hostIp ?? hostIp;
  const title = maskedView ? `같은 대역(${shownHost}) 인시던트` : '같은 호스트의 다른 인시던트';
  const allPath = data ? hostAllIncidentsPath(data.hostIp ?? hostIp) : null;

  return (
    <section aria-labelledby="summary-related" className="space-y-3 border-t border-slate-800 pt-4" data-related-host="">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h3 id="summary-related" className="text-sm font-semibold text-slate-100">
          {title}
        </h3>
        {data && (
          <span className="text-xs tabular-nums text-slate-400" data-testid="related-count">
            이 인시던트 말고 {formatNumber(data.total)}건
            {data.total > data.items.length && ` · 가까운 ${formatNumber(data.items.length)}건`}
          </span>
        )}
        {data && data.total > data.items.length && allPath && (
          <Link
            to={allPath}
            className="text-xs text-cyan-300 hover:text-cyan-200 hover:underline focus:outline-none focus-visible:underline"
            title="이 호스트의 전체 기간 인시던트 목록입니다. 이 인시던트도 들어 있습니다."
          >
            전체 보기
          </Link>
        )}
      </div>

      {current === null || (current.status === 'loading' && !data) ? (
        <p className="text-xs text-slate-400" data-related-state="loading">
          불러오는 중...
        </p>
      ) : current.status === 'error' ? (
        <div
          className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-amber-500/40 bg-amber-950/30 px-3 py-2 text-xs text-amber-100"
          data-related-state="error"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <span className="min-w-0 break-words">{current.notice.message}</span>
          <button
            type="button"
            onClick={() => void load()}
            aria-label="같은 호스트 인시던트 다시 시도"
            className="soc-btn-secondary ml-auto py-1 text-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            다시 시도
          </button>
        </div>
      ) : data && data.items.length === 0 ? (
        <p className="text-xs text-slate-400" data-related-state="empty">
          {maskedView ? '같은 대역에서 탐지된 다른 인시던트가 없습니다.' : '이 호스트에서 탐지된 다른 인시던트가 없습니다.'}
        </p>
      ) : (
        <ul className="divide-y divide-slate-800/80 rounded-lg border border-slate-800" data-related-state="ok">
          {(data?.items ?? []).map((item) => (
            <RelatedRow key={`${item.jobId}-${item.queueRank}`} item={item} selfEventStart={eventStart} maskedView={maskedView} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RelatedRow({
  item,
  selfEventStart,
  maskedView,
}: {
  item: RelatedHostIncident;
  selfEventStart: string | null;
  maskedView: boolean;
}) {
  const path = incidentPath(item);
  const gap = relativeGapText(item.eventStart, selfEventStart);
  const numberText = typeof item.incidentNo === 'number' ? `#${item.incidentNo}` : '상세 보기';
  const capture = captureInfo(item.captureId);
  return (
    <li className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-3 py-2 text-xs" data-related-row="">
      {path ? (
        <Link
          to={path}
          aria-label={
            typeof item.incidentNo === 'number' ? `인시던트 번호 ${item.incidentNo} 상세` : `인시던트 상세: ${item.hostIp}`
          }
          className="shrink-0 font-mono font-semibold tabular-nums text-cyan-200 hover:underline focus:outline-none focus-visible:underline"
        >
          {numberText}
        </Link>
      ) : (
        <span className="shrink-0 text-slate-500">-</span>
      )}
      <span className="tabular-nums text-slate-200" title="발생 시각">
        {formatDateTime(item.eventStart)}
      </span>
      {gap && (
        <span className="tabular-nums text-slate-400" title="이 인시던트의 발생 시각과 견준 앞뒤와 간격" data-related-gap="">
          {gap}
        </span>
      )}
      {maskedView && <span className="font-mono text-slate-400">{item.hostIp}</span>}
      <span className="text-slate-300">
        <CodeLabel dict="hostRole" value={item.zeekadRole} />
      </span>
      <PriorityBadge priority={item.priority} />
      {item.assetCritical && (
        <CriticalAssetBadge
          priority={item.priority}
          priorityBase={item.priorityBase}
          name={item.criticalAssetName}
          masked={maskedView}
        />
      )}
      <IncidentStatusBadge status={item.zeekadStatus} />
      <ResolutionBadge resolution={item.zeekadResolution} />
      <span className="text-slate-300">
        <DetectionModelName id={item.zeekadPickedBy} />
      </span>
      <span className="text-slate-400" title={capture.tooltip ? `${capture.text} · ${capture.tooltip}` : capture.text}>
        {captureShortName(item.captureId)}
      </span>
    </li>
  );
}
