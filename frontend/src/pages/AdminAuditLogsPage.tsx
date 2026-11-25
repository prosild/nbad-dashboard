import { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronUp, FileSearch, Filter } from 'lucide-react';
import { errorNotice, type ErrorNotice } from '../api/client';
import { adminApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import { CodeLabel, SocBadge } from '../components/StatusBadge';
import type { AdminAuditLogsResponse, AuditLog } from '../types/api';
import { formatDateTime } from '../utils/format';
import { labelText } from '../utils/labels';

/** 보안상 확인이 필요한 동작(실패·잠김·거부)만 주의 색으로 강조하고 나머지는 중립색 */
function isSecurityAttention(actionType: string): boolean {
  return actionType.includes('DENIED') || actionType.includes('LOCKED') || actionType.includes('FAILURE');
}

function AuditLogRow({ log }: { log: AuditLog }) {
  const [expanded, setExpanded] = useState(false);

  const tone = isSecurityAttention(log.actionType) ? 'attention' : 'neutral';

  return (
    <>
      <tr className="hover:bg-slate-800/35">
        <td className="soc-td whitespace-nowrap text-xs tabular-nums text-slate-300">
          {formatDateTime(log.occurredAt)}
        </td>
        <td className="soc-td text-xs">
          <div className="font-mono font-semibold text-slate-100">{log.actorUsername ?? '-'}</div>
          {log.actorRole && (
            <div className="text-[11px] text-slate-400">
              <CodeLabel dict="userRole" value={log.actorRole} />
            </div>
          )}
        </td>
        <td className="soc-td">
          <SocBadge tone={tone}>
            <CodeLabel dict="auditAction" value={log.actionType} />
          </SocBadge>
        </td>
        <td className="soc-td text-xs text-slate-300">
          <div className="font-mono">{log.targetCaptureId ?? '-'}</div>
          {log.targetIncidentId && (
            <div className="mt-0.5 break-all font-mono text-[11px] text-slate-400" data-raw="">
              {log.targetIncidentId}
            </div>
          )}
        </td>
        <td className="soc-td font-mono text-xs text-slate-400">{log.clientIp ?? '-'}</td>
        <td className="soc-td text-right text-xs">
          {log.detailJson ? (
            <button
              type="button"
              onClick={() => setExpanded((prev) => !prev)}
              className="soc-btn-secondary inline-flex py-1 px-2.5 text-xs"
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {expanded ? '접기' : '상세 보기'}
            </button>
          ) : (
            <span className="text-slate-500">-</span>
          )}
        </td>
      </tr>
      {expanded && log.detailJson && (
        <tr>
          <td colSpan={6} className="border-b border-slate-800 bg-[#080d1a] px-4 py-3">
            <pre
              className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300"
              data-raw=""
            >
              {log.detailJson}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

interface AuditQuery {
  actionType?: string;
  actorUsername?: string;
  limit?: number;
}

function auditKey(q: AuditQuery): string {
  return JSON.stringify([q.actionType ?? null, q.actorUsername ?? null, q.limit ?? null]);
}

export function AdminAuditLogsPage() {
  /** 마지막 성공 응답과 그 조건 키(T42). 지금 조건 = [조회]로 제출한 조건(입력 칸만 고친 값이 아니다) */
  const [loaded, setLoaded] = useState<{ condKey: string; res: AdminAuditLogsResponse; loadedAt: string } | null>(null);
  /** 동작 유형 선택지(조건과 상관없는 값): 마지막 성공 응답의 것 */
  const [actionTypes, setActionTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<{ condKey: string; notice: ErrorNotice } | null>(null);
  const [submitted, setSubmitted] = useState<AuditQuery>({ limit: 100 });
  const seq = useRef(0);

  const [actionType, setActionType] = useState('');
  const [actorUsername, setActorUsername] = useState('');
  const [limit, setLimit] = useState(100);

  const loadLogs = useCallback(async (params: AuditQuery) => {
    const my = ++seq.current;
    const condKey = auditKey(params);
    setSubmitted(params);
    setLoading(true);
    try {
      const res = await adminApi.listAuditLogs(params);
      if (my !== seq.current) return;
      setLoaded({ condKey, res, loadedAt: new Date().toISOString() });
      setActionTypes(res.actionTypes ?? []);
      setFailure(null);
    } catch (err) {
      if (my !== seq.current) return;
      setFailure({ condKey, notice: errorNotice(err, '감사 로그를 불러오지 못했습니다.') });
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLogs({ limit: 100 });
  }, [loadLogs]);

  const condKey = auditKey(submitted);
  const current = loaded !== null && loaded.condKey === condKey ? loaded : null;
  const data = current?.res ?? null;
  const failed = failure !== null && failure.condKey === condKey ? failure.notice : null;
  const stale = failed !== null && current !== null;

  function handleFilterSubmit(e: React.FormEvent) {
    e.preventDefault();
    void loadLogs({
      actionType: actionType || undefined,
      actorUsername: actorUsername.trim() || undefined,
      limit,
    });
  }

  return (
    <AppShell title="감사 로그">
      <div className="space-y-5">
        <section className="soc-card p-4">
          <form onSubmit={handleFilterSubmit} className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="audit-action-type" className="mb-1 block text-[11px] font-medium text-slate-400">
                동작 유형
              </label>
              <select
                id="audit-action-type"
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="soc-select text-xs"
              >
                <option value="">모든 유형</option>
                {actionTypes.map((type) => (
                  <option key={type} value={type}>
                    {labelText('auditAction', type)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="audit-actor" className="mb-1 block text-[11px] font-medium text-slate-400">
                사용자 아이디
              </label>
              <input
                id="audit-actor"
                type="text"
                value={actorUsername}
                onChange={(e) => setActorUsername(e.target.value)}
                placeholder="찾을 사용자 아이디"
                className="soc-input text-xs"
              />
            </div>

            <div>
              <label htmlFor="audit-limit" className="mb-1 block text-[11px] font-medium text-slate-400">
                조회 건수
              </label>
              <select
                id="audit-limit"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="soc-select text-xs tabular-nums"
              >
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={250}>250</option>
                <option value={500}>500</option>
              </select>
            </div>

            <button type="submit" className="soc-btn-primary py-2 text-xs">
              <Filter className="h-3.5 w-3.5" />
              조회
            </button>
          </form>
        </section>

        {/* T42: 다시 시도는 제출한 조건으로 다시 부른다(입력 칸만 고친 값이 아니다) */}
        {failed && stale && (
          <StaleNotice
            notice={failed}
            loadedAt={current?.loadedAt ?? null}
            loading={loading}
            onRetry={() => void loadLogs(submitted)}
          />
        )}
        {failed && !stale && (
          <ErrorAlert
            message={failed.message}
            rateLimited={failed.rateLimited}
            onRetry={() => void loadLogs(submitted)}
          />
        )}

        {!data ? (
          loading ? <LoadingPanel label="감사 로그를 불러오는 중..." /> : null
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 text-xs text-slate-400">
              <div className="flex items-center gap-2 font-semibold text-slate-200">
                <FileSearch className="h-4 w-4 text-slate-400" />
                감사 로그 ({data.logs.length}건)
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">발생 시각</th>
                    <th className="soc-th">사용자</th>
                    <th className="soc-th">동작 유형</th>
                    <th className="soc-th">대상 캡처 · 인시던트</th>
                    <th className="soc-th">접속 IP</th>
                    <th className="soc-th text-right">상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.logs ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                        조회된 감사 로그가 없습니다.
                      </td>
                    </tr>
                  ) : (
                    (data?.logs ?? []).map((log) => <AuditLogRow key={log.id} log={log} />)
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
