import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { AlertTriangle, ClipboardCheck, ExternalLink, Info } from 'lucide-react';
import { ApiError, errorNotice, type ErrorNotice } from '../api/client';
import { reviewsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { STALE_ACTION_BLOCKED, StaleNotice } from '../components/StaleNotice';
import { ReviewDecisionButtons } from '../components/incident/ReviewDecisionButtons';
import { CaptureName, CodeLabel, LookupText, ResumeStatusBadge, ReviewActionBadge } from '../components/StatusBadge';
import { useToast } from '../components/ToastContext';
import type { AnalystReviewItem, ReviewsApiResponse } from '../types/api';
import { incidentPath } from '../utils/incidentLink';
import { formatDateTime } from '../utils/format';
import { FREE_TEXT_MAX } from '../utils/freeText';
import { captureInfo, reviewReasonText } from '../utils/labels';
import {
  RESUME_DELAYED_LABEL,
  RESUME_DELAYED_TEXT,
  resumePhase,
  REVIEW_STATUS_RELATION,
  useNowMs,
} from '../utils/reviewResume';

function ReviewRowActions({
  item,
  onSubmitted,
  blockedReason,
}: {
  item: AnalystReviewItem;
  onSubmitted: () => Promise<void>;
  blockedReason: string | null;
}) {
  const { notify } = useToast();
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const targetJobId = item.reviewJobId ?? item.jobId;
  if (!targetJobId) {
    return <span className="text-xs text-slate-500">에스컬레이션 정보가 없어 결정할 수 없습니다</span>;
  }

  async function decide(action: 'confirm' | 'dismiss') {
    setSubmitting(true);
    try {
      const res = await reviewsApi.decide({
        jobId: targetJobId as number,
        incidentId: item.incidentId,
        action,
        note: note.trim() || undefined,
      });
      notify(res.message || '검토 결정을 저장했습니다.', 'success');
      setNote('');
      await onSubmitted();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '검토 결정을 저장하지 못했습니다.', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  const noteId = `review-note-${targetJobId}-${item.incidentId}`;
  return (
    <div className="min-w-[230px] space-y-2">
      <input
        id={noteId}
        type="text"
        aria-label={`${item.incidentId} 검토 메모`}
        maxLength={FREE_TEXT_MAX}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="검토 메모 (오탐 종결 때 필수)"
        className="soc-input py-1 text-xs"
      />
      <ReviewDecisionButtons
        note={note}
        noteInputId={noteId}
        submitting={submitting}
        onDecide={(action) => void decide(action)}
        compact
        idPrefix={item.incidentId}
        blockedReason={blockedReason}
      />
    </div>
  );
}

export function ReviewsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  /** 마지막 성공 응답과 그 조건 키(T42). 키가 지금 조건과 같을 때만 그린다 */
  const [loaded, setLoaded] = useState<{ condKey: string; res: ReviewsApiResponse; loadedAt: string } | null>(null);
  /** 조건과 상관없는 값(캡처 선택지·결정 가능 여부): 마지막 성공 응답의 것 */
  const [lastRes, setLastRes] = useState<ReviewsApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  /** 마지막 실패와 그 조건. 같은 조건의 다음 성공 때 지운다 */
  const [failure, setFailure] = useState<{ condKey: string; notice: ErrorNotice } | null>(null);
  /** 늦게 온 앞 요청의 응답을 버리기 위한 요청 순번 */
  const seq = useRef(0);
  const nowMs = useNowMs();

  const captureId = searchParams.get('captureId') ?? '';
  const pendingOnly = searchParams.get('pendingOnly') === 'true';
  const condKey = `${captureId}|${pendingOnly}`;

  const loadReviews = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const res = await reviewsApi.list(captureId || undefined, pendingOnly);
      if (my !== seq.current) return;
      setLoaded({ condKey, res, loadedAt: new Date().toISOString() });
      setLastRes(res);
      setFailure(null);
    } catch (err) {
      if (my !== seq.current) return;
      setFailure({ condKey, notice: errorNotice(err, '에스컬레이션 목록을 불러오지 못했습니다.') });
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [captureId, pendingOnly, condKey]);

  useEffect(() => {
    void loadReviews();
  }, [loadReviews]);

  function updateCapture(nextCapture: string) {
    const next = new URLSearchParams(searchParams);
    if (nextCapture) next.set('captureId', nextCapture);
    else next.delete('captureId');
    setSearchParams(next);
  }

  function togglePendingOnly(checked: boolean) {
    const next = new URLSearchParams(searchParams);
    if (checked) next.set('pendingOnly', 'true');
    else next.delete('pendingOnly');
    setSearchParams(next);
  }

  // T42: 지금 조건(캡처·대기만)으로 받은 값만 그린다. 실패를 "총 0건"·빈 목록으로 그리지 않는다
  const current = loaded !== null && loaded.condKey === condKey ? loaded : null;
  const data = current?.res ?? null;
  const failed = failure !== null && failure.condKey === condKey ? failure.notice : null;
  /** 같은 조건의 값을 남긴 채 다시 읽기가 실패한 상태. 이 동안 결정 버튼을 막는다 */
  const stale = failed !== null && current !== null;
  const canDecide = lastRes?.canDecideReview ?? false;

  return (
    <AppShell title="에스컬레이션">
      <div className="space-y-5">
        {lastRes && !lastRes.canDecideReview && (
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>읽기 전용 계정입니다. 검토 결정은 분석가 계정에서 할 수 있습니다.</span>
          </div>
        )}

        <p
          role="note"
          aria-label="에스컬레이션 결정과 상태"
          className="flex items-start gap-1.5 rounded border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-400"
        >
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          {REVIEW_STATUS_RELATION}
        </p>

        <section className="soc-card flex flex-wrap items-center justify-between gap-4 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label htmlFor="reviews-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
                캡처
              </label>
              <select
                id="reviews-capture"
                value={captureId}
                onChange={(e) => updateCapture(e.target.value)}
                className="soc-select text-xs"
              >
                <option value="">열람 허용 캡처 전체</option>
                {(lastRes?.allowedCaptures ?? []).map((cap) => {
                  const info = captureInfo(cap);
                  return (
                    <option key={cap} value={cap} title={info.tooltip}>
                      {info.text}
                    </option>
                  );
                })}
              </select>
            </div>

            <label className="mt-4 flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700/80 bg-[#090f1d] px-3 py-2 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={pendingOnly}
                onChange={(e) => togglePendingOnly(e.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-cyan-400 focus:ring-cyan-500/30"
              />
              <span>대기만 보기</span>
            </label>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <ClipboardCheck className="h-4 w-4 text-slate-400" />
            <span className="tabular-nums" data-testid="reviews-total">
              {data ? `총 ${data.reviews.length}건` : '총 -'}
            </span>
          </div>
        </section>

        {failed && stale && (
          <StaleNotice
            notice={failed}
            loadedAt={current?.loadedAt ?? null}
            loading={loading}
            onRetry={() => void loadReviews()}
          />
        )}
        {failed && !stale && (
          <ErrorAlert message={failed.message} rateLimited={failed.rateLimited} onRetry={() => void loadReviews()} />
        )}

        {!data ? (
          loading ? <LoadingPanel label="에스컬레이션 목록을 불러오는 중..." /> : null
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">캡처</th>
                    <th className="soc-th">인시던트 · 호스트</th>
                    <th className="soc-th">요청 사유</th>
                    <th className="soc-th">요청 시각</th>
                    <th className="soc-th">검토 결정 · 반영 상태</th>
                    <th className="soc-th">결정 · 상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.reviews ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                        대기 중인 에스컬레이션이 없습니다.
                      </td>
                    </tr>
                  ) : (
                    (data?.reviews ?? []).map((item) => {
                      const isPending = item.zeekadReviewAction === null || item.zeekadReviewAction === '';
                      const resumeFailed = item.zeekadReviewResumeFailed === true;
                      const resumed = item.zeekadReviewResumedAt !== null;
                      // T21: 반영 상태 이름은 서버 라벨(resumeStatusLabel)만 쓴다. 반영 지연은 결정 시각으로 계산하는 보조 표시.
                      const resumeText = item.resumeStatusLabel ?? '';
                      const phase = resumePhase(
                        {
                          reviewAction: item.zeekadReviewAction,
                          decidedAt: item.decidedAt,
                          resumedAt: item.zeekadReviewResumedAt,
                          resumeFailed: item.zeekadReviewResumeFailed,
                        },
                        nowMs,
                      );

                      return (
                        <tr key={`${item.reviewJobId ?? item.jobId}-${item.incidentId}`} className="hover:bg-slate-800/35">
                          <td
                            className="soc-td text-xs font-semibold text-slate-200"
                            title={`에스컬레이션 작업 ${item.reviewJobId ?? item.jobId ?? '-'}`}
                          >
                            <CaptureName id={item.captureId} />
                          </td>
                          <td className="soc-td text-xs">
                            <div className="flex flex-wrap items-baseline gap-x-2">
                              <span className="font-mono font-semibold text-slate-100">{item.hostIp ?? '-'}</span>
                              <CodeLabel dict="hostRole" value={item.zeekadRole} className="text-slate-400" />
                            </div>
                            <div className="mt-0.5 break-all font-mono text-[11px] text-slate-500" data-raw="">
                              {item.incidentId}
                            </div>
                          </td>
                          <td className="soc-td max-w-sm text-xs text-slate-200">
                            <LookupText label={reviewReasonText(item.zeekadReviewReason)} />
                          </td>
                          <td className="soc-td whitespace-nowrap text-xs tabular-nums text-slate-300">
                            {formatDateTime(item.requestedAt)}
                          </td>
                          <td className="soc-td text-xs">
                            <div className="flex flex-col items-start gap-1">
                              <ReviewActionBadge action={item.zeekadReviewAction} pending={isPending} />
                              {!isPending && resumeText && (
                                <ResumeStatusBadge
                                  label={resumeText}
                                  failed={resumeFailed}
                                  resumed={resumed}
                                  pending={false}
                                />
                              )}
                              {phase === 'delayed' && (
                                <span
                                  className="inline-flex items-center gap-1 text-[11px] text-amber-200"
                                  title={RESUME_DELAYED_TEXT}
                                >
                                  <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                                  {RESUME_DELAYED_LABEL}
                                </span>
                              )}
                              {item.analystDisplay && (
                                <span className="text-[11px] text-slate-400" data-raw="">
                                  {item.analystDisplay}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <div className="space-y-2">
                              {canDecide && isPending && (
                                <ReviewRowActions
                                  item={item}
                                  onSubmitted={loadReviews}
                                  blockedReason={stale ? STALE_ACTION_BLOCKED : null}
                                />
                              )}
                              {/* T27: 번호가 있으면 순위가 없어도 고정 주소로, 둘 다 없으면 숨긴다 */}
                              {incidentPath(item) !== null && (
                                <Link
                                  to={incidentPath(item) as string}
                                  className="soc-btn-secondary inline-flex py-1 text-xs"
                                >
                                  인시던트 상세
                                  <ExternalLink className="h-3 w-3" />
                                </Link>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
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
