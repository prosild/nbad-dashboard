import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { CheckCircle2, ClipboardCheck, ExternalLink, ShieldAlert, XCircle } from 'lucide-react';
import { ApiError } from '../api/client';
import { reviewsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { ReviewActionBadge, SocBadge } from '../components/StatusBadge';
import { useToast } from '../components/ToastContext';
import type { AnalystReviewItem, ReviewsApiResponse } from '../types/api';
import { formatDateTime } from '../utils/format';

function ReviewRowActions({
  item,
  onSubmitted,
}: {
  item: AnalystReviewItem;
  onSubmitted: () => Promise<void>;
}) {
  const { notify } = useToast();
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const targetJobId = item.reviewJobId ?? item.jobId;
  if (!targetJobId) {
    return <span className="text-xs text-slate-500">작업 ID 없음</span>;
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
      notify(res.message || '검토 결정이 저장되었습니다.', 'success');
      setNote('');
      await onSubmitted();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '검토 결정 저장에 실패했습니다.', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-w-[230px] space-y-2">
      <input
        type="text"
        aria-label={`${item.incidentId} 검토 메모`}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="검토 메모 (선택)"
        className="soc-input py-1 text-xs"
      />
      <div className="flex gap-1.5">
        <button
          type="button"
          disabled={submitting}
          onClick={() => void decide('confirm')}
          className="soc-btn-emerald flex-1 py-1 px-2 text-xs"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          confirm
        </button>
        <button
          type="button"
          disabled={submitting}
          onClick={() => void decide('dismiss')}
          className="soc-btn-danger flex-1 py-1 px-2 text-xs"
        >
          <XCircle className="h-3.5 w-3.5" />
          dismiss
        </button>
      </div>
    </div>
  );
}

export function ReviewsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<ReviewsApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const captureId = searchParams.get('captureId') ?? '';
  const pendingOnly = searchParams.get('pendingOnly') === 'true';

  const loadReviews = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await reviewsApi.list(captureId || undefined, pendingOnly);
      setData(res);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : '승인 대기 목록을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, [captureId, pendingOnly]);

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

  return (
    <AppShell
      title="분석가 승인 대기 목록"
      subtitle="dashboard.analyst_review_queue · (zeekad_report_job_id, incident_id) 연계 및 decide_review 결정"
    >
      <div className="space-y-5">
        {data?.maskedView && (
          <div className="flex items-center gap-2.5 rounded-xl border border-amber-500/35 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-200">
            <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              조회자(VIEWER) 권한은 검토 목록을 조회할 수 있으나 결정(confirm/dismiss)은 분석가(ANALYST) 이상만 가능합니다.
            </span>
          </div>
        )}

        <section className="soc-card flex flex-wrap items-center justify-between gap-4 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label htmlFor="reviews-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
                캡처 필터
              </label>
              <select
                id="reviews-capture"
                value={captureId}
                onChange={(e) => updateCapture(e.target.value)}
                className="soc-select font-mono text-xs"
              >
                <option value="">전체 허용 캡처</option>
                {(data?.allowedCaptures ?? []).map((cap) => (
                  <option key={cap} value={cap}>
                    {cap}
                  </option>
                ))}
              </select>
            </div>

            <label className="mt-4 flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700/80 bg-[#090f1d] px-3 py-2 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={pendingOnly}
                onChange={(e) => togglePendingOnly(e.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-cyan-400 focus:ring-cyan-500/30"
              />
              <span>미결정만 보기 (pendingOnly)</span>
            </label>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <ClipboardCheck className="h-4 w-4 text-cyan-400" />
            <span>총 {data?.reviews.length ?? 0}건</span>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadReviews()} />}

        {loading && !data ? (
          <LoadingPanel label="승인 대기 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">캡처 · 작업</th>
                    <th className="soc-th">사건 · 호스트</th>
                    <th className="soc-th">검토 사유</th>
                    <th className="soc-th">요청 시각</th>
                    <th className="soc-th">결정 · 반영 상태</th>
                    <th className="soc-th">결정 / 상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.reviews ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                        조건에 해당하는 검토 요청이 없습니다.
                      </td>
                    </tr>
                  ) : (
                    (data?.reviews ?? []).map((item) => {
                      const isPending = item.zeekadReviewAction === null || item.zeekadReviewAction === '';
                      const resumeTone = item.zeekadReviewResumeFailed
                        ? 'rose'
                        : item.zeekadReviewResumedAt
                          ? 'emerald'
                          : isPending
                            ? 'amber'
                            : 'cyan';
                      const resumeText =
                        item.resumeStatusLabel ||
                        (isPending
                          ? '대기 중'
                          : item.zeekadReviewResumeFailed
                            ? '반영 실패(운영자 확인)'
                            : item.zeekadReviewResumedAt
                              ? '반영됨'
                              : '반영 중');

                      return (
                        <tr
                          key={`${item.reviewJobId ?? item.jobId}-${item.incidentId}`}
                          className="hover:bg-slate-800/35"
                        >
                          <td className="soc-td font-mono text-xs">
                            <div className="font-semibold text-cyan-200">{item.captureId ?? '-'}</div>
                            <div className="mt-0.5 text-[11px] text-slate-400">
                              검토 #{item.reviewJobId ?? item.jobId ?? '-'}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <div className="font-mono font-semibold text-slate-100">
                              {item.hostIp ?? '-'} ({item.zeekadRole ?? '-'})
                            </div>
                            <div className="mt-0.5 break-all font-mono text-[11px] text-slate-400">
                              {item.incidentId}
                            </div>
                          </td>
                          <td className="soc-td max-w-sm text-xs text-slate-200">
                            {item.zeekadReviewReason || '-'}
                          </td>
                          <td className="soc-td font-mono text-xs tabular-nums text-slate-300">
                            {formatDateTime(item.requestedAt)}
                          </td>
                          <td className="soc-td text-xs">
                            <div className="flex flex-col items-start gap-1">
                              <ReviewActionBadge
                                action={item.zeekadReviewAction}
                                pending={isPending}
                              />
                              <SocBadge tone={resumeTone}>{resumeText}</SocBadge>
                              {item.analystDisplay && (
                                <span className="font-mono text-[11px] text-slate-400">
                                  {item.analystDisplay}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="soc-td text-xs">
                            <div className="space-y-2">
                              {data?.canDecideReview && isPending && (
                                <ReviewRowActions item={item} onSubmitted={loadReviews} />
                              )}
                              {item.jobId !== null && item.queueRank !== null && (
                                <Link
                                  to={`/incidents/${item.jobId}/rank/${item.queueRank}`}
                                  className="soc-btn-secondary inline-flex py-1 text-xs"
                                >
                                  사건 상세
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
