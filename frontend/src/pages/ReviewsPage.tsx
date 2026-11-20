import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { CheckCircle2, ClipboardCheck, ExternalLink, Info, XCircle } from 'lucide-react';
import { ApiError } from '../api/client';
import { reviewsApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { CodeLabel, LookupText, ResumeStatusBadge, ReviewActionBadge } from '../components/StatusBadge';
import { useToast } from '../components/ToastContext';
import type { AnalystReviewItem, ReviewsApiResponse } from '../types/api';
import { formatDateTime } from '../utils/format';
import { labelText, reviewReasonText } from '../utils/labels';

function ReviewRowActions({ item, onSubmitted }: { item: AnalystReviewItem; onSubmitted: () => Promise<void> }) {
  const { notify } = useToast();
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const targetJobId = item.reviewJobId ?? item.jobId;
  if (!targetJobId) {
    return <span className="text-xs text-slate-500">판단 요청 정보가 없어 결정할 수 없습니다</span>;
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
      notify(res.message || '판단을 저장했습니다.', 'success');
      setNote('');
      await onSubmitted();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '판단을 저장하지 못했습니다.', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-w-[230px] space-y-2">
      <input
        type="text"
        aria-label={`${item.incidentId} 판단 메모`}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="판단 메모 (선택)"
        className="soc-input py-1 text-xs"
      />
      <div className="flex gap-1.5">
        <button
          type="button"
          disabled={submitting}
          onClick={() => void decide('confirm')}
          className="soc-btn-emerald flex-1 px-2 py-1 text-xs"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          {labelText('reviewAction', 'confirm')}
        </button>
        <button
          type="button"
          disabled={submitting}
          onClick={() => void decide('dismiss')}
          className="soc-btn-secondary flex-1 px-2 py-1 text-xs"
        >
          <XCircle className="h-3.5 w-3.5" />
          {labelText('reviewAction', 'dismiss')}
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
      setErrorMsg(err instanceof ApiError ? err.message : '판단 요청 목록을 불러오지 못했습니다.');
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
      title="판단 요청"
      subtitle="자동 판단이 엇갈려 분석가 판단을 기다리는 사건입니다. 조사를 진행할지 오탐으로 종료할지 정해 주세요"
    >
      <div className="space-y-5">
        {data && !data.canDecideReview && (
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>읽기 전용 계정입니다. 판단은 분석가 계정에서 할 수 있습니다.</span>
          </div>
        )}

        <section className="soc-card flex flex-wrap items-center justify-between gap-4 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label htmlFor="reviews-capture" className="mb-1 block text-[11px] font-medium text-slate-400">
                수집 구간
              </label>
              <select
                id="reviews-capture"
                value={captureId}
                onChange={(e) => updateCapture(e.target.value)}
                className="soc-select text-xs"
              >
                <option value="">열람 허용 수집 구간 전체</option>
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
              <span>판단 대기만 보기</span>
            </label>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <ClipboardCheck className="h-4 w-4 text-slate-400" />
            <span className="tabular-nums">총 {data?.reviews.length ?? 0}건</span>
          </div>
        </section>

        {errorMsg && <ErrorAlert message={errorMsg} onRetry={() => void loadReviews()} />}

        {loading && !data ? (
          <LoadingPanel label="판단 요청 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">수집 구간</th>
                    <th className="soc-th">사건 · 호스트</th>
                    <th className="soc-th">요청 사유</th>
                    <th className="soc-th">요청 시각</th>
                    <th className="soc-th">판단 · 반영 상태</th>
                    <th className="soc-th">판단 · 상세</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.reviews ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                        판단을 기다리는 사건이 없습니다.
                      </td>
                    </tr>
                  ) : (
                    (data?.reviews ?? []).map((item) => {
                      const isPending = item.zeekadReviewAction === null || item.zeekadReviewAction === '';
                      const resumeFailed = item.zeekadReviewResumeFailed === true;
                      const resumed = item.zeekadReviewResumedAt !== null;
                      const resumeText =
                        item.resumeStatusLabel ||
                        (isPending
                          ? '판단 대기'
                          : resumeFailed
                            ? '반영 실패(관리자 확인 필요)'
                            : resumed
                              ? '반영됨'
                              : '반영 중');

                      return (
                        <tr key={`${item.reviewJobId ?? item.jobId}-${item.incidentId}`} className="hover:bg-slate-800/35">
                          <td
                            className="soc-td font-mono text-xs font-semibold text-slate-200"
                            title={`판단 요청 실행 #${item.reviewJobId ?? item.jobId ?? '-'}`}
                          >
                            {item.captureId ?? '-'}
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
                              {!isPending && (
                                <ResumeStatusBadge
                                  label={resumeText}
                                  failed={resumeFailed}
                                  resumed={resumed}
                                  pending={false}
                                />
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
