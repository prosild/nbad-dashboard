import { useState } from 'react';
import { AlertTriangle, CheckCircle2, ClipboardCheck, History, RefreshCw, XCircle } from 'lucide-react';
import { ApiError } from '../../api/client';
import { incidentsApi } from '../../api/endpoints';
import type { AnalystReviewView, StatusHistoryItem } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { labelText, reviewReasonText } from '../../utils/labels';
import {
  CodeLabel,
  IncidentStatusBadge,
  LookupText,
  ResolutionBadge,
  ResumeStatusBadge,
  ReviewActionBadge,
} from '../StatusBadge';
import { useToast } from '../ToastContext';

interface IncidentStatusAndReviewSectionProps {
  jobId: number;
  queueRank: number;
  currentStatus: string;
  currentResolution: string | null;
  statusUpdatedAt: string | null;
  statusUpdatedByDisplay: string | null;
  canTransition: boolean;
  nextAllowedStatus: string | null;
  statusHistory: StatusHistoryItem[];
  analystReview: AnalystReviewView;
  onRefresh: () => Promise<void>;
}

export function IncidentStatusAndReviewSection({
  jobId,
  queueRank,
  currentStatus,
  currentResolution,
  statusUpdatedAt,
  statusUpdatedByDisplay,
  canTransition,
  nextAllowedStatus,
  statusHistory,
  analystReview,
  onRefresh,
}: IncidentStatusAndReviewSectionProps) {
  const { notify } = useToast();

  const [resolution, setResolution] = useState<'true_positive' | 'false_positive' | 'benign'>('true_positive');
  const [reason, setReason] = useState('');
  const [transitioning, setTransitioning] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);

  const [reviewNote, setReviewNote] = useState('');
  const [decidingReview, setDecidingReview] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  async function handleTransition(e: React.FormEvent) {
    e.preventDefault();
    if (!nextAllowedStatus) return;

    setTransitionError(null);
    setTransitioning(true);
    try {
      const res = await incidentsApi.transition(jobId, queueRank, {
        toStatus: nextAllowedStatus,
        resolution: nextAllowedStatus === 'closed' ? resolution : null,
        reason: reason.trim(),
      });
      notify(res.message || '사건 상태를 바꿨습니다.', 'success');
      setReason('');
      await onRefresh();
    } catch (err) {
      setTransitionError(err instanceof ApiError ? err.message : '상태 변경 요청을 처리하지 못했습니다.');
    } finally {
      setTransitioning(false);
    }
  }

  async function handleReviewDecision(action: 'confirm' | 'dismiss') {
    setReviewError(null);
    setDecidingReview(true);
    try {
      const res = await incidentsApi.reviewDecision(jobId, queueRank, {
        action,
        note: reviewNote.trim() || undefined,
      });
      notify(res.message || '판단을 저장했습니다.', 'success');
      setReviewNote('');
      await onRefresh();
    } catch (err) {
      setReviewError(err instanceof ApiError ? err.message : '판단을 저장하지 못했습니다.');
    } finally {
      setDecidingReview(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <section className="soc-card space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <History className="h-4 w-4 text-slate-400" />
            상태 변경 · 이력
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <IncidentStatusBadge status={currentStatus} />
            <ResolutionBadge resolution={currentResolution} />
          </div>
        </div>

        {statusUpdatedAt && (
          <div className="text-xs text-slate-400">
            최근 변경 <span className="tabular-nums text-slate-300">{formatDateTime(statusUpdatedAt)}</span> · 담당자{' '}
            <span className="text-slate-300" data-raw="">
              {statusUpdatedByDisplay ?? '-'}
            </span>
          </div>
        )}

        {canTransition && nextAllowedStatus && (
          <form onSubmit={(e) => void handleTransition(e)} className="soc-panel space-y-3 p-4">
            <h4 className="soc-subhead">
              다음 단계: {labelText('incidentStatus', currentStatus)} → {labelText('incidentStatus', nextAllowedStatus)}
            </h4>

            {transitionError && (
              <div
                role="alert"
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                  <span>{transitionError}</span>
                </div>
                <button type="button" onClick={() => void onRefresh()} className="soc-btn-secondary py-1 text-[11px]">
                  <RefreshCw className="h-3 w-3" />
                  다시 불러오기
                </button>
              </div>
            )}

            {nextAllowedStatus === 'closed' && (
              <div>
                <label htmlFor="transition-resolution" className="mb-1 block text-xs font-medium text-slate-300">
                  판정 (필수)
                </label>
                <select
                  id="transition-resolution"
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value as 'true_positive' | 'false_positive' | 'benign')}
                  className="soc-select w-full text-xs"
                >
                  <option value="true_positive">{labelText('resolution', 'true_positive')}</option>
                  <option value="false_positive">{labelText('resolution', 'false_positive')}</option>
                  <option value="benign">{labelText('resolution', 'benign')}</option>
                </select>
              </div>
            )}

            <div>
              <label htmlFor="transition-reason" className="mb-1 block text-xs font-medium text-slate-300">
                변경 사유 (필수)
              </label>
              <textarea
                id="transition-reason"
                rows={2}
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="조사 판단과 상태 변경 근거를 입력하세요."
                className="soc-input text-xs"
              />
            </div>

            <button type="submit" disabled={transitioning || !reason.trim()} className="soc-btn-primary w-full py-2 text-xs">
              {transitioning
                ? '저장 중...'
                : nextAllowedStatus === 'investigating'
                  ? '조사 중으로 변경'
                  : '종료 처리'}
            </button>
          </form>
        )}

        <div className="space-y-2">
          <h4 className="soc-subhead">상태 변경 이력 {statusHistory.length}건</h4>
          {statusHistory.length === 0 ? (
            <div className="soc-panel px-4 py-4 text-center text-xs text-slate-400">
              아직 상태를 바꾼 기록이 없습니다.
            </div>
          ) : (
            <div className="space-y-2">
              {statusHistory.map((item, idx) => (
                <div
                  key={`${item.changedAt ?? idx}-${idx}`}
                  className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-slate-400">
                        {item.fromStatus ? <CodeLabel dict="incidentStatus" value={item.fromStatus} /> : '생성'}
                      </span>
                      <span className="text-slate-600">→</span>
                      <span className="font-semibold text-slate-100">
                        <CodeLabel dict="incidentStatus" value={item.toStatus} />
                      </span>
                      {item.resolution && <ResolutionBadge resolution={item.resolution} />}
                    </div>
                    <span
                      className="whitespace-nowrap text-[11px] tabular-nums text-slate-400"
                      title={item.jobId !== null ? `분석 실행 #${item.jobId}` : undefined}
                    >
                      {formatDateTime(item.changedAt)}
                    </span>
                  </div>
                  <div className="mt-1.5 text-slate-200">{item.reason || '-'}</div>
                  <div className="mt-1 text-[11px] text-slate-400">
                    담당자{' '}
                    <span data-raw="">{item.actorDisplay ?? '-'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="soc-card space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <ClipboardCheck className="h-4 w-4 text-slate-400" />
            분석가 판단 요청
          </div>
          {analystReview.present && analystReview.resumeStatusLabel && (
            <ResumeStatusBadge
              label={analystReview.resumeStatusLabel}
              failed={analystReview.resumeFailed}
              resumed={analystReview.resumedAt !== null}
              pending={analystReview.pending}
            />
          )}
        </div>

        {!analystReview.present ? (
          <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
            이 사건에는 분석가 판단 요청이 없습니다.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="soc-panel space-y-2.5 p-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-slate-400">요청 시각</span>
                <span
                  className="tabular-nums text-slate-300"
                  title={analystReview.reviewJobId !== null ? `판단 요청 실행 #${analystReview.reviewJobId}` : undefined}
                >
                  {formatDateTime(analystReview.requestedAt)}
                </span>
              </div>
              <div>
                <div className="font-semibold text-slate-400">요청 사유</div>
                <div className="mt-1 text-sm text-slate-100">
                  <LookupText label={reviewReasonText(analystReview.reviewReason)} />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-2.5">
                <span className="text-slate-400">현재 판단</span>
                <ReviewActionBadge action={analystReview.reviewAction} pending={analystReview.pending} />
                {analystReview.analystDisplay && (
                  <span className="text-slate-300" data-raw="">
                    {analystReview.analystDisplay}
                  </span>
                )}
              </div>
              {analystReview.decidedAt && (
                <div className="text-[11px] tabular-nums text-slate-400">
                  판단 시각 {formatDateTime(analystReview.decidedAt)}
                  {analystReview.resumedAt ? ` · 자동 처리 반영 ${formatDateTime(analystReview.resumedAt)}` : ''}
                </div>
              )}
            </div>

            {analystReview.canDecide && !analystReview.reviewAction && (
              <div className="soc-panel space-y-3 p-4">
                <h4 className="soc-subhead">판단 입력</h4>

                {reviewError && (
                  <div
                    role="alert"
                    className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                  >
                    {reviewError}
                  </div>
                )}

                <div>
                  <label htmlFor="detail-review-note" className="mb-1 block text-xs font-medium text-slate-300">
                    판단 메모 (선택)
                  </label>
                  <textarea
                    id="detail-review-note"
                    rows={2}
                    value={reviewNote}
                    onChange={(e) => setReviewNote(e.target.value)}
                    placeholder="판단 근거를 적어 두세요(선택)."
                    className="soc-input text-xs"
                  />
                </div>

                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <button
                    type="button"
                    disabled={decidingReview}
                    onClick={() => void handleReviewDecision('confirm')}
                    className="soc-btn-emerald py-2 text-xs"
                  >
                    <CheckCircle2 className="h-4 w-4" />
                    {labelText('reviewAction', 'confirm')}
                  </button>
                  <button
                    type="button"
                    disabled={decidingReview}
                    onClick={() => void handleReviewDecision('dismiss')}
                    className="soc-btn-secondary py-2 text-xs"
                  >
                    <XCircle className="h-4 w-4" />
                    {labelText('reviewAction', 'dismiss')}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
