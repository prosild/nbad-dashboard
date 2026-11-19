import { useState } from 'react';
import { AlertTriangle, CheckCircle2, ClipboardCheck, History, RefreshCw } from 'lucide-react';
import { ApiError } from '../../api/client';
import { incidentsApi } from '../../api/endpoints';
import type { AnalystReviewView, StatusHistoryItem } from '../../types/api';
import { formatDateTime, resolutionLabel, statusLabel } from '../../utils/format';
import {
  IncidentStatusBadge,
  ResolutionBadge,
  ReviewActionBadge,
  SocBadge,
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
      notify(res.message || '사건 상태가 변경되었습니다.', 'success');
      setReason('');
      await onRefresh();
    } catch (err) {
      setTransitionError(
        err instanceof ApiError ? err.message : '상태 변경 요청을 처리하지 못했습니다.',
      );
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
      notify(res.message || '검토 결정이 기록되었습니다.', 'success');
      setReviewNote('');
      await onRefresh();
    } catch (err) {
      setReviewError(
        err instanceof ApiError ? err.message : '검토 결정을 저장하지 못했습니다.',
      );
    } finally {
      setDecidingReview(false);
    }
  }

  const resumeTone = analystReview.resumeFailed
    ? 'rose'
    : analystReview.resumedAt
      ? 'emerald'
      : analystReview.pending
        ? 'amber'
        : 'cyan';

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <section className="soc-card space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <History className="h-4 w-4 text-cyan-400" />
            사건 상태 관리 및 이력 (incident_id 기준)
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <IncidentStatusBadge status={currentStatus} />
            <ResolutionBadge resolution={currentResolution} />
          </div>
        </div>

        <div className="text-xs text-slate-400">
          최근 변경: {formatDateTime(statusUpdatedAt)} · 담당자: {statusUpdatedByDisplay ?? '-'}
        </div>

        {canTransition && nextAllowedStatus && (
          <form onSubmit={(e) => void handleTransition(e)} className="soc-panel space-y-3 p-4">
            <div className="flex items-center justify-between gap-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                다음 상태 전이: {statusLabel(currentStatus)} → {statusLabel(nextAllowedStatus)}
              </h4>
            </div>

            {transitionError && (
              <div
                role="alert"
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200"
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                  <span>{transitionError}</span>
                </div>
                <button
                  type="button"
                  onClick={() => void onRefresh()}
                  className="soc-btn-secondary py-1 text-[11px]"
                >
                  <RefreshCw className="h-3 w-3" />
                  새로고침
                </button>
              </div>
            )}

            {nextAllowedStatus === 'closed' && (
              <div>
                <label
                  htmlFor="transition-resolution"
                  className="mb-1 block text-xs font-medium text-slate-300"
                >
                  종료 결론 (필수)
                </label>
                <select
                  id="transition-resolution"
                  value={resolution}
                  onChange={(e) =>
                    setResolution(e.target.value as 'true_positive' | 'false_positive' | 'benign')
                  }
                  className="soc-select w-full text-xs"
                >
                  <option value="true_positive">{resolutionLabel('true_positive')}</option>
                  <option value="false_positive">{resolutionLabel('false_positive')}</option>
                  <option value="benign">{resolutionLabel('benign')}</option>
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
                placeholder="조사 판단 및 상태 변경 근거를 입력하세요."
                className="soc-input text-xs"
              />
            </div>

            <button
              type="submit"
              disabled={transitioning || !reason.trim()}
              className="soc-btn-primary w-full py-2 text-xs"
            >
              {transitioning
                ? '상태 변경 저장 중...'
                : nextAllowedStatus === 'investigating'
                  ? '확인 중으로 변경 (investigating)'
                  : '종료 처리 (closed)'}
            </button>
          </form>
        )}

        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            상태 변경 이력 ({statusHistory.length}건)
          </h4>
          {statusHistory.length === 0 ? (
            <div className="soc-panel px-4 py-4 text-center text-xs text-slate-400">
              상태 변경 이력이 없습니다.
            </div>
          ) : (
            <div className="space-y-2">
              {statusHistory.map((item, idx) => (
                <div
                  key={`${item.changedAt ?? idx}-${idx}`}
                  className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5 font-mono">
                      <span className="text-slate-400">{item.fromStatus ?? 'init'}</span>
                      <span className="text-slate-600">→</span>
                      <span className="font-semibold text-cyan-300">{item.toStatus}</span>
                      {item.resolution && <ResolutionBadge resolution={item.resolution} />}
                    </div>
                    <span className="font-mono text-[11px] tabular-nums text-slate-400">
                      {formatDateTime(item.changedAt)}
                    </span>
                  </div>
                  <div className="mt-1.5 text-slate-200">{item.reason || '-'}</div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400">
                    담당: {item.actorDisplay ?? '-'} · 작업 #{item.jobId ?? '-'}
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
            <ClipboardCheck className="h-4 w-4 text-cyan-400" />
            분석가 검토 결정 (analyst_review_queue)
          </div>
          {analystReview.present && (
            <SocBadge tone={resumeTone}>{analystReview.resumeStatusLabel ?? '-'}</SocBadge>
          )}
        </div>

        {!analystReview.present ? (
          <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
            이 보고 작업에 연결된 분석가 검토 요청이 없습니다.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="soc-panel space-y-2.5 p-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-slate-400">
                  검토 작업 #{analystReview.reviewJobId ?? '-'}
                </span>
                <span className="font-mono tabular-nums text-slate-400">
                  요청 {formatDateTime(analystReview.requestedAt)}
                </span>
              </div>
              <div>
                <div className="font-semibold text-slate-400">검토 사유</div>
                <div className="mt-1 text-sm text-slate-100">
                  {analystReview.reviewReason || '-'}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-2.5">
                <span className="text-slate-400">현재 결정:</span>
                <ReviewActionBadge
                  action={analystReview.reviewAction}
                  pending={analystReview.pending}
                />
                {analystReview.analystDisplay && (
                  <span className="font-mono text-slate-300">
                    ({analystReview.analystDisplay})
                  </span>
                )}
              </div>
              {analystReview.decidedAt && (
                <div className="font-mono text-[11px] text-slate-400">
                  결정 시각: {formatDateTime(analystReview.decidedAt)}
                  {analystReview.resumedAt ? ` · 파이프라인 반영: ${formatDateTime(analystReview.resumedAt)}` : ''}
                </div>
              )}
            </div>

            {analystReview.canDecide && !analystReview.reviewAction && (
              <div className="soc-panel space-y-3 p-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-300">
                  검토 결정 제출 (confirm / dismiss)
                </h4>

                {reviewError && (
                  <div
                    role="alert"
                    className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200"
                  >
                    {reviewError}
                  </div>
                )}

                <div>
                  <label htmlFor="detail-review-note" className="mb-1 block text-xs font-medium text-slate-300">
                    검토 메모 (선택)
                  </label>
                  <textarea
                    id="detail-review-note"
                    rows={2}
                    value={reviewNote}
                    onChange={(e) => setReviewNote(e.target.value)}
                    placeholder="검토 판단 메모를 입력하세요 (선택 사항)."
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
                    confirm (조사 진행)
                  </button>
                  <button
                    type="button"
                    disabled={decidingReview}
                    onClick={() => void handleReviewDecision('dismiss')}
                    className="soc-btn-danger py-2 text-xs"
                  >
                    dismiss (오탐 종료)
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
