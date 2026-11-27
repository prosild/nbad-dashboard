import { useEffect, useState } from 'react';
import { AlertTriangle, ClipboardCheck, History, Info, RefreshCw, RotateCcw, Wrench } from 'lucide-react';
import { ApiError } from '../../api/client';
import { incidentsApi } from '../../api/endpoints';
import type { AssignmentHistoryItem, IncidentAssignment, IncidentDetailView, ResponseActionItem } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { labelText, reviewReasonText } from '../../utils/labels';
import {
  isResumeStuck,
  RESUME_DELAYED_LABEL,
  RESUME_DELAYED_TEXT,
  RESUME_FAILED_TEXT,
  RESUME_MANUAL_CLOSE_TEXT,
  RESUME_PENDING_FORM_NOTE,
  resumePhase,
  REVIEW_STATUS_RELATION,
  useNowMs,
} from '../../utils/reviewResume';
import { CLOSED_INCIDENT_TEXT, REOPEN_ASSIGN_NOTE, REOPEN_EFFECT_NOTE, reopenedAfter } from '../../utils/reopen';
import { RESPONSE_ACTION_REQUIRED_TEXT } from '../../utils/responseActions';
import { isClosedStatus } from '../../utils/triage';
import {
  IncidentStatusBadge,
  LookupText,
  ResolutionBadge,
  ResumeStatusBadge,
  ReviewActionBadge,
} from '../StatusBadge';
import { useToast } from '../ToastContext';
import { AssignmentSection } from './AssignmentSection';
import { FREE_TEXT_MAX } from '../../utils/freeText';
import { FreeTextCounter } from './FreeTextCounter';
import { buildTimeline, HistoryTimeline } from './HistoryTimeline';
import { ResponseActionSection } from './ResponseActionSection';
import { ReviewDecisionButtons } from './ReviewDecisionButtons';

type Resolution = 'true_positive' | 'false_positive' | 'benign';

/** 두 결정의 관계 안내(T21 정정: zeek_AD 계약대로 결정이 반영되면 상태가 바뀐다). 정의는 utils/reviewResume.ts */
export { REVIEW_STATUS_RELATION };

/** 패널 아래쪽에 보이는 최근 이력 수 */
const RECENT_HISTORY = 3;

/**
 * 인시던트 조치 패널(T19): 상태 변경과 에스컬레이션 결정을 한곳에 둔다.
 * 조회자(쓰기 권한 없음)는 폼 없이 현재 상태·판정만 읽기 전용으로 본다. 폼 노출은 서버가 준 권한 값(canTransition·canDecide)을 따른다.
 */
export function ActionPanel({
  detail,
  readOnly,
  onRefresh,
  onShowHistory,
  assignment = null,
  assignmentHistory = [],
  canAssign = false,
  currentUsername = null,
  blockedReason = null,
  responseActions,
  canRecordResponse = false,
  canReopen = false,
}: {
  detail: IncidentDetailView;
  /** 조회자 계정이면 true */
  readOnly: boolean;
  onRefresh: () => Promise<void>;
  onShowHistory: () => void;
  /** T25 현재 담당·담당 이력·바꿀 수 있는지(서버 값)·로그인 사용자 */
  assignment?: IncidentAssignment | null;
  assignmentHistory?: AssignmentHistoryItem[];
  canAssign?: boolean;
  currentUsername?: string | null;
  /** T42: 상세 값이 최신이 아닌 동안(다시 읽기 실패) 조치를 막는 이유 */
  blockedReason?: string | null;
  /** T56 대응 조치 기록(시간 역순, 서버 값). 응답에 없으면(옛 응답) undefined: 정탐 종결을 화면에서 막지 않는다 */
  responseActions?: ResponseActionItem[];
  /** T56 기록할 수 있는지(분석가·관리자이고 신규가 아님, 서버 값) */
  canRecordResponse?: boolean;
  /** T53 다시 열 수 있는지(분석가·관리자이고 지금 종결, 서버 값) */
  canReopen?: boolean;
}) {
  const { notify } = useToast();
  const { incident, analystReview, currentStatus, nextAllowedStatus } = detail;
  const canTransition = !readOnly && detail.canTransition && nextAllowedStatus !== null;
  const canDecide = !readOnly && analystReview.present && analystReview.canDecide && !analystReview.reviewAction;

  // 결정 반영 단계(T21): 서버 값(결정·결정 시각·반영 시각·반영 실패)과 지금 시각으로 끌어낸다.
  const nowMs = useNowMs();
  const phase = resumePhase(analystReview, nowMs);
  const stuck = isResumeStuck(phase);
  const closed = isClosedStatus(currentStatus);
  // T53: 결정 시각보다 늦게 사람이 종결 건을 다시 열었으면(종결 → 분석 중) 그 사람은 판정을 의심해 연 것이다.
  // 반영 상태(반영됨·실패·지연)와 상관없이 "직접 종결" 안내와 오탐 미리 채움을 띄우지 않는다(서버 규칙은 그대로, 화면 안의 판단).
  const reopenedAfterDecision = reopenedAfter(detail.statusHistory, analystReview.decidedAt);
  // 오탐 미리 채움(T21): 오탐 종결 결정이 자동 반영되지 않았을 때(반영 실패·반영 지연)만. 상태 ≠ 종결.
  const dismissed = analystReview.reviewAction === 'dismiss' && !closed && stuck && !reopenedAfterDecision;
  // T53 다시 열기: 서버 값(canReopen)이고 지금 종결일 때만
  const showReopen = !readOnly && canReopen && closed;
  const defaultResolution: Resolution = dismissed ? 'false_positive' : 'true_positive';

  const [resolution, setResolution] = useState<Resolution>(defaultResolution);
  const [reason, setReason] = useState('');
  const [transitioning, setTransitioning] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);

  const [reopenReason, setReopenReason] = useState('');
  const [reopening, setReopening] = useState(false);
  /** 다시 불러오기로 풀릴 수 있는 오류인지(501 기능 없음은 아니다) */
  const [reopenError, setReopenError] = useState<{ message: string; retryable: boolean } | null>(null);

  const [reviewNote, setReviewNote] = useState('');
  const [decidingReview, setDecidingReview] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  useEffect(() => {
    setResolution(defaultResolution);
  }, [defaultResolution, nextAllowedStatus]);

  async function handleTransition(e: React.FormEvent) {
    e.preventDefault();
    if (!nextAllowedStatus) return;
    setTransitionError(null);
    setTransitioning(true);
    try {
      const res = await incidentsApi.transition(incident.jobId, incident.queueRank, {
        toStatus: nextAllowedStatus,
        resolution: nextAllowedStatus === 'closed' ? resolution : null,
        reason: reason.trim(),
      });
      notify(res.message || '인시던트 상태를 바꿨습니다.', 'success');
      setReason('');
      await onRefresh();
    } catch (err) {
      setTransitionError(err instanceof ApiError ? err.message : '상태 변경 요청을 처리하지 못했습니다.');
    } finally {
      setTransitioning(false);
    }
  }

  async function handleReopen(e: React.FormEvent) {
    e.preventDefault();
    setReopenError(null);
    setReopening(true);
    try {
      const res = await incidentsApi.reopen(incident.jobId, incident.queueRank, {
        reason: reopenReason.trim(),
        // 화면이 보고 있는 판정. 그사이 다른 사람이 다시 열어 다른 판정으로 종결했으면 서버가 409로 거부한다.
        expectedResolution: detail.currentResolution ?? '',
      });
      notify(res.message || '인시던트를 다시 열었습니다.', 'success');
      setReopenReason('');
      await onRefresh();
    } catch (err) {
      setReopenError(
        err instanceof ApiError
          ? { message: err.message, retryable: err.status !== 501 }
          : { message: '다시 열기 요청을 처리하지 못했습니다.', retryable: true },
      );
    } finally {
      setReopening(false);
    }
  }

  async function handleReviewDecision(action: 'confirm' | 'dismiss') {
    setReviewError(null);
    setDecidingReview(true);
    try {
      const res = await incidentsApi.reviewDecision(incident.jobId, incident.queueRank, {
        action,
        note: reviewNote.trim() || undefined,
      });
      notify(res.message || '검토 결정을 저장했습니다.', 'success');
      setReviewNote('');
      await onRefresh();
    } catch (err) {
      setReviewError(err instanceof ApiError ? err.message : '검토 결정을 저장하지 못했습니다.');
    } finally {
      setDecidingReview(false);
    }
  }

  const statusEvents = buildTimeline(detail.statusHistory, analystReview, assignmentHistory, responseActions ?? []);
  /**
   * T56: 정탐으로 종결하려면 대응 조치 기록이 하나 이상 있어야 한다(서버 409 RESPONSE_ACTION_REQUIRED와 같은 규칙).
   * 응답에 기록 목록이 없으면(옛 응답) 모르는 것으로 보고 막지 않는다. 빈 목록일 때만 막는다.
   */
  const needsResponseAction =
    nextAllowedStatus === 'closed' && resolution === 'true_positive' && responseActions !== undefined && responseActions.length === 0;
  /** T25: 조사를 시작하면 미배정일 때 시작한 사람이 담당자가 된다 */
  const autoAssignHint = nextAllowedStatus === 'investigating' && !assignment?.assignee;
  const recent = statusEvents.slice(-RECENT_HISTORY).reverse();

  return (
    <section aria-label="조치" className="soc-card space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Wrench className="h-4 w-4 text-slate-400" aria-hidden="true" />
          조치
        </h2>
        <div className="flex items-center gap-1">
          <IncidentStatusBadge status={currentStatus} />
          <ResolutionBadge resolution={detail.currentResolution} />
        </div>
      </div>

      {detail.statusUpdatedAt && (
        <div className="text-[11px] text-slate-400">
          최근 변경 <span className="tabular-nums text-slate-300">{formatDateTime(detail.statusUpdatedAt)}</span> · 마지막
          변경자{' '}
          <span className="text-slate-300 [overflow-wrap:anywhere]" data-raw="">
            {detail.statusUpdatedByDisplay ?? '-'}
          </span>
        </div>
      )}

      {blockedReason !== null && !readOnly && (
        <p
          role="note"
          data-testid="action-blocked"
          className="flex items-start gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-100"
        >
          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" aria-hidden="true" />
          {blockedReason}
        </p>
      )}

      <AssignmentSection
        jobId={incident.jobId}
        queueRank={incident.queueRank}
        assignment={assignment}
        canAssign={!readOnly && canAssign}
        closed={isClosedStatus(currentStatus)}
        currentUsername={currentUsername}
        onRefresh={onRefresh}
        blockedReason={blockedReason}
      />

      {readOnly && (
        <p className="flex items-start gap-1.5 text-xs text-slate-400">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          읽기 전용 계정입니다. 담당 지정·대응 조치 기록·상태 변경·에스컬레이션 결정은 분석가 계정에서 할 수 있습니다.
        </p>
      )}

      <ResponseActionSection
        jobId={incident.jobId}
        queueRank={incident.queueRank}
        actions={responseActions ?? []}
        canRecord={!readOnly && canRecordResponse}
        notStarted={!readOnly && currentStatus === 'open'}
        onRefresh={onRefresh}
        blockedReason={blockedReason}
      />

      {/* 상태 변경 */}
      {canTransition && nextAllowedStatus && (
        <form onSubmit={(e) => void handleTransition(e)} className="space-y-2.5" aria-label="상태 변경">
          <h3 className="soc-subhead">
            상태 변경: {labelText('incidentStatus', currentStatus)} → {labelText('incidentStatus', nextAllowedStatus)}
          </h3>

          {autoAssignHint && (
            <p
              role="note"
              aria-label="담당자 자동 지정 안내"
              className="flex items-start gap-1.5 rounded border border-slate-700 bg-slate-900/60 px-2 py-1.5 text-[11px] text-slate-300"
            >
              <Info className="mt-0.5 h-3 w-3 shrink-0 text-slate-400" aria-hidden="true" />
              분석을 시작하면(분석 중으로 바꾸면) 내가 담당자로 지정됩니다.
            </p>
          )}

          {phase === 'pending' && (
            <p
              role="note"
              aria-label="반영 중 상태 변경 안내"
              className="flex items-start gap-1.5 rounded border border-slate-700 bg-slate-900/60 px-2 py-1.5 text-[11px] text-slate-300"
            >
              <Info className="mt-0.5 h-3 w-3 shrink-0 text-slate-400" aria-hidden="true" />
              {RESUME_PENDING_FORM_NOTE}
            </p>
          )}

          {dismissed && (
            <p
              role="note"
              aria-label="직접 종결 안내"
              className="flex items-start gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-100"
            >
              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" aria-hidden="true" />
              {RESUME_MANUAL_CLOSE_TEXT}
            </p>
          )}

          {transitionError && (
            <div
              role="alert"
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
            >
              <span className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                {transitionError}
              </span>
              <button type="button" onClick={() => void onRefresh()} className="soc-btn-secondary py-1 text-[11px]">
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
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
                onChange={(e) => setResolution(e.target.value as Resolution)}
                className="soc-select w-full text-xs"
              >
                <option value="true_positive">{labelText('resolution', 'true_positive')}</option>
                <option value="false_positive">{labelText('resolution', 'false_positive')}</option>
                <option value="benign">{labelText('resolution', 'benign')}</option>
              </select>
              {dismissed && (
                <p className="mt-1 text-[11px] text-slate-400">판정을 오탐으로 미리 채웠습니다. 바꿀 수 있습니다.</p>
              )}
            </div>
          )}

          {nextAllowedStatus === 'investigating' && dismissed && (
            <p className="text-[11px] text-slate-400">
              분석 중으로 바꾼 뒤 종결할 때 판정이 오탐으로 채워집니다.
            </p>
          )}

          <div>
            <label htmlFor="transition-reason" className="mb-1 block text-xs font-medium text-slate-300">
              변경 사유 (필수)
            </label>
            <textarea
              id="transition-reason"
              rows={2}
              required
              maxLength={FREE_TEXT_MAX}
              aria-describedby="transition-reason-count"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="분석 내용과 상태 변경 사유를 입력하세요."
              className="soc-input text-xs"
            />
            <FreeTextCounter id="transition-reason-count" value={reason} />
          </div>

          {needsResponseAction && (
            <p
              role="note"
              aria-label="정탐 종결 안내"
              className="flex items-start gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-100"
            >
              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" aria-hidden="true" />
              {RESPONSE_ACTION_REQUIRED_TEXT}
            </p>
          )}

          <button
            type="submit"
            disabled={transitioning || !reason.trim() || blockedReason !== null || needsResponseAction}
            title={blockedReason ?? undefined}
            className="soc-btn-primary w-full py-2 text-xs"
          >
            {transitioning ? '저장 중...' : nextAllowedStatus === 'investigating' ? '분석 중으로 변경' : '종결 처리'}
          </button>
        </form>
      )}

      {closed && !canTransition && <p className="text-xs text-slate-400">{CLOSED_INCIDENT_TEXT}</p>}
      {!closed && !readOnly && !canTransition && <p className="text-xs text-slate-400">지금 바꿀 수 있는 상태가 없습니다.</p>}

      {/* T53 다시 열기: 확인 단계는 두지 않는다(상태 변경과 같다. 되돌릴 수 있는 동작이다) */}
      {showReopen && (
        <form onSubmit={(e) => void handleReopen(e)} className="space-y-2.5" aria-label="다시 열기">
          <h3 className="soc-subhead">다시 열기</h3>

          <div
            role="note"
            aria-label="다시 열기 안내"
            className="flex items-start gap-1.5 rounded border border-slate-700 bg-slate-900/60 px-2 py-1.5 text-[11px] text-slate-300"
          >
            <Info className="mt-0.5 h-3 w-3 shrink-0 text-slate-400" aria-hidden="true" />
            <div className="space-y-0.5">
              <p>{REOPEN_EFFECT_NOTE}</p>
              <p>{REOPEN_ASSIGN_NOTE}</p>
            </div>
          </div>

          {reopenError && (
            <div
              role="alert"
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
            >
              <span className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
                {reopenError.message}
              </span>
              {reopenError.retryable && (
                <button type="button" onClick={() => void onRefresh()} className="soc-btn-secondary py-1 text-[11px]">
                  <RefreshCw className="h-3 w-3" aria-hidden="true" />
                  다시 불러오기
                </button>
              )}
            </div>
          )}

          <div>
            <label htmlFor="reopen-reason" className="mb-1 block text-xs font-medium text-slate-300">
              다시 여는 사유 (필수)
            </label>
            <textarea
              id="reopen-reason"
              rows={2}
              required
              maxLength={FREE_TEXT_MAX}
              aria-describedby="reopen-reason-count"
              value={reopenReason}
              onChange={(e) => setReopenReason(e.target.value)}
              placeholder="다시 여는 사유와 새로 본 근거를 입력하세요."
              className="soc-input text-xs"
            />
            <FreeTextCounter id="reopen-reason-count" value={reopenReason} />
          </div>

          <button
            type="submit"
            disabled={reopening || !reopenReason.trim() || blockedReason !== null}
            title={blockedReason ?? undefined}
            className="soc-btn-secondary w-full py-2 text-xs"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            {reopening ? '저장 중...' : '다시 열기'}
          </button>
        </form>
      )}

      {/* 에스컬레이션 */}
      <div className="space-y-2.5 border-t border-slate-800 pt-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="soc-subhead flex items-center gap-1.5">
            <ClipboardCheck className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            에스컬레이션
          </h3>
          {analystReview.present && (
            <ReviewActionBadge action={analystReview.reviewAction} pending={analystReview.pending} />
          )}
        </div>

        {!analystReview.present ? (
          <p className="text-xs text-slate-400">이 인시던트에는 에스컬레이션이 없습니다.</p>
        ) : (
          <>
            <div className="space-y-1 text-xs">
              <div className="text-slate-200">
                <LookupText label={reviewReasonText(analystReview.reviewReason)} />
              </div>
              <div className="text-[11px] tabular-nums text-slate-400">
                요청 {formatDateTime(analystReview.requestedAt)}
                {analystReview.decidedAt && ` · 결정 ${formatDateTime(analystReview.decidedAt)}`}
              </div>
              {analystReview.analystDisplay && (
                <div className="text-[11px] text-slate-400">
                  결정자{' '}
                  <span className="text-slate-300 [overflow-wrap:anywhere]" data-raw="">
                    {analystReview.analystDisplay}
                  </span>
                </div>
              )}
              {analystReview.reviewAction && analystReview.resumeStatusLabel && (
                <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                  반영 상태
                  <ResumeStatusBadge
                    label={analystReview.resumeStatusLabel}
                    failed={analystReview.resumeFailed}
                    resumed={analystReview.resumedAt !== null}
                    pending={analystReview.pending}
                  />
                  {phase === 'delayed' && (
                    <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-200">
                      <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                      {RESUME_DELAYED_LABEL}
                    </span>
                  )}
                  {analystReview.resumedAt && (
                    <span className="tabular-nums">{formatDateTime(analystReview.resumedAt)}</span>
                  )}
                </div>
              )}
              {(phase === 'delayed' || phase === 'failed') && (
                <p
                  role="alert"
                  className="flex items-start gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-100"
                >
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" aria-hidden="true" />
                  {phase === 'delayed' ? RESUME_DELAYED_TEXT : RESUME_FAILED_TEXT}
                </p>
              )}
            </div>

            <p className="flex items-start gap-1.5 rounded border border-slate-800 bg-slate-900/60 px-2 py-1.5 text-[11px] text-slate-400">
              <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
              {REVIEW_STATUS_RELATION}
            </p>

            {canDecide && (
              <div className="space-y-2">
                {reviewError && (
                  <div
                    role="alert"
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                  >
                    <span>{reviewError}</span>
                    <button type="button" onClick={() => void onRefresh()} className="soc-btn-secondary py-1 text-[11px]">
                      <RefreshCw className="h-3 w-3" aria-hidden="true" />
                      다시 불러오기
                    </button>
                  </div>
                )}
                <div>
                  <label htmlFor="detail-review-note" className="mb-1 block text-xs font-medium text-slate-300">
                    검토 메모 (오탐 종결 때 필수)
                  </label>
                  <textarea
                    id="detail-review-note"
                    rows={2}
                    maxLength={FREE_TEXT_MAX}
                    aria-describedby="detail-review-note-count"
                    value={reviewNote}
                    onChange={(e) => setReviewNote(e.target.value)}
                    placeholder="결정 근거를 적어 두세요."
                    className="soc-input text-xs"
                  />
                  <FreeTextCounter id="detail-review-note-count" value={reviewNote} />
                </div>
                <ReviewDecisionButtons
                  note={reviewNote}
                  noteInputId="detail-review-note"
                  submitting={decidingReview}
                  onDecide={(action) => void handleReviewDecision(action)}
                  blockedReason={blockedReason}
                  hideBlockedText
                />
              </div>
            )}
          </>
        )}
      </div>

      {/* 최근 이력 */}
      <div className="space-y-2 border-t border-slate-800 pt-3">
        <div className="flex items-center justify-between gap-2">
          <h3 className="soc-subhead flex items-center gap-1.5">
            <History className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            최근 이력
          </h3>
          {statusEvents.length > 0 && (
            <button type="button" onClick={onShowHistory} className="text-[11px] text-cyan-300 hover:underline">
              전체 이력 {statusEvents.length}건
            </button>
          )}
        </div>
        <HistoryTimeline events={recent} emptyText="아직 이력이 없습니다." label="최근 이력" />
      </div>
    </section>
  );
}
