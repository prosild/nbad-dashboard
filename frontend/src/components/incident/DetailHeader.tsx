import { Copy, FileX, Link2 } from 'lucide-react';
import type { IncidentDetailView, IncidentQueueMeta } from '../../types/api';
import { formatDateTime, formatDateTimeRange, formatDuration, formatNumber } from '../../utils/format';
import { captureInfo, detectionModelInfo } from '../../utils/labels';
import {
  CaptureName,
  CodeLabel,
  DetectionModelName,
  IncidentStatusBadge,
  PriorityBadge,
  ResolutionBadge,
  SocBadge,
  VerificationBadge,
  AlertedBadge,
  OngoingBadge,
  SourceTypeBadge,
} from '../StatusBadge';
import { useToast } from '../ToastContext';
import { incidentShareUrl } from '../../utils/incidentLink';
import { AckOverdueBadge, elapsedText } from './AssignmentBits';

/** 복사 버튼 글자. 접근성 이름·툴팁은 버튼에 있다 */
const COPY_LABEL_CLASS = '';

function Field({ label, children, title }: { label: string; children: React.ReactNode; title?: string }) {
  return (
    <span className="inline-flex min-w-0 items-baseline gap-1.5" title={title}>
      <span className="shrink-0 text-[11px] text-slate-500">{label}</span>
      {children}
    </span>
  );
}

/**
 * 인시던트 상세 고정 요약 헤더(T19): 스크롤해도 화면 위에 남는 두 줄.
 * 모델 버전·탐지 작업 시각은 발생 시각 툴팁에만 둔다. 인시던트 ID는 글로 보이지 않고 복사 버튼만 둔다(복사 값은 원문).
 * T23: 우선순위는 서버 값(queueMeta.priority, 상태 변경 뒤 상세를 다시 불러오면 함께 바뀐다)이고,
 * 수집원(종류 + 표시 이름)·탐지 시각·캡처 내 순위·진행 중 표지를 보인다.
 */
export function DetailHeader({
  detail,
  meta = null,
  snapshot = false,
  incidentNo = null,
}: {
  detail: IncidentDetailView;
  meta?: IncidentQueueMeta | null;
  snapshot?: boolean;
  /** T27 인시던트 번호(없으면 번호와 링크 복사를 보이지 않는다) */
  incidentNo?: number | null;
}) {
  const { notify } = useToast();
  const incident = detail.incident;
  const priority = meta?.priority ?? null;
  const jobWhen = detail.job ? (detail.job.finishedAt ?? detail.job.startedAt) : null;
  const capture = captureInfo(incident.captureId);
  // T25: 미종결이면 탐지 뒤 경과(기준 시각까지), 종결이면 처리 시간(종결 = 상태 갱신 시각)
  const elapsed = elapsedText(meta?.detectedAt ?? null, detail.currentStatus, detail.statusUpdatedAt, meta?.anchor ?? null);
  const timeTitle = [
    // T20: 캡처 표시 이름(zeek_AD Q65)과 원래 ID. 헤더 배치는 바꾸지 않고 툴팁에만 둔다.
    `캡처 ${capture.text}${capture.known && capture.raw ? ` · ${capture.raw}` : ''}`,
    `발생 구간 ${formatDateTimeRange(incident.eventStart, incident.eventEnd)}`,
    // T27: '#'은 인시던트 번호에만 쓴다. 작업 번호는 "작업 44"
    `탐지 작업 ${jobWhen ? `${formatDateTime(jobWhen)} (작업 ${incident.jobId})` : `작업 ${incident.jobId}`}`,
    `모델 버전 ${incident.bundleId}`,
  ].join('\n');

  async function copyId() {
    try {
      if (!navigator.clipboard) throw new Error('clipboard');
      await navigator.clipboard.writeText(incident.incidentId);
      notify('인시던트 ID를 복사했습니다.', 'success');
    } catch {
      notify('인시던트 ID를 복사하지 못했습니다.', 'error');
    }
  }

  async function copyLink() {
    if (incidentNo === null) return;
    try {
      if (!navigator.clipboard) throw new Error('clipboard');
      await navigator.clipboard.writeText(incidentShareUrl(incidentNo));
      notify('인시던트 링크를 복사했습니다.', 'success');
    } catch {
      notify('인시던트 링크를 복사하지 못했습니다.', 'error');
    }
  }

  return (
    <section aria-label="인시던트 요약" className="space-y-1.5 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 xl:flex-nowrap" data-detail-head-row="1">
        {incidentNo !== null && (
          <span
            className="shrink-0 font-mono text-sm font-bold tabular-nums text-cyan-200"
            aria-label={`인시던트 번호 ${incidentNo}`}
            data-incident-no=""
          >
            #{incidentNo}
          </span>
        )}
        <PriorityBadge priority={priority} />
        {meta?.ongoing && <OngoingBadge snapshot={snapshot} />}
        <span className="flex items-center gap-1">
          <IncidentStatusBadge status={detail.currentStatus} />
          <ResolutionBadge resolution={detail.currentResolution} />
        </span>
        <span className="inline-flex min-w-0 items-baseline gap-2">
          <span className="font-mono text-sm font-bold text-slate-50">{incident.hostIp}</span>
          {incident.hostName.length > 0 && (
            <span className="max-w-[16rem] truncate font-mono text-slate-400" title={incident.hostName.join(', ')}>
              {incident.hostName.join(', ')}
            </span>
          )}
        </span>
        <Field label="방향">
          <CodeLabel dict="hostRole" value={incident.zeekadRole} className="text-slate-200" />
        </Field>
        <Field label="탐지 모델">
          <DetectionModelName id={incident.zeekadPickedBy} variant="detail" className="font-semibold text-slate-100" />
          {incident.zeekadAlsoFlaggedBy.length > 0 && (
            <SocBadge
              tone="neutral"
              title={incident.zeekadAlsoFlaggedBy.map((m) => detectionModelInfo(m).tooltip).join('\n\n')}
            >
              교차 탐지 +{incident.zeekadAlsoFlaggedBy.length}
            </SocBadge>
          )}
        </Field>
      </div>
      {/* T28: 둘째 줄은 어느 폭에서도 줄을 바꿀 수 있고 항목은 줄어들지 않는다. 줄바꿈을 막으면 1440~1600px에서
          min-w-0 항목이 내용보다 좁아져 서로 덮였다(착수 지연·캡처 내 순위, 경보·AI 리포트, 검증·링크 복사). */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 [&>*]:shrink-0" data-detail-head-row="2">
        <Field label="수집원">
          <SourceTypeBadge type={meta?.sourceType} />
          <CaptureName id={incident.captureId} className="max-w-[14rem] truncate text-slate-200" />
        </Field>
        <Field label="탐지" title="인시던트가 처음 탐지된 분석 완료 시각">
          <span className="tabular-nums text-slate-200">{formatDateTime(meta?.detectedAt ?? null)}</span>
        </Field>
        {elapsed && (
          <Field
            label={elapsed.kind === 'handled' ? '처리' : '경과'}
            title={elapsed.kind === 'handled' ? '처리 시간: 종결 시각 − 탐지 시각' : '탐지 뒤 경과(기준 시각까지)'}
          >
            <span className="shrink-0 whitespace-nowrap tabular-nums text-slate-200" data-detail-elapsed="">
              {elapsed.kind === 'handled' ? elapsed.text.replace(/^처리 /, '') : elapsed.text}
            </span>
            {meta?.ackOverdue && <AckOverdueBadge dueAt={meta?.ackDueAt} detectedAt={meta?.detectedAt ?? null} />}
          </Field>
        )}
        <Field label="캡처 내 순위">
          <span className="tabular-nums text-slate-200">{incident.queueRank}위</span>
        </Field>
        <Field label="발생" title={timeTitle}>
          <span className="tabular-nums text-slate-200">{formatDateTime(incident.eventStart)}</span>
          <span className="tabular-nums text-slate-400">{formatDuration(incident.eventStart, incident.eventEnd)}</span>
        </Field>
        <Field label="세션">
          <span className="tabular-nums text-slate-200">{formatNumber(incident.connectionCount)}건</span>
        </Field>
        <Field label="경보">
          {/* T21: 경보 발송 = 사건 알림 Slack 기록(alerted). 발송 판단은 "발송 판단" 탭에 있다. */}
          <AlertedBadge alerted={incident.alerted} />
        </Field>
        <Field label="AI 리포트">
          {detail.report.present ? (
            detail.report.verificationPassed === null ? (
              <SocBadge tone="neutral">
                <CodeLabel dict="reportKind" value={detail.report.reportKind} />
              </SocBadge>
            ) : (
              <VerificationBadge passed={detail.report.verificationPassed} />
            )
          ) : (
            <SocBadge tone="muted">
              <FileX className="h-3 w-3" aria-hidden="true" />
              리포트 없음
            </SocBadge>
          )}
        </Field>
        <span className="ml-auto inline-flex shrink-0 items-center gap-1.5">
          {incidentNo !== null && (
            <button
              type="button"
              onClick={() => void copyLink()}
              className="inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-[11px] text-slate-400 hover:border-slate-500 hover:text-slate-200"
              aria-label="링크 복사"
              title="이 인시던트의 고정 주소를 복사합니다"
            >
              <Link2 className="h-3 w-3" aria-hidden="true" />
              <span className={COPY_LABEL_CLASS}>링크 복사</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => void copyId()}
            className="inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-[11px] text-slate-400 hover:border-slate-500 hover:text-slate-200"
            aria-label="인시던트 ID 복사"
            title="인시던트 ID 원문을 복사합니다"
          >
            <Copy className="h-3 w-3" aria-hidden="true" />
            <span className={COPY_LABEL_CLASS}>ID 복사</span>
          </button>
        </span>
      </div>
    </section>
  );
}
