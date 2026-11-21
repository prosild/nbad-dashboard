import { Copy, FileX } from 'lucide-react';
import type { IncidentDetailView } from '../../types/api';
import { formatDateTime, formatDateTimeRange, formatDuration, formatNumber } from '../../utils/format';
import { captureInfo, detectionModelInfo } from '../../utils/labels';
import { computePriority } from '../../utils/triage';
import {
  CodeLabel,
  DetectionModelName,
  IncidentStatusBadge,
  PriorityBadge,
  ResolutionBadge,
  SocBadge,
  VerificationBadge,
  WouldSendBadge,
} from '../StatusBadge';
import { useToast } from '../ToastContext';

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
 * 캡처·모델 버전·탐지 작업 시각은 발생 시각 툴팁에만 둔다. 인시던트 ID는 글로 보이지 않고 복사 버튼만 둔다(복사 값은 원문).
 */
export function DetailHeader({ detail }: { detail: IncidentDetailView }) {
  const { notify } = useToast();
  const incident = detail.incident;
  // 상태 변경 직후에도 맞도록 상세의 현재 상태로 계산한다(L1).
  const priority = computePriority({ ...incident, zeekadStatus: detail.currentStatus });
  const jobWhen = detail.job ? (detail.job.finishedAt ?? detail.job.startedAt) : null;
  const capture = captureInfo(incident.captureId);
  const timeTitle = [
    // T20: 캡처 표시 이름(zeek_AD Q65)과 원래 ID. 헤더 배치는 바꾸지 않고 툴팁에만 둔다.
    `캡처 ${capture.text}${capture.known && capture.raw ? ` · ${capture.raw}` : ''}`,
    `발생 구간 ${formatDateTimeRange(incident.eventStart, incident.eventEnd)}`,
    `탐지 작업 ${jobWhen ? formatDateTime(jobWhen) : `#${incident.jobId}`}`,
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

  return (
    <section aria-label="인시던트 요약" className="space-y-1.5 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <PriorityBadge priority={priority} />
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
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <Field label="발생" title={timeTitle}>
          <span className="tabular-nums text-slate-200">{formatDateTime(incident.eventStart)}</span>
          <span className="tabular-nums text-slate-400">{formatDuration(incident.eventStart, incident.eventEnd)}</span>
        </Field>
        <Field label="세션">
          <span className="tabular-nums text-slate-200">{formatNumber(incident.connectionCount)}건</span>
        </Field>
        <Field label="경보">
          <WouldSendBadge wouldSend={incident.zeekadWouldSend} />
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
        <button
          type="button"
          onClick={() => void copyId()}
          className="ml-auto inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-[11px] text-slate-400 hover:border-slate-500 hover:text-slate-200"
          aria-label="인시던트 ID 복사"
          title="인시던트 ID 원문을 복사합니다"
        >
          <Copy className="h-3 w-3" aria-hidden="true" />
          ID 복사
        </button>
      </div>
    </section>
  );
}
