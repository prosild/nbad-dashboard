import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Bell,
  BellOff,
  CheckCircle2,
  Circle,
  CircleDot,
  Clock,
  Loader,
  Minus,
  ShieldCheck,
} from 'lucide-react';
import {
  detectionModelInfo,
  labelText,
  lookupLabel,
  unregisteredTitle,
  type LabelDictionaryName,
  type LabelLookup,
} from '../utils/labels';
import type { Priority } from '../utils/triage';

/**
 * 색 체계(docs/ui-terminology.md '색·배지 체계'):
 * - danger(빨강): 높은 위험·우선순위·정탐(실제 위협) 전용
 * - attention(주황): 사람 손이 필요함(에스컬레이션 대기, 반영 실패, 작업 실패, 검증 실패 등) 전용
 * - neutral(회색): 상태·정보. 상태는 아이콘으로 구분한다
 * - info(하늘): 진행 중(분석 중, 진행 중)
 * - positive(초록): 정상 판정·검증 통과
 * - notice(청록): 경보 발송
 * - violet(보라): 오탐 판정
 * - emphasis(밝은 회색 테두리): 우선순위 Medium처럼 중립이지만 눈에 띄어야 하는 값
 * - muted(흐린 회색): 우선순위 Low·종결, 값 없음
 */
export type BadgeTone =
  | 'danger'
  | 'attention'
  | 'neutral'
  | 'emphasis'
  | 'info'
  | 'positive'
  | 'notice'
  | 'violet'
  | 'muted';

const TONE_CLASS: Record<BadgeTone, string> = {
  danger: 'border-rose-500/40 bg-rose-500/15 text-rose-200',
  attention: 'border-amber-500/40 bg-amber-500/15 text-amber-200',
  neutral: 'border-slate-700 bg-slate-800/80 text-slate-200',
  emphasis: 'border-slate-300/70 bg-slate-700/40 text-slate-50',
  info: 'border-sky-500/35 bg-sky-500/10 text-sky-200',
  positive: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-200',
  notice: 'border-cyan-500/35 bg-cyan-500/10 text-cyan-200',
  violet: 'border-violet-500/35 bg-violet-500/10 text-violet-200',
  muted: 'border-slate-800 bg-transparent text-slate-400',
};

export function SocBadge({
  tone = 'neutral',
  title,
  children,
}: {
  tone?: BadgeTone;
  title?: string;
  children: React.ReactNode;
}) {
  return (
    <span
      title={title}
      className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium leading-tight ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * 코드 값을 표시 이름 사전으로 바꿔 보여 준다. 원래 코드 값은 툴팁(title)으로만 둔다.
 * 사전에 없는 값은 원래 값을 흐린 글자로 보이고 "미등록 값" 툴팁을 단다.
 */
export function CodeLabel({
  dict,
  value,
  className = '',
}: {
  dict: LabelDictionaryName;
  value: string | boolean | null | undefined;
  className?: string;
}) {
  return <LookupText label={lookupLabel(dict, value)} className={className} />;
}

/** 사전 조회 결과(LabelLookup)를 보여 준다. 미등록 값은 흐린 원문 + "미등록 값" 툴팁. */
export function LookupText({ label, className = '' }: { label: LabelLookup; className?: string }) {
  if (!label.known) {
    return (
      <span data-unregistered="" title={unregisteredTitle(label.raw)} className={`font-mono text-slate-500 ${className}`}>
        {label.text}
      </span>
    );
  }
  return (
    <span title={label.raw && label.raw !== label.text ? label.raw : undefined} className={className}>
      {label.text}
    </span>
  );
}

/**
 * 탐지 모델 이름(zeek_AD '모델 표시 이름'). 표(`variant="table"`)에는 표시 이름만 보이고 "모델 종류 · 식별자"와 설명은 툴팁에 둔다.
 * 상세(`variant="detail"`)는 표시 이름 옆에 "모델 종류 · 식별자"를 함께 보인다(식별자 요소는 data-raw).
 * 사전에 없는 식별자는 흐린 원문 + "미등록 값" 툴팁이다.
 */
export function DetectionModelName({
  id,
  variant = 'table',
  className = '',
}: {
  id: string | null | undefined;
  variant?: 'table' | 'detail';
  className?: string;
}) {
  const info = detectionModelInfo(id);
  if (!info.known || !info.kind) {
    return <LookupText label={info} className={className} />;
  }
  if (variant === 'detail') {
    return (
      <span className={`inline-flex flex-wrap items-baseline gap-x-1.5 ${className}`} title={info.tooltip}>
        <span>{info.text}</span>
        <span className="font-mono text-[11px] font-normal text-slate-400" data-raw="">
          {info.kindAndId}
        </span>
      </span>
    );
  }
  return (
    <span className={className} title={info.tooltip}>
      {info.text}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status: string | null | undefined }) {
  const norm = (status ?? 'open').toLowerCase();
  const tone: BadgeTone = norm === 'investigating' ? 'info' : norm === 'closed' ? 'muted' : 'neutral';
  const Icon = norm === 'investigating' ? CircleDot : norm === 'closed' ? CheckCircle2 : Circle;
  return (
    <SocBadge tone={tone}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      <CodeLabel dict="incidentStatus" value={norm} />
    </SocBadge>
  );
}

export function ResolutionBadge({ resolution }: { resolution: string | null | undefined }) {
  if (!resolution) {
    return null;
  }
  const norm = resolution.toLowerCase();
  const tone: BadgeTone =
    norm === 'true_positive' ? 'danger' : norm === 'false_positive' ? 'violet' : norm === 'benign' ? 'positive' : 'neutral';
  return (
    <SocBadge tone={tone}>
      <span className="text-slate-400">판정</span>
      <CodeLabel dict="resolution" value={norm} />
    </SocBadge>
  );
}

/** 분석가 판단: 결정 전이면 '대기'(주황), 결정 후는 중립색 + 체크 아이콘 */
export function ReviewActionBadge({
  action,
  pending,
}: {
  action: string | null | undefined;
  pending?: boolean;
}) {
  if (pending || !action) {
    return pending ? (
      <SocBadge tone="attention">
        <Clock className="h-3 w-3" aria-hidden="true" />
        대기
      </SocBadge>
    ) : (
      <SocBadge tone="muted">-</SocBadge>
    );
  }
  return (
    <SocBadge tone="neutral">
      <CheckCircle2 className="h-3 w-3 text-slate-400" aria-hidden="true" />
      <CodeLabel dict="reviewAction" value={action.toLowerCase()} />
    </SocBadge>
  );
}

/** 판단 결정의 자동 처리 반영 상태. 실패만 주황, 나머지는 중립색 + 아이콘 */
export function ResumeStatusBadge({
  label,
  failed,
  resumed,
  pending,
}: {
  label: string;
  failed: boolean;
  resumed: boolean;
  pending: boolean;
}) {
  if (failed) {
    return (
      <SocBadge tone="attention">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        {label}
      </SocBadge>
    );
  }
  if (pending) {
    return (
      <SocBadge tone="attention">
        <Clock className="h-3 w-3" aria-hidden="true" />
        {label}
      </SocBadge>
    );
  }
  const Icon = resumed ? CheckCircle2 : Loader;
  return (
    <SocBadge tone="neutral">
      <Icon className="h-3 w-3 text-slate-400" aria-hidden="true" />
      {label}
    </SocBadge>
  );
}

/** 경보 발송 판단 결과(would_send) */
export function WouldSendBadge({ wouldSend }: { wouldSend: boolean | null | undefined }) {
  return wouldSend ? (
    <SocBadge tone="notice">
      <Bell className="h-3 w-3" aria-hidden="true" />
      경보 발송
    </SocBadge>
  ) : (
    <SocBadge tone="muted">
      <BellOff className="h-3 w-3" aria-hidden="true" />
      보류
    </SocBadge>
  );
}

/** 리포트 검증 결과 */
export function VerificationBadge({ passed }: { passed: boolean | null | undefined }) {
  if (passed === null || passed === undefined) {
    return null;
  }
  return passed ? (
    <SocBadge tone="positive">
      <ShieldCheck className="h-3 w-3" aria-hidden="true" />
      <CodeLabel dict="verification" value={true} />
    </SocBadge>
  ) : (
    <SocBadge tone="attention">
      <AlertTriangle className="h-3 w-3" aria-hidden="true" />
      <CodeLabel dict="verification" value={false} />
    </SocBadge>
  );
}

/** 탐지 작업 상태 */
export function JobStatusBadge({ status }: { status: string | null | undefined }) {
  const norm = (status ?? '').toLowerCase();
  if (norm === 'failed') {
    return (
      <SocBadge tone="attention">
        <AlertTriangle className="h-3 w-3" aria-hidden="true" />
        <CodeLabel dict="jobStatus" value={norm} />
      </SocBadge>
    );
  }
  if (norm === 'succeeded') {
    return (
      <SocBadge tone="neutral">
        <CheckCircle2 className="h-3 w-3 text-slate-400" aria-hidden="true" />
        <CodeLabel dict="jobStatus" value={norm} />
      </SocBadge>
    );
  }
  return (
    <SocBadge tone="info">
      <Loader className="h-3 w-3" aria-hidden="true" />
      <CodeLabel dict="jobStatus" value={status} />
    </SocBadge>
  );
}

/** 사용자 역할(정보성: 중립색) */
export function UserRoleBadge({ role }: { role: string | null | undefined }) {
  return (
    <SocBadge tone="neutral">
      <CodeLabel dict="userRole" value={role} />
    </SocBadge>
  );
}

/** 자동 분류 우선순위 툴팁. 분석가 판정이 아니라 화면이 계산한 값임을 알린다. */
export const PRIORITY_TOOLTIP = '자동 분류 우선순위: 파이프라인 결과로 화면이 계산한 값이며 분석가 판정이 아닙니다';
export const NO_PRIORITY_TOOLTIP = '종결된 인시던트는 우선순위를 매기지 않습니다';

/**
 * 자동 분류 우선순위. High = 빨강(danger), Medium = 밝은 회색 테두리(emphasis), Low = 흐린 회색(muted),
 * 종결(우선순위 없음) = 흐린 '-'. 주황은 "사람 손 필요" 전용이라 쓰지 않는다.
 */
export function PriorityBadge({ priority }: { priority: Priority | null }) {
  if (priority === null) {
    return (
      <SocBadge tone="muted" title={NO_PRIORITY_TOOLTIP}>
        <span aria-hidden="true">-</span>
        <span className="sr-only">우선순위 없음</span>
      </SocBadge>
    );
  }
  const tone: BadgeTone = priority === 'high' ? 'danger' : priority === 'medium' ? 'emphasis' : 'muted';
  const Icon = priority === 'high' ? ArrowUp : priority === 'medium' ? Minus : ArrowDown;
  return (
    <SocBadge tone={tone} title={PRIORITY_TOOLTIP}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      {labelText('priority', priority)}
    </SocBadge>
  );
}
