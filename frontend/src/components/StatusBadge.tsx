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
  Crown,
  Database,
  Loader,
  Minus,
  Radio,
  ShieldCheck,
} from 'lucide-react';
import {
  captureInfo,
  detectionModelInfo,
  labelText,
  lookupLabel,
  unregisteredTitle,
  VERIFICATION_DESCRIPTION,
  type LabelDictionaryName,
  type LabelLookup,
} from '../utils/labels';
import type { Priority } from '../utils/triage';
import type { SourceType } from '../types/api';

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
  ...data
}: {
  tone?: BadgeTone;
  title?: string;
  children: React.ReactNode;
} & { [key: `data-${string}`]: string | undefined }) {
  return (
    <span
      {...data}
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

/**
 * 캡처(수집 구간) 표시 이름(zeek_AD Q65). 표시 이름만 보이고 zeek_AD 설명과 원래 캡처 ID는 툴팁에 둔다.
 * 규칙에 맞지 않는 ID는 원래 ID를 흐리게 보이고 "미등록 값" 툴팁을 단다(이때 글은 ID 원문이라 data-raw).
 */
export function CaptureName({ id, className = '' }: { id: string | null | undefined; className?: string }) {
  const info = captureInfo(id);
  if (!info.known) {
    return (
      <span data-unregistered="" data-raw="" title={info.tooltip} className={`font-mono text-slate-500 ${className}`}>
        {info.text}
      </span>
    );
  }
  return (
    <span className={className} title={info.tooltip || undefined}>
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

/**
 * 발송 판단 결과(zeek_AD would_send): 발송 / 보류. T21: "경보 발송"이라 부르지 않는다.
 * "경보 발송"은 사건 알림 Slack 기록이 있다는 뜻이고(AlertedBadge), 발송 판단과 다를 수 있다.
 */
export function WouldSendBadge({ wouldSend }: { wouldSend: boolean | null | undefined }) {
  return wouldSend ? (
    <SocBadge tone="notice" title="발송 판단: 발송">
      <Bell className="h-3 w-3" aria-hidden="true" />
      발송
    </SocBadge>
  ) : (
    <SocBadge tone="muted" title="발송 판단: 보류">
      <BellOff className="h-3 w-3" aria-hidden="true" />
      보류
    </SocBadge>
  );
}

/** 경보 발송(T21): 사건 알림 Slack 기록(상태 후속 알림 제외)이 있는 인시던트. 현황판 KPI·목록 필터와 같은 정의 */
export function AlertedBadge({ alerted }: { alerted: boolean | null | undefined }) {
  return alerted ? (
    <SocBadge tone="notice" title="사건 알림 Slack 기록이 있습니다(dry-run 기록·발송 실패 기록 포함)">
      <Bell className="h-3 w-3" aria-hidden="true" />
      경보 발송
    </SocBadge>
  ) : (
    <SocBadge tone="muted" title="사건 알림 Slack 기록이 없습니다">
      <BellOff className="h-3 w-3" aria-hidden="true" />
      발송 기록 없음
    </SocBadge>
  );
}

/** 리포트 검증 결과 */
export function VerificationBadge({ passed }: { passed: boolean | null | undefined }) {
  if (passed === null || passed === undefined) {
    return null;
  }
  // T37: 이름은 "검증 통과"·"검증 실패" 그대로 두고 툴팁·접근성 이름에 무엇을 검증했는지 적는다.
  const description = passed ? VERIFICATION_DESCRIPTION.passed : VERIFICATION_DESCRIPTION.failedDetail;
  return (
    <span role="img" aria-label={description} title={description} className="inline-flex">
      {passed ? (
        <SocBadge tone="positive">
          <ShieldCheck className="h-3 w-3" aria-hidden="true" />
          {labelText('verification', true)}
        </SocBadge>
      ) : (
        <SocBadge tone="attention">
          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
          {labelText('verification', false)}
        </SocBadge>
      )}
    </span>
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

/** 자동 분류 우선순위 툴팁. 분석가 판정이 아니라 서버가 계산한 값임을 알린다(T52: 중요 자산 등록도 반영). */
export const PRIORITY_TOOLTIP =
  '자동 분류 우선순위: 파이프라인 결과와 중요 자산 등록으로 서버가 계산한 값이며 분석가 판정이 아닙니다';
/** 데스크톱 인시던트 목록 표의 우선순위 열 머리 툴팁(T62: 그 칸의 중요 자산 표지는 왕관 아이콘만 보인다) */
export const PRIORITY_COLUMN_TOOLTIP = `${PRIORITY_TOOLTIP}.\n왕관 아이콘: 중요 자산으로 등록된 호스트입니다(미종결이면 우선순위를 한 단계 올립니다. 이미 High면 그대로). 아이콘의 툴팁에 자세한 설명이 있습니다`;
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

/* ───────────── T52 중요 자산 ───────────── */

export const CRITICAL_ASSET_LABEL = '중요 자산';
export const CRITICAL_ASSET_BAND_TOOLTIP = '이 대역에 중요 자산으로 등록된 호스트가 있습니다';

type QueuePriorityValue = 'high' | 'medium' | 'low';

/** 올렸으면 "Medium → High", 아니면 null */
export function criticalAssetRaise(
  priority: QueuePriorityValue | null | undefined,
  priorityBase: QueuePriorityValue | null | undefined,
): string | null {
  if (!priority || !priorityBase || priority === priorityBase) return null;
  return `${labelText('priority', priorityBase)} → ${labelText('priority', priority)}`;
}

/**
 * 중요 자산 표지의 설명 글(툴팁과 화면 읽기 글이 같은 글을 쓴다). 이름은 분석가·관리자에게만 온다(조회자 응답은 null).
 * - 올렸으면: "…한 단계 올렸습니다(Medium → High)"  - 이미 High면: "…이미 High라 우선순위는 그대로입니다"
 * - 종결·호스트 줄: "중요 자산으로 등록된 호스트입니다"  - 조회자의 대역 줄(band): "이 대역에 …"
 */
export function criticalAssetTooltip({
  priority,
  priorityBase,
  name,
  band = false,
}: {
  priority?: QueuePriorityValue | null;
  priorityBase?: QueuePriorityValue | null;
  name?: string | null;
  band?: boolean;
}): string {
  let text: string;
  const raise = criticalAssetRaise(priority, priorityBase);
  if (band) {
    text = CRITICAL_ASSET_BAND_TOOLTIP;
  } else if (raise) {
    text = `중요 자산으로 등록된 호스트라 자동 분류 우선순위를 한 단계 올렸습니다(${raise})`;
  } else if (priority === 'high') {
    text = '중요 자산으로 등록된 호스트입니다. 이미 High라 우선순위는 그대로입니다';
  } else {
    text = '중요 자산으로 등록된 호스트입니다';
  }
  return name ? `${text}\n중요 자산: ${name}` : text;
}

/**
 * 중요 자산 표지(우선순위 배지 옆). 색만으로 뜻을 전하지 않게 글자 "중요 자산"을 두고,
 * 툴팁만으로는 휴대폰·키보드 사용자가 볼 수 없어 같은 설명을 화면 읽기 글로도 둔다.
 * showRaise면 올림을 보이는 글로 붙인다(상세 머리줄: "중요 자산 · Medium → High").
 * masked면 이름을 쓰지 않는다(조회자. 서버도 이름을 주지 않는다).
 * iconOnly면 보이는 글 없이 작은 원 안의 왕관 아이콘만 둔다(데스크톱 인시던트 목록 표의 우선순위 칸, T62). 글 표지가 칸을
 * 96px에서 177px로 넓혀 1280px 표가 넘쳤고, 배지 꼴의 아이콘도 칸에 34px를 더해 1536px에서 넘쳤다. 그래서 놓는 쪽(큐 칸)이
 * 우선순위 배지 모서리에 겹쳐 둔다. 툴팁과 화면 읽기 글은 같고, 왕관의 뜻은 우선순위 열 머리 툴팁에도 적는다.
 */
export function CriticalAssetBadge({
  priority,
  priorityBase,
  name,
  band = false,
  masked = false,
  showRaise = false,
  iconOnly = false,
}: {
  priority?: QueuePriorityValue | null;
  priorityBase?: QueuePriorityValue | null;
  name?: string | null;
  band?: boolean;
  masked?: boolean;
  showRaise?: boolean;
  iconOnly?: boolean;
}) {
  const tooltip = criticalAssetTooltip({ priority, priorityBase, name: masked ? null : name, band });
  const raise = showRaise && !band ? criticalAssetRaise(priority, priorityBase) : null;
  if (iconOnly) {
    return (
      <span
        title={tooltip}
        data-critical-asset="icon"
        className="inline-flex h-3.5 w-3.5 items-center justify-center rounded-full border border-sky-500/60 bg-slate-950 text-sky-200"
      >
        <Crown className="h-2.5 w-2.5" aria-hidden="true" />
        <span className="sr-only">{tooltip.replace('\n', '. ')}</span>
      </span>
    );
  }
  return (
    <SocBadge tone="info" title={tooltip} data-critical-asset="">
      <Crown className="h-3 w-3" aria-hidden="true" />
      <span aria-hidden="true">{raise ? `${CRITICAL_ASSET_LABEL} · ${raise}` : CRITICAL_ASSET_LABEL}</span>
      <span className="sr-only">{tooltip.replace('\n', '. ')}</span>
    </SocBadge>
  );
}

/* ───────────── T23 통합 큐: 수집원·진행 중·새 인시던트 ───────────── */

/** 수집원 종류 표시 이름(docs/ui-terminology.md) */
export const SOURCE_TYPE_LABEL: Record<SourceType, string> = {
  live: '실습망 센서',
  imported: '가져온 데이터',
};

export const SOURCE_TYPE_TOOLTIP: Record<SourceType, string> = {
  live: '실습망 센서: 실습망 VM이 실제로 수집하고 5분 파일마다 다시 분석하는 수집원',
  imported: '가져온 데이터: 공개 데이터셋(PCAP)을 가져와 분석한 수집원. 발생 시각은 원본 그대로입니다',
};

/** 수집원 종류 배지(정보성: 중립색, 아이콘으로 구분) */
export function SourceTypeBadge({ type }: { type: SourceType | null | undefined }) {
  if (type !== 'live' && type !== 'imported') {
    return <SocBadge tone="muted">-</SocBadge>;
  }
  const Icon = type === 'live' ? Radio : Database;
  return (
    <SocBadge tone="neutral" title={SOURCE_TYPE_TOOLTIP[type]}>
      <Icon className="h-3 w-3 text-slate-400" aria-hidden="true" />
      {SOURCE_TYPE_LABEL[type]}
    </SocBadge>
  );
}

export const ONGOING_TOOLTIP =
  '진행 중: 실습망 센서의 종결되지 않은 인시던트이며, 마지막 윈도우가 그 캡처의 최신 윈도우이고 기준 시각 15분 안에 끝났습니다';

/** 진행 중 표지(하늘색 = 진행 중). 고정 스냅샷이면 툴팁에 "기준 시각 기준"을 적는다. */
export function OngoingBadge({ snapshot = false }: { snapshot?: boolean }) {
  return (
    <SocBadge tone="info" title={snapshot ? `${ONGOING_TOOLTIP}(기준 시각 기준)` : ONGOING_TOOLTIP}>
      <Loader className="h-3 w-3" aria-hidden="true" />
      진행 중
    </SocBadge>
  );
}

/** 새 인시던트 표지(새 인시던트 띠로 불러온 행, 다음 불러오기 전까지) */
export function NewRowBadge() {
  return (
    <SocBadge tone="emphasis" title="방금 불러온 새 인시던트">
      새
    </SocBadge>
  );
}
