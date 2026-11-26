/**
 * 화면 밖으로 가져가는 글(T44): 상세의 마크다운 요약과 인시던트 큐의 CSV.
 * 둘 다 이미 받은 응답만 쓴다(추가 요청 없음). 그래서 조회자는 화면과 같은 가려진 값만 가져간다.
 * 값은 호스트 이름처럼 관측 대상이 정할 수 있는 글이라, 붙여 넣는 쪽에서 뜻이 바뀌지 않게 막는다
 * (마크다운은 코드 표기·기호 이스케이프, CSV는 수식 시작 문자 앞 작은따옴표).
 */
import type { IncidentDetailView, IncidentQueueMeta, ResponseActionItem, UnifiedQueueItem } from '../types/api';
import { DISPLAY_TIME_ZONE_LABEL, formatBytes, formatDateTime, formatDateTimeRange, formatNumber } from './format';
import { captureText, labelText } from './labels';

function cellText(value: unknown): string | null {
  return value === null || value === undefined || value === '' ? null : String(value);
}

/** 증적의 포트 행 → "80/tcp"(전송 계층이 없으면 포트만, 포트가 없으면 null) */
export function portText(row: Record<string, unknown> | null | undefined): string | null {
  const port = cellText(row?.port);
  if (!port) return null;
  const transport = cellText(row?.transport);
  return transport ? `${port}/${transport}` : port;
}

/* ───────────── 상세 마크다운 요약 ───────────── */

const OMITTED = '(식별자 생략)';
/**
 * 화면이 글로 보이지 않는 내부 이름(`zeekad_*` 필드, `dashboard.<뷰·함수>`, `evidence.v1`). 리포트 글에 인용돼 있어도 싣지 않는다.
 * 소문자 그대로만 본다. `dashboard.` 뒤에 점이 더 이어지는 글(`dashboard.corp.example` 같은 호스트 이름)은 내부 이름이 아니다.
 */
const INTERNAL_NAME = /zeekad_[\w.]+|dashboard\.[a-z][a-z0-9_]*(?!\.?[\w-])|evidence\.v1/g;

/** 한 줄 값으로 만들고(줄바꿈으로 제목·목록을 만들지 못하게) 이 인시던트의 ID·모델 버전을 뺀다 */
function plain(value: string, hidden: string[]): string {
  let text = value;
  for (const id of hidden) {
    if (id) text = text.split(id).join(OMITTED);
  }
  return text.replace(/\s+/g, ' ').trim();
}

/** 서술 글: 내부 이름을 빼고 마크다운 기호와 HTML 꺾쇠를 글자 그대로 보이게 한다 */
function mdText(value: string, hidden: string[]): string {
  return plain(value, hidden).replace(INTERNAL_NAME, OMITTED).replace(/[\\`*[\]<>]/g, '\\$&');
}

/**
 * 주소·이름·포트: 코드 표기(가려진 주소의 `*`가 강조로 읽히지 않고, 안의 글은 해석되지 않는다).
 * 관측한 값이므로 내부 이름 규칙으로 바꾸지 않는다(호스트 이름이 화면과 달라지면 안 된다).
 */
function mdCode(value: string, hidden: string[]): string {
  return `\`${plain(value, hidden).replace(/`/g, "'")}\``;
}

function withZone(text: string): string {
  return text === '-' ? text : `${text} ${DISPLAY_TIME_ZONE_LABEL}`;
}

function sessionSuffix(row: Record<string, unknown>): string {
  return typeof row.connections === 'number' ? ` · 세션 ${formatNumber(row.connections)}건` : '';
}

const SUMMARY_PEERS = 5;
const SUMMARY_PORTS = 3;

/**
 * 인시던트 한 건의 한국어 마크다운 요약. 인시던트 ID·모델 버전 같은 내부 식별자는 넣지 않는다.
 * T56: responseActions(상세 응답의 바깥 값, 시간 역순)가 있으면 끝에 "대응 조치" 항목을 시각순으로 싣는다.
 * 화면이 받은 값만 쓴다(조회자는 메모가 없다). 값이 없으면(옛 응답) 항목을 싣지 않는다.
 */
export function incidentMarkdown(
  detail: IncidentDetailView,
  meta: IncidentQueueMeta | null,
  incidentNo: number | null,
  responseActions?: ResponseActionItem[],
): string {
  const { incident, evidence, report } = detail;
  const hidden = [incident.incidentId, incident.bundleId];
  const text = (value: string) => mdText(value, hidden);
  const code = (value: string) => mdCode(value, hidden);

  const host = [incident.hostIp, ...incident.hostName].filter(Boolean).map(code).join(' · ');
  const sessions = (evidence.available ? evidence.connectionCount : null) ?? incident.connectionCount;
  const peers = evidence.available
    ? evidence.topPeers
        .filter((row) => typeof row.ip === 'string' && row.ip !== '')
        .slice(0, SUMMARY_PEERS)
        .map((row) => `${code(row.ip as string)}${sessionSuffix(row)}`)
    : [];
  const ports = evidence.available
    ? evidence.topPorts
        .slice(0, SUMMARY_PORTS)
        .flatMap((row) => {
          const label = portText(row);
          return label ? [`${code(label)}${sessionSuffix(row)}`] : [];
        })
    : [];

  const lines = [
    incidentNo === null ? '# 인시던트 요약' : `# 인시던트 #${incidentNo} 요약`,
    '',
    '## 기본 정보',
    `- 우선순위: ${text(labelText('priority', meta?.priority ?? null))}`,
    // T52 중요 자산: 예/아니요만(이름·설명은 싣지 않는다). 메타가 없으면 "-"
    `- 중요 자산: ${meta ? (meta.assetCritical ? '예' : '아니요') : '-'}`,
    `- 상태: ${text(labelText('incidentStatus', detail.currentStatus || 'open'))}`,
    `- 판정: ${text(labelText('resolution', detail.currentResolution))}`,
    `- 호스트: ${host || '-'}`,
    `- 방향: ${text(labelText('hostRole', incident.zeekadRole))}`,
    `- 수집원: ${text(captureText(incident.captureId))}`,
    `- 탐지 시각: ${withZone(formatDateTime(meta?.detectedAt ?? null))}`,
    `- 발생 구간: ${withZone(formatDateTimeRange(incident.eventStart, incident.eventEnd))}`,
    `- 탐지 모델: ${text(labelText('detectionModel', incident.zeekadPickedBy))}`,
    '',
    '## 주요 증적',
    `- 세션 수: ${sessions === null ? '-' : `${formatNumber(sessions)}건`}`,
    `- 송신 바이트: ${formatBytes(evidence.available ? evidence.bytesSent : null)}`,
    `- 수신 바이트: ${formatBytes(evidence.available ? evidence.bytesReceived : null)}`,
    `- 주요 상대 IP: ${peers.join(', ') || '-'}`,
    `- 주요 포트: ${ports.join(', ') || '-'}`,
  ];

  if (report.present) {
    lines.push('', '## 리포트', `- 구분: ${text(labelText('reportKind', report.reportKind))}`);
    if ((report.reportKind ?? '').trim().toLowerCase() === 'template') {
      lines.push('- [템플릿 리포트 — AI 리포트 대체]');
    }
    if (report.verificationPassed !== null) {
      lines.push(`- 검증: ${labelText('verification', report.verificationPassed)}`);
    }
    const sections: Array<[string, string[]]> = [
      ['관측 요약', report.observationSummary ? [report.observationSummary] : []],
      ['확인된 사실', report.claims.map((item) => item.claim)],
      ['관련 ATT&CK 기법 후보', report.attackCandidates.map((item) => `${item.attackId} ${item.name}`)],
      ['추가 확인 권고', report.followUp],
    ];
    for (const [label, values] of sections) {
      const items = values.map(text).filter((value) => value !== '');
      if (items.length > 0) lines.push('', `### ${label}`, ...items.map((value) => `- ${value}`));
    }
  }
  if (responseActions !== undefined) {
    lines.push('', '## 대응 조치');
    if (responseActions.length === 0) lines.push('- 기록 없음');
    for (const item of [...responseActions].reverse()) {
      const note = item.note ? text(item.note) : '';
      lines.push(
        `- ${text(labelText('responseAction', item.action))} (기록 ${withZone(formatDateTime(item.recordedAt))})${note ? `: ${note}` : ''}`,
      );
    }
  }
  return `${lines.join('\n')}\n`;
}

/* ───────────── 인시던트 큐 CSV ───────────── */

/** 수식으로 읽히는 시작: 앞의 스페이스만 건너뛴 첫 글자가 `=` `+` `-` `@` 탭·줄바꿈. 탭·줄바꿈까지 지우는 trimStart로 보지 않는다. */
const FORMULA_START = /^ *[=+\-@\t\r\n]/;

/** CSV 한 칸: 값 없음은 빈 글, 수식 시작이면 원문 앞에 작은따옴표, 그다음 쌍따옴표로 감싼다(RFC 4180) */
export function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? '' : String(value);
  const safe = FORMULA_START.test(raw) ? `'${raw}` : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}

export const QUEUE_CSV_HEADERS = [
  '번호',
  '우선순위',
  '중요 자산',
  '탐지 시각(KST)',
  '호스트 IP',
  '호스트 이름',
  '수집원',
  '통신 방향',
  '발생 시작(KST)',
  '발생 종료(KST)',
  '탐지 모델',
  '교차 탐지',
  '리포트 종류',
  '발송 판단',
  '경보 발송',
  '상태',
  '판정',
  '담당',
  '세션 수',
] as const;

/** 표시 이름. 값이 없으면 "-"가 아니라 빈 칸 */
function label(dict: Parameters<typeof labelText>[0], value: string | null | undefined): string {
  return value ? labelText(dict, value) : '';
}

function time(iso: string | null | undefined): string {
  return iso ? formatDateTime(iso) : '';
}

/** 큐 한 쪽의 CSV. 화면과 같은 표시 이름·시각(KST)을 쓰고, 엑셀이 한글을 읽게 UTF-8 BOM과 CRLF를 쓴다. */
export function queueCsv(items: UnifiedQueueItem[]): string {
  const rows = items.map((item) => [
    item.incidentNo,
    label('priority', item.priority),
    // T52 중요 자산: 예/아니요만(이름은 넣지 않는다. 조회자도 같다)
    item.assetCritical ? '예' : '아니요',
    time(item.detectedAt),
    item.hostIp,
    item.hostName.join(', '),
    item.captureId ? captureText(item.captureId) : '',
    label('hostRole', item.zeekadRole),
    time(item.eventStart),
    time(item.eventEnd),
    label('detectionModel', item.zeekadPickedBy),
    item.zeekadAlsoFlaggedBy.map((id) => labelText('detectionModel', id)).join(', '),
    label('reportKind', item.zeekadReportKind),
    item.zeekadWouldSend ? '발송' : '보류',
    item.alerted ? '경보 발송' : '발송 기록 없음',
    labelText('incidentStatus', item.zeekadStatus || 'open'),
    label('resolution', item.zeekadResolution),
    item.assignee?.displayName,
    item.connectionCount,
  ]);
  return `﻿${[QUEUE_CSV_HEADERS, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
}

/** 파일 이름: `incidents-YYYYMMDD-HHmm.csv`(KST) */
export function queueCsvFileName(now: Date = new Date()): string {
  const stamp = formatDateTime(now.toISOString()).slice(0, 16).replace(/[-:]/g, '').replace(' ', '-');
  return `incidents-${stamp}.csv`;
}

export function downloadQueueCsv(items: UnifiedQueueItem[]): void {
  const url = URL.createObjectURL(new Blob([queueCsv(items)], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = queueCsvFileName();
  document.body.appendChild(link);
  try {
    link.click();
  } finally {
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
