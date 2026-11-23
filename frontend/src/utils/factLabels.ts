/**
 * AI 리포트 근거 사실(zeek_AD `zeekad_facts`, `[{id, name, value}]`) 표시 사전(T37).
 * 사실 이름은 규칙(`baseline.<지표>`, `conn_state.<상태>`, `protocol.<이름>`, `top_peer_<N>` 등)으로 한국어 항목 이름을 만들고,
 * 값은 이름이 정한 모양(숫자·바이트·초·비율·객체)대로 읽기 좋게 보인다. 상태·역할·모델 이름은 labels.ts 사전을 다시 쓴다.
 * 사전에 없는 이름이나 이름과 맞지 않는 값 모양은 원문 그대로 보인다(known=false, 화면은 data-raw). 값을 지어내거나 숨기지 않는다.
 * 값을 다시 계산해 리포트 문장과 맞는지 판정하지 않는다(검증은 zeek_AD가 한다). 같은 내용을 docs/ui-terminology.md에 남긴다.
 */
import type { FactItem } from '../types/api';
import { formatNumber, formatSeconds, formatSessionDuration } from './format';
import { lookupLabel, labelText } from './labels';

/** 근거 사실 전체 표의 묶음(표시 순서) */
export const FACT_GROUPS = [
  { key: 'overview', label: '규모·방향' },
  { key: 'detection', label: '탐지 모델' },
  { key: 'baseline', label: '평소 대비' },
  { key: 'distribution', label: '세션 상태·전송 계층·서비스 프로토콜' },
  { key: 'protocolLog', label: '프로토콜 로그' },
  { key: 'peers', label: '상대 IP·목적지 포트' },
  { key: 'sessions', label: '주요 세션' },
  { key: 'other', label: '사전에 없는 항목' },
] as const;

export type FactGroupKey = (typeof FACT_GROUPS)[number]['key'];

export interface FactView {
  /** 사실 번호(응답 값 그대로, 조회자는 서버가 IPv4를 가림) */
  id: string;
  /** zeek_AD 사실 이름 원문 */
  rawName: string;
  /** 화면 항목 이름. 사전에 없으면 원문 */
  label: string;
  nameKnown: boolean;
  group: FactGroupKey;
  /** 화면 값. 값 모양을 모르면 응답의 글 값(value) 원문 */
  text: string;
  valueKnown: boolean;
  /** 값이 길어 줄을 따로 쓰는 항목 */
  wide: boolean;
  /** 리포트가 인용한 번호가 사실 목록에 없음("근거 정보 없음") */
  missing: boolean;
}

export type Pseudonyms = Record<string, string> | null | undefined;

const MISSING_NAME = '근거 정보 없음';

const PROTOCOL_LOG_NAMES: Record<string, string> = {
  dns: 'DNS',
  http: 'HTTP',
  tls: 'TLS',
  smb: 'SMB',
  kerberos: 'Kerberos',
  ntlm: 'NTLM',
  ssh: 'SSH',
  ftp: 'FTP',
  dce_rpc: 'DCE-RPC',
};

/** 단순 숫자 사실(이름 → 항목 이름, 값 단위) */
const SCALAR_FACTS: Record<string, { label: string; unit: ValueUnit; group: FactGroupKey }> = {
  connection_count: { label: '세션 수', unit: 'count', group: 'overview' },
  unique_peers: { label: '고유 상대 IP 수', unit: 'count', group: 'overview' },
  unique_destination_ports: { label: '고유 목적지 포트 수', unit: 'count', group: 'overview' },
  payload_bytes_inflated_connections: { label: '페이로드 바이트가 부푼 세션 수', unit: 'count', group: 'overview' },
  queue_rank: { label: '탐지 순위', unit: 'rank', group: 'overview' },
  bytes_sent_by_host: { label: '자산 송신 바이트', unit: 'bytes', group: 'overview' },
  bytes_received_by_host: { label: '자산 수신 바이트', unit: 'bytes', group: 'overview' },
  incident_duration_seconds: { label: '인시던트 지속 시간', unit: 'seconds', group: 'overview' },
};

/** `baseline.<지표>` 지표 이름. 단위는 이름 끝(`_ratio` 비율, `_chars` 글자 수, `payload_bytes_*` 바이트)으로 정한다. */
const BASELINE_METRICS: Record<string, string> = {
  connections_per_window: '구간당 세션 수',
  dce_rpc_calls_per_window: '구간당 DCE-RPC 호출 수',
  distinct_peer_ports_per_window: '구간당 고유 상대 포트 수',
  distinct_peers_per_window: '구간당 고유 상대 IP 수',
  dns_max_query_length_chars: 'DNS 최장 질의 길이',
  dns_nxdomain_per_window: '구간당 DNS 없는 도메인 응답',
  dns_queries_per_window: '구간당 DNS 질의 수',
  ftp_failures_per_window: '구간당 FTP 실패 응답',
  http_errors_per_window: '구간당 HTTP 오류 응답',
  http_requests_per_window: '구간당 HTTP 요청 수',
  icmp_connection_ratio: 'ICMP 세션 비율',
  kerberos_failures_per_window: '구간당 Kerberos 실패 수',
  payload_bytes_received_by_host_per_window: '구간당 자산 수신 페이로드 바이트',
  payload_bytes_sent_by_host_per_window: '구간당 자산 송신 페이로드 바이트',
  rejected_connection_ratio: '거부된 세션 비율',
  smb_file_actions_per_window: '구간당 SMB 파일 작업 수',
  smb_mappings_per_window: '구간당 SMB 공유 폴더 연결',
  tls_without_sni_per_window: '구간당 SNI 없는 TLS 세션',
  unestablished_connection_ratio: '성립하지 않은 세션 비율',
};

type ValueUnit = 'count' | 'sessions' | 'bytes' | 'seconds' | 'rank' | 'chars' | 'ratio' | 'plain';

type Json = unknown;

function isRecord(v: Json): v is Record<string, Json> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isFiniteNumber(v: Json): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** 정수는 천 단위 구분, 소수는 소수 둘째 자리까지(원문은 펼친 상세·툴팁). */
export function formatFactNumber(n: number): string {
  if (Number.isInteger(n)) return formatNumber(n);
  return new Intl.NumberFormat('ko-KR', { maximumFractionDigits: 2 }).format(n);
}

/** 바이트: 1024 미만은 B, 그 이상은 KB·MB·GB·TB(소수 한 자리, 100 이상은 정수). */
export function formatFactBytes(n: number): string {
  if (n < 0) return formatFactNumber(n);
  if (n < 1024) return `${new Intl.NumberFormat('ko-KR', { maximumFractionDigits: 1 }).format(n)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[i]}`;
}

/** 비율: 0~1이면 %(소수 한 자리), 그 밖의 값은 바꾸지 않고 그대로. */
export function formatFactRatio(n: number): string {
  if (n >= 0 && n <= 1) {
    const pct = Math.round(n * 1000) / 10;
    return `${Number.isInteger(pct) ? pct : pct.toFixed(1)}%`;
  }
  return String(n);
}

/** 단위대로 값을 보인다. null은 "-"(0으로 바꾸지 않는다). 숫자가 아니면 null(모르는 모양). */
function formatUnit(v: Json, unit: ValueUnit): string | null {
  if (v === null) return '-';
  if (!isFiniteNumber(v)) return null;
  switch (unit) {
    case 'bytes':
      return formatFactBytes(v);
    case 'seconds':
      return v < 0 ? formatFactNumber(v) + '초' : formatSeconds(v);
    case 'rank':
      return `${formatFactNumber(v)}위`;
    case 'chars':
      return `${formatFactNumber(v)}자`;
    case 'sessions':
      return `${formatFactNumber(v)}건`;
    case 'ratio':
      return formatFactRatio(v);
    default:
      return formatFactNumber(v);
  }
}

/** 글 잎 전체가 가명 키와 같을 때만 주소를 붙인다(`X1(203.0.*.*)`). 섞인 글(`X1:443`)에는 붙이지 않는다. */
export function withPseudonymAddress(text: string, pseudonyms: Pseudonyms): string {
  if (!pseudonyms || !hasOwn(pseudonyms, text)) return text;
  const addr = pseudonyms[text];
  return typeof addr === 'string' && addr.trim() !== '' ? `${text}(${addr})` : text;
}

function addressText(v: Json, pseudonyms: Pseudonyms): string | null {
  if (v === null) return '-';
  if (typeof v !== 'string') return null;
  return withPseudonymAddress(v, pseudonyms);
}

function codeText(v: Json): string | null {
  if (v === null) return '-';
  return typeof v === 'string' ? v : null;
}

function sessionCount(v: Json): string | null {
  const n = formatUnit(v, 'sessions');
  return n === null ? null : n === '-' ? '세션 -' : `세션 ${n}`;
}

/** 객체 값이 정확히 이 키들만 가지는지(모르는 키가 있으면 원문으로 보인다) */
function hasExactKeys(v: Json, keys: readonly string[]): v is Record<string, Json> {
  if (!isRecord(v)) return false;
  const own = Object.keys(v);
  return own.length === keys.length && keys.every((k) => hasOwn(v, k));
}

function joinParts(parts: Array<string | null>): string | null {
  return parts.some((p) => p === null) ? null : (parts as string[]).join(' · ');
}

interface NameRule {
  label: string;
  group: FactGroupKey;
  wide?: boolean;
  render: (v: Json, pseudonyms: Pseudonyms) => string | null;
}

function baselineMetricUnit(metric: string): ValueUnit {
  if (metric.endsWith('_ratio')) return 'ratio';
  if (metric.endsWith('_chars')) return 'chars';
  if (metric.startsWith('payload_bytes_')) return 'bytes';
  return 'plain';
}

const BASELINE_KEYS = ['incident_max', 'baseline_p50', 'baseline_p95', 'baseline_max'] as const;

/** 평소 p95보다 몇 배인지(둘 다 숫자이고 p95가 0보다 클 때만. 0으로 나누지 않는다) */
function timesOverP95(max: Json, p95: Json): string | null {
  if (!isFiniteNumber(max) || !isFiniteNumber(p95) || p95 <= 0) return null;
  const r = max / p95;
  return `평소 p95의 ${new Intl.NumberFormat('ko-KR', { maximumFractionDigits: 1 }).format(r)}배`;
}

function renderBaseline(metric: string) {
  const unit = baselineMetricUnit(metric);
  return (v: Json): string | null => {
    if (!hasExactKeys(v, BASELINE_KEYS)) return null;
    const vals = BASELINE_KEYS.map((k) => formatUnit(v[k], unit));
    if (vals.some((x) => x === null)) return null;
    const line = `이번 인시던트 최대 ${vals[0]} / 평소 중앙값 ${vals[1]} / 평소 p95 ${vals[2]} / 평소 최대 ${vals[3]}`;
    const times = unit === 'ratio' ? null : timesOverP95(v.incident_max, v.baseline_p95);
    return times ? `${line} (${times})` : line;
  };
}

function renderExampleConnection(v: Json, pseudonyms: Pseudonyms): string | null {
  const keys = [
    'source',
    'destination',
    'destination_port',
    'transport',
    'protocol',
    'conn_state',
    'duration_seconds',
    'source_bytes',
    'destination_bytes',
    'start_seconds',
  ] as const;
  if (!hasExactKeys(v, keys)) return null;
  const src = addressText(v.source, pseudonyms);
  const dst = addressText(v.destination, pseudonyms);
  const port = v.destination_port === null ? '-' : isFiniteNumber(v.destination_port) ? String(v.destination_port) : null;
  const transport = codeText(v.transport);
  const protocol = v.protocol === null ? '-' : typeof v.protocol === 'string' ? labelText('serviceProtocol', v.protocol) : null;
  const state = v.conn_state === null ? '-' : typeof v.conn_state === 'string' ? labelText('connState', v.conn_state) : null;
  const duration = v.duration_seconds === null ? '-' : isFiniteNumber(v.duration_seconds) ? formatSessionDuration(v.duration_seconds) : null;
  const sent = formatUnit(v.source_bytes, 'bytes');
  const recv = formatUnit(v.destination_bytes, 'bytes');
  // start_seconds는 뜻을 확인하지 않아 한 줄 요약에 넣지 않는다(원문은 펼친 상세에 있다). 모양만 본다.
  if (v.start_seconds !== null && !isFiniteNumber(v.start_seconds)) return null;
  if ([src, dst, port, transport, protocol, state, duration, sent, recv].some((x) => x === null)) return null;
  return `${src} → ${dst}:${port}/${transport} · ${protocol} · ${state} · 지속 ${duration} · 출발지가 보냄 ${sent} · 목적지가 보냄 ${recv}`;
}

function protocolMetricLabel(proto: string, metric: string): { label: string; unit: ValueUnit } | null {
  const protoName = PROTOCOL_LOG_NAMES[proto];
  if (!protoName) return null;
  if (metric === 'max_query_length_chars') {
    return { label: `${protoName} ${labelText('protocolMetric', 'max_query_length')}`, unit: 'chars' };
  }
  const m = lookupLabel('protocolMetric', metric);
  if (!m.known) return null;
  return { label: `${protoName} ${m.text}`, unit: 'plain' };
}

function ruleFor(name: string): NameRule | null {
  if (hasOwn(SCALAR_FACTS, name)) {
    const s = SCALAR_FACTS[name];
    return { label: s.label, group: s.group, render: (v) => formatUnit(v, s.unit) };
  }
  if (name === 'host_role') {
    return {
      label: '통신 방향',
      group: 'overview',
      render: (v) => {
        if (v === null) return '-';
        if (typeof v !== 'string') return null;
        const l = lookupLabel('hostRole', v);
        return l.known ? l.text : null;
      },
    };
  }
  if (name === 'picked_by_model') {
    return {
      label: '탐지 모델',
      group: 'detection',
      render: (v) => {
        if (v === null) return '-';
        if (typeof v !== 'string') return null;
        const l = lookupLabel('detectionModel', v);
        return l.known ? l.text : null;
      },
    };
  }
  if (name === 'also_flagged_by_models') {
    return {
      label: '함께 탐지한 모델',
      group: 'detection',
      render: (v) => {
        if (!Array.isArray(v)) return null;
        if (v.length === 0) return '없음';
        const labels = v.map((m) => (typeof m === 'string' ? lookupLabel('detectionModel', m) : null));
        if (labels.some((l) => l === null || !l.known)) return null;
        return labels.map((l) => l!.text).join(', ');
      },
    };
  }
  if (name === 'baseline_windows') {
    return {
      label: '비교한 구간 수',
      group: 'baseline',
      render: (v) => {
        if (!hasExactKeys(v, ['baseline_windows', 'incident_windows'])) return null;
        const b = formatUnit(v.baseline_windows, 'plain');
        const i = formatUnit(v.incident_windows, 'plain');
        if (b === null || i === null) return null;
        return `평소 ${b}구간 · 이번 인시던트 ${i}구간`;
      },
    };
  }
  let m = /^baseline\.([a-z0-9_]+)$/.exec(name);
  if (m && hasOwn(BASELINE_METRICS, m[1])) {
    return { label: `평소 대비 · ${BASELINE_METRICS[m[1]]}`, group: 'baseline', wide: true, render: renderBaseline(m[1]) };
  }
  m = /^model_candidate_windows\.([A-Za-z0-9_]+)$/.exec(name);
  if (m) {
    const model = lookupLabel('detectionModel', m[1]);
    if (!model.known) return null;
    return {
      label: `${model.text} 이상 판정 구간`,
      group: 'detection',
      render: (v) => {
        if (!hasExactKeys(v, ['candidate', 'windows'])) return null;
        const c = formatUnit(v.candidate, 'plain');
        const w = formatUnit(v.windows, 'plain');
        return c === null || w === null ? null : `${c} / ${w} 구간`;
      },
    };
  }
  m = /^conn_state\.([A-Za-z0-9]+)$/.exec(name);
  if (m) {
    const st = lookupLabel('connState', m[1]);
    if (!st.known) return null;
    return { label: `세션 상태 · ${st.text}`, group: 'distribution', render: (v) => formatUnit(v, 'sessions') };
  }
  m = /^protocol\.([A-Za-z0-9_.-]+)$/.exec(name);
  if (m) {
    const p = m[1];
    return {
      label: `서비스 프로토콜 · ${labelText('serviceProtocol', p)}`,
      group: 'distribution',
      render: (v) => formatUnit(v, 'sessions'),
    };
  }
  m = /^transport\.([A-Za-z0-9_-]+)$/.exec(name);
  if (m) {
    return { label: `전송 계층 · ${m[1]}`, group: 'distribution', render: (v) => formatUnit(v, 'sessions') };
  }
  m = /^dce_rpc\.top_operation_(\d+)$/.exec(name);
  if (m) {
    return {
      label: `DCE-RPC 주요 호출 ${m[1]}`,
      group: 'protocolLog',
      render: (v) => {
        if (!hasExactKeys(v, ['operation', 'connections'])) return null;
        return joinParts([codeText(v.operation), sessionCount(v.connections)]);
      },
    };
  }
  m = /^([a-z_]+)\.([a-z_]+)$/.exec(name);
  if (m) {
    const pm = protocolMetricLabel(m[1], m[2]);
    if (pm) {
      return { label: pm.label, group: 'protocolLog', render: (v) => formatUnit(v, pm.unit) };
    }
  }
  m = /^top_peer_(\d+)$/.exec(name);
  if (m) {
    return {
      label: `많이 통신한 상대 IP ${m[1]}`,
      group: 'peers',
      render: (v, ps) => {
        if (!hasExactKeys(v, ['peer', 'connections'])) return null;
        return joinParts([addressText(v.peer, ps), sessionCount(v.connections)]);
      },
    };
  }
  m = /^top_destination_port_(\d+)$/.exec(name);
  if (m) {
    return {
      label: `많이 쓴 목적지 포트 ${m[1]}`,
      group: 'peers',
      render: (v) => {
        if (!hasExactKeys(v, ['port', 'transport', 'connections'])) return null;
        const port = v.port === null ? '-' : isFiniteNumber(v.port) ? String(v.port) : null;
        const tr = codeText(v.transport);
        if (port === null || tr === null) return null;
        return joinParts([`${port}/${tr}`, sessionCount(v.connections)]);
      },
    };
  }
  m = /^example_connection_(\d+)$/.exec(name);
  if (m) {
    return { label: `주요 세션 ${m[1]}`, group: 'sessions', wide: true, render: renderExampleConnection };
  }
  return null;
}

/** 사실 이름이 사전(이름 규칙)으로 덮이는지. 시험이 공개 데이터 이름 목록으로 판정한다. */
export function isKnownFactName(name: string): boolean {
  return ruleFor(name) !== null;
}

/** 이름만 바꾼 항목 이름(사전에 없으면 원문) */
export function factLabel(name: string): string {
  return ruleFor(name)?.label ?? name;
}

/** 응답이 준 구조 값. 없으면(옛 응답, 조회자 키 겹침) undefined */
function structured(fact: FactItem): { present: boolean; value: Json } {
  if (fact.valueJson === undefined || fact.valueJson === null) {
    // 값 자체가 JSON null인 사실과 구조 값을 싣지 않은 경우를 글 값으로 가른다(서버는 null 값을 "-"로 준다).
    return fact.valueJson === null && fact.value === '-' ? { present: true, value: null } : { present: false, value: undefined };
  }
  return { present: true, value: fact.valueJson };
}

export function isMissingFact(fact: FactItem): boolean {
  return fact.name === MISSING_NAME && (fact.valueJson === null || fact.valueJson === undefined) && fact.value === '-';
}

/** 근거 사실 한 건을 화면 항목으로 바꾼다. */
export function describeFact(fact: FactItem, pseudonyms: Pseudonyms): FactView {
  const base = { id: fact.id, rawName: fact.name };
  if (isMissingFact(fact)) {
    return { ...base, label: MISSING_NAME, nameKnown: true, group: 'other', text: '-', valueKnown: true, wide: false, missing: true };
  }
  const rule = ruleFor(fact.name);
  const sv = structured(fact);
  let text: string | null = null;
  if (rule && sv.present) {
    text = rule.render(sv.value, pseudonyms);
  }
  if (!rule && sv.present && typeof sv.value === 'string') {
    // 사전에 없는 이름이라도 값 글 전체가 가명이면 문장과 같은 모양으로 주소를 붙인다.
    const annotated = withPseudonymAddress(sv.value, pseudonyms);
    if (annotated !== sv.value) {
      return {
        ...base,
        label: fact.name,
        nameKnown: false,
        group: 'other',
        text: annotated,
        valueKnown: false,
        wide: annotated.length > 40,
        missing: false,
      };
    }
  }
  const rawText = fact.value ?? '-';
  return {
    ...base,
    label: rule?.label ?? fact.name,
    nameKnown: rule !== null,
    group: rule?.group ?? 'other',
    text: text ?? rawText,
    valueKnown: text !== null,
    wide: Boolean(rule?.wide) || (text === null && rawText.length > 40),
    missing: false,
  };
}

/** 검증 문제 한 건의 화면 문장(T37). 모르는 kind·모양은 원문(known=false). */
export interface ProblemView {
  text: string;
  known: boolean;
  /** 위치(`where`) 원문. 없으면 null */
  where: string | null;
}

const PROBLEM_KINDS: Record<string, (value: string) => string> = {
  number_not_in_facts: (value) => `리포트 글의 숫자 "${value}"가 근거 사실에 없습니다`,
  pseudonym_not_in_facts: (value) => `리포트 글의 가명 "${value}"가 근거 사실에 없습니다`,
};

export function describeProblem(item: unknown, pseudonyms: Pseudonyms): ProblemView {
  if (typeof item === 'string') {
    return { text: item, known: false, where: null };
  }
  if (isRecord(item) && typeof item.kind === 'string' && hasOwn(PROBLEM_KINDS, item.kind)) {
    const raw = item.value;
    const okValue = typeof raw === 'string' || isFiniteNumber(raw);
    const okWhere = item.where === undefined || item.where === null || typeof item.where === 'string';
    const extraKeys = Object.keys(item).filter((k) => !['kind', 'value', 'where'].includes(k));
    if (okValue && okWhere && extraKeys.length === 0) {
      const valueText =
        item.kind === 'pseudonym_not_in_facts' && typeof raw === 'string' ? withPseudonymAddress(raw, pseudonyms) : String(raw);
      return {
        text: PROBLEM_KINDS[item.kind](valueText),
        known: true,
        where: typeof item.where === 'string' && item.where !== '' ? item.where : null,
      };
    }
  }
  return { text: JSON.stringify(item), known: false, where: null };
}
