/**
 * 표시 이름 사전: zeek_AD·API 코드 값 → 화면 표시 이름.
 * 화면은 코드 값을 이 사전으로만 보여 준다. 같은 내용을 docs/ui-terminology.md '표시 이름 사전' 절에 사람이 읽을 수 있게 남긴다.
 * 탐지 모델 이름(tail_rarity_v2 등)과 모델 구성(zeekad-fusion/N)은 사용자 결정으로 바꾸지 않으므로 여기에 넣지 않는다.
 */

export const LABEL_DICTIONARIES = {
  /** 사건 상태 (zeek_AD incident status) */
  incidentStatus: {
    open: '신규',
    investigating: '조사 중',
    closed: '종료',
  },
  /** 판정 (zeek_AD resolution) */
  resolution: {
    true_positive: '정탐',
    false_positive: '오탐',
    benign: '정상 행위',
  },
  /** 통신 방향 (zeek_AD zeekad_role) */
  hostRole: {
    originator: '연결 시작 측',
    responder: '연결 수신 측',
  },
  /** 보고서 작성 방식 (zeek_AD zeekad_report_kind) */
  reportKind: {
    llm: 'AI 작성',
    template: '템플릿 작성',
  },
  /** 알림 전송 판단 선택지 (zeek_AD send decision choice) */
  sendChoice: {
    send: '전송',
    hold: '보류',
    analyst_review: '분석가 판단 요청',
    need_more_evidence: '근거 보강 필요',
  },
  /** 알림 전송 최종 결정 주체 (zeek_AD decided_by) */
  decidedBy: {
    policy: '규칙',
    llm: 'AI 보고서',
    decision_model: '판단 모델',
  },
  /** 분석가 판단 결정 (zeek_AD zeekad_review_action) */
  reviewAction: {
    confirm: '조사 진행',
    dismiss: '오탐으로 종료',
  },
  /** 사실 검증 결과 (zeek_AD zeekad_verification_passed) */
  verification: {
    true: '사실 검증 통과',
    false: '사실 검증 실패',
  },
  /** 자산 관측 이름 종류 (zeek_AD zeekad_name_kind) */
  assetNameKind: {
    kerberos_machine: '컴퓨터 계정',
    kerberos_user: '사용자 계정',
    ntlm_user: 'NTLM 사용자 계정',
  },
  /** 자산 관측 항목 이름 (zeek_AD zeekad_asset_observations 키) */
  assetAttribute: {
    zeekad_name: '이름',
    zeekad_name_kind: '이름 종류',
    zeekad_source_log: '출처 로그',
    observations: '관측 횟수',
    observation_count: '관측 횟수',
    first_seen: '처음 관측',
    last_seen: '마지막 관측',
  },
  /** Slack 메시지 종류 (zeek_AD slack message kind) */
  slackMessageKind: {
    incident: '사건 알림',
    status: '상태 변경 알림',
    daily_summary: '일일 요약',
  },
  /** Slack 전송 방식 (zeek_AD zeekad_delivery_mode) */
  slackDeliveryMode: {
    dry_run: '시험 모드(실제 전송 안 함)',
    live: '실제 전송',
  },
  /** Slack 전송 결과 (zeek_AD zeekad_delivery_status) */
  slackDeliveryStatus: {
    recorded: '기록됨',
    sent: '전송됨',
    delivered: '전송됨',
    failed: '전송 실패',
  },
  /** 분석 실행 상태 (zeek_AD scoring_jobs.status) */
  jobStatus: {
    succeeded: '완료',
    failed: '실패',
    running: '진행 중',
    queued: '대기',
    pending: '대기',
  },
  /** 대시보드 사용자 역할 */
  userRole: {
    VIEWER: '조회자',
    ANALYST: '분석가',
    ADMIN: '관리자',
  },
  /** 감사 로그 동작 유형 (대시보드 AuditActionType) */
  auditAction: {
    LOGIN_SUCCESS: '로그인 성공',
    LOGIN_FAILURE: '로그인 실패',
    ACCOUNT_LOCKED: '계정 잠김',
    TOTP_VERIFIED: '2단계 인증 성공',
    ACCESS_DENIED_IDOR: '허용 범위 밖 접근 거부',
    INCIDENT_VIEW_UNMASKED: '가림 없이 사건 열람',
    INCIDENT_STATUS_TRANSITION: '사건 상태 변경',
    ANALYST_REVIEW_DECISION: '분석가 판단 결정',
    USER_ADMIN_CHANGE: '사용자 계정 변경',
  },
  /** 근거 표의 열 이름 (zeek_AD evidence.v1 하위 키) */
  evidenceField: {
    ip: 'IP',
    port: '포트',
    transport: '전송 계층',
    protocol: '서비스 프로토콜',
    connections: '연결 수',
    bytes: '바이트',
    zeek: 'Zeek 기록',
    event: '시각',
    source: '출발지',
    destination: '목적지',
    network: '네트워크',
    uid: '연결 ID',
    conn_state: '연결 상태',
    start: '시작',
    duration: '지속 시간',
  },
  /** 프로토콜 로그 하위 수치 이름 (zeek_AD evidence.v1 protocol_logs.*) */
  protocolMetric: {
    queries: '질의 수',
    nxdomain: '없는 도메인 응답',
    max_query_length: '최장 질의 길이',
    failed_replies: '실패 응답',
    files: '파일 수',
    mappings: '공유 폴더 연결',
    auth_failures: '인증 실패',
    connections: '연결 수',
    without_sni: 'SNI 없는 연결',
    errors: '오류 응답',
    requests: '요청 수',
    auths: '인증 수',
    failures: '실패 수',
    calls: '호출 수',
    top_operations: '주요 호출',
  },
  /** Zeek 연결 상태 코드 (zeek_AD evidence.v1 zeek_conn_state) */
  connState: {
    S0: '연결 시도, 응답 없음',
    S1: '연결됨, 종료 전',
    S2: '연결됨, 시작 측만 종료',
    S3: '연결됨, 수신 측만 종료',
    SF: '정상 연결·종료',
    REJ: '연결 거부',
    RSTO: '시작 측이 강제 종료',
    RSTR: '수신 측이 강제 종료',
    RSTOS0: '시작 측이 응답 전 강제 종료',
    RSTRH: '수신 측이 강제 종료(시작 미확인)',
    SH: '시작 측 종료, 응답 없음',
    SHR: '수신 측 종료, 시작 미확인',
    OTH: '시작 미확인 연결',
  },
  /** MITRE ATT&CK 전술 (zeek_AD 보고서 attack_candidates.tactics, 슬러그·제목 표기 모두) */
  attackTactic: {
    reconnaissance: '정찰',
    'resource-development': '자원 개발',
    'resource development': '자원 개발',
    'initial-access': '최초 접근',
    'initial access': '최초 접근',
    execution: '실행',
    persistence: '지속성 확보',
    'privilege-escalation': '권한 상승',
    'privilege escalation': '권한 상승',
    'defense-evasion': '방어 회피',
    'defense evasion': '방어 회피',
    'credential-access': '자격 증명 접근',
    'credential access': '자격 증명 접근',
    discovery: '탐색',
    'lateral-movement': '내부 확산',
    'lateral movement': '내부 확산',
    collection: '수집',
    'command-and-control': '명령 및 제어',
    'command and control': '명령 및 제어',
    exfiltration: '유출',
    impact: '영향',
  },
} as const;

export type LabelDictionaryName = keyof typeof LABEL_DICTIONARIES;

export interface LabelLookup {
  /** 화면에 보일 글. 사전에 있으면 표시 이름, 없으면 원래 값 */
  text: string;
  /** 사전에 등록된 값이면 true */
  known: boolean;
  /** 원래 코드 값(툴팁용) */
  raw: string;
}

/** 대소문자 구분 없이 찾는다(사용자 역할·연결 상태 코드는 대문자, 나머지는 소문자로 온다). */
export function lookupLabel(dict: LabelDictionaryName, value: string | boolean | null | undefined): LabelLookup {
  if (value === null || value === undefined || value === '') {
    return { text: '-', known: true, raw: '' };
  }
  const raw = String(value).trim();
  const entries = LABEL_DICTIONARIES[dict] as Record<string, string>;
  const hit =
    entries[raw] ?? entries[raw.toLowerCase()] ?? entries[raw.toUpperCase()];
  if (hit !== undefined) {
    return { text: hit, known: true, raw };
  }
  return { text: raw, known: false, raw };
}

/** 글만 필요한 곳(<option>, aria-label 등). 사전에 없는 값은 원래 값 그대로. */
export function labelText(dict: LabelDictionaryName, value: string | boolean | null | undefined): string {
  return lookupLabel(dict, value).text;
}

/**
 * 알림 규칙 사유(zeek_AD policy_reasons) 문장. 알려진 조건식은 한국어 문장으로 바꾸고, 모르는 형식은 known=false로 원문을 돌려준다.
 * 예: `queue_rank 1 <= 5` → `탐지 순위 5위 이내(현재 1위)`
 */
export function policyReasonText(reason: string): LabelLookup {
  const raw = reason.trim();
  const rank = /^queue_rank\s+(\d+)\s*<=\s*(\d+)$/.exec(raw);
  if (rank) {
    return { text: `탐지 순위 ${rank[2]}위 이내(현재 ${rank[1]}위)`, known: true, raw };
  }
  const models = /^flagging_models\s+(\d+)\s*>=\s*(\d+)$/.exec(raw);
  if (models) {
    return { text: `${models[2]}개 이상 모델이 탐지(현재 ${models[1]}개)`, known: true, raw };
  }
  // 한국어 문장(코드 식별자가 없는 글)은 그대로 보여 준다.
  if (!/[A-Za-z_]+_[A-Za-z_]+|[<>]=?/.test(raw)) {
    return { text: raw, known: true, raw };
  }
  return { text: raw, known: false, raw };
}

/**
 * 분석가 판단 요청 사유(zeek_AD zeekad_review_reason). `llm=analyst_review, decision_model=analyst_review` 같은
 * `주체=선택지` 나열은 `AI 보고서: 분석가 판단 요청 · 판단 모델: 분석가 판단 요청`으로 바꾸고, 그 밖의 문장은 그대로 둔다.
 */
export function reviewReasonText(reason: string | null | undefined): LabelLookup {
  if (!reason) {
    return { text: '-', known: true, raw: '' };
  }
  const raw = reason.trim();
  const pairs = raw.split(/\s*,\s*/);
  if (pairs.every((p) => /^[a-z_]+=[a-z_]+$/.test(p))) {
    const parts = pairs.map((p) => {
      const [who, choice] = p.split('=');
      return { who: lookupLabel('decidedBy', who), choice: lookupLabel('sendChoice', choice) };
    });
    const known = parts.every((p) => p.who.known && p.choice.known);
    return {
      text: parts.map((p) => `${p.who.text}: ${p.choice.text}`).join(' · '),
      known,
      raw,
    };
  }
  return { text: raw, known: true, raw };
}

/** 미등록 값 툴팁 문구 */
export function unregisteredTitle(raw: string): string {
  return `미등록 값: ${raw} (표시 이름 사전에 없음)`;
}
