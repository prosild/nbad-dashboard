/**
 * 표시 이름 사전: zeek_AD·API 코드 값 → 화면 표시 이름.
 * 화면은 코드 값을 이 사전으로만 보여 준다. 같은 내용을 docs/ui-terminology.md '표시 이름 사전' 절에 사람이 읽을 수 있게 남긴다.
 * 탐지 모델 이름은 zeek_AD 데이터 계약 v2 '모델 표시 이름'(2026-11-21 결정)을 따른다(`detectionModel`, `DETECTION_MODEL_INFO`).
 * 모델 버전 값(zeekad-fusion/N)은 바꾸지 않으므로 여기에 넣지 않는다.
 */

export const LABEL_DICTIONARIES = {
  /** 인시던트 상태 (zeek_AD incident status) */
  incidentStatus: {
    open: '신규',
    investigating: '분석 중',
    closed: '종결',
  },
  /** 자동 분류 우선순위 (대시보드 계산 값, utils/triage.ts) */
  priority: {
    high: 'High',
    medium: 'Medium',
    low: 'Low',
  },
  /**
   * 탐지 모델 표시 이름 (zeek_AD 데이터 계약 v2 '모델 표시 이름', 설계 토론 Q63). 버전을 넣지 않는다.
   * 모델 종류·툴팁 설명은 DETECTION_MODEL_INFO. 사전에 없는 새 식별자는 "미등록 값"으로 보인다.
   */
  detectionModel: {
    tail_rarity_v2: '기준선 이탈',
    transformer_v2: '행위 패턴 이탈',
    tgn_recon: '통신 관계 이상',
  },
  /** 판정 (zeek_AD resolution) */
  resolution: {
    true_positive: '정탐',
    false_positive: '오탐',
    benign: '정상',
  },
  /** 대응 조치 종류 (T56, 대시보드 자체 값) */
  responseAction: {
    block_ip: 'IP 차단',
    isolate_host: '호스트 격리',
    lock_account: '사용자 계정 잠금·비밀번호 초기화',
    handover: '침해사고 대응팀 이관',
    monitor: '모니터링 강화',
    none: '조치 없음',
    other: '기타',
  },
  /** 통신 방향 (zeek_AD zeekad_role) */
  hostRole: {
    originator: '출발지',
    responder: '목적지',
  },
  /** 리포트 작성 방식 (zeek_AD zeekad_report_kind). T43: 템플릿은 "템플릿 리포트"로 통일 */
  reportKind: {
    llm: 'AI 작성',
    template: '템플릿 리포트',
  },
  /** 경보 발송 판단 선택지 (zeek_AD send decision choice) */
  sendChoice: {
    send: '전송',
    hold: '보류',
    analyst_review: '에스컬레이션',
    need_more_evidence: '증적 보강 필요',
  },
  /** 경보 발송 최종 결정 주체 (zeek_AD decided_by) */
  decidedBy: {
    policy: '규칙',
    llm: 'AI 리포트',
    decision_model: '판단 모델',
  },
  /** 에스컬레이션 검토 결정 (zeek_AD zeekad_review_action) */
  reviewAction: {
    confirm: '승인',
    dismiss: '오탐 종결',
  },
  /** 리포트 검증 결과 (zeek_AD zeekad_verification_passed) */
  verification: {
    true: '검증 통과',
    false: '검증 실패',
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
    incident: '인시던트 알림',
    status: '상태 변경 알림',
    daily_summary: '일일 요약',
  },
  /**
   * 사건 알림의 판 (zeek_AD zeekad_message_version 앞머리, T38). 판 번호(`.v1`)는 보지 않는다.
   * `template` = 탐지 직후 틀 문장으로 보내는 알림, `llm-report` = AI 리포트가 생긴 뒤 보내는 알림.
   */
  slackMessageVersion: {
    template: '즉시 알림(틀 문장)',
    'llm-report': 'AI 리포트 알림',
  },
  /** Slack 전송 방식 (zeek_AD zeekad_delivery_mode) */
  slackDeliveryMode: {
    dry_run: 'Dry-run',
    live: '실제 전송',
  },
  /** Slack 전송 결과 (zeek_AD zeekad_delivery_status) */
  slackDeliveryStatus: {
    recorded: '기록됨',
    sent: '전송됨',
    delivered: '전송됨',
    failed: '전송 실패',
  },
  /** 탐지 작업 상태 (zeek_AD scoring_jobs.status) */
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
    /** 사람이 아닌 행위자(계정 시드, 보관 기한 삭제)의 감사 행에만 나온다. 계정 역할이 아니다 */
    SYSTEM: '시스템',
  },
  /** 감사 로그 동작 유형 (대시보드 AuditActionType) */
  auditAction: {
    LOGIN_SUCCESS: '로그인 성공',
    LOGIN_FAILURE: '로그인 실패',
    ACCOUNT_LOCKED: '계정 잠김',
    TOTP_VERIFIED: '2단계 인증 성공',
    TOTP_FAILURE: '2단계 인증 실패',
    ACCESS_DENIED_IDOR: '허용 범위 밖 접근 거부',
    INCIDENT_VIEW_UNMASKED: '마스킹 없이 인시던트 열람',
    INCIDENT_STATUS_TRANSITION: '인시던트 상태 변경',
    ANALYST_REVIEW_DECISION: '에스컬레이션 결정',
    INCIDENT_ASSIGNMENT: '담당 지정',
    INCIDENT_RESPONSE_ACTION: '대응 조치 기록',
    USER_ADMIN_CHANGE: '사용자 계정 변경',
    CRITICAL_ASSET_CHANGE: '중요 자산 변경',
    AUDIT_RETENTION_PURGE: '보관 기한 지난 기록 삭제',
  },
  /** 증적 표의 열 이름 (zeek_AD evidence.v1 하위 키) */
  evidenceField: {
    ip: 'IP',
    port: '포트',
    transport: '전송 계층',
    protocol: '서비스 프로토콜',
    connections: '세션 수',
    bytes: '바이트',
    zeek: 'Zeek 기록',
    event: '시각',
    source: '출발지 IP',
    destination: '목적지 IP',
    network: '네트워크',
    uid: '세션 ID',
    conn_state: '세션 상태',
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
    connections: '세션 수',
    without_sni: 'SNI 없는 세션',
    errors: '오류 응답',
    requests: '요청 수',
    auths: '인증 수',
    failures: '실패 수',
    calls: '호출 수',
    top_operations: '주요 호출',
  },
  /**
   * 서비스 프로토콜 분포의 특수 값 (zeek_AD evidence.v1 network.protocol).
   * http·dns 같은 프로토콜 이름은 업계 약어라 그대로 두고(사전에 없어도 미등록 표시를 하지 않는다), 특수 값만 바꾼다.
   */
  serviceProtocol: {
    unidentified: '식별 안 됨',
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
  /** MITRE ATT&CK 전술 (zeek_AD 리포트 attack_candidates.tactics, 슬러그·제목 표기 모두) */
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
  // 데이터 값이 'constructor' 같은 객체 기본 속성 이름이어도 사전 항목으로 오인하지 않게 자기 속성만 본다.
  const own = (key: string) => (Object.prototype.hasOwnProperty.call(entries, key) ? entries[key] : undefined);
  const hit = own(raw) ?? own(raw.toLowerCase()) ?? own(raw.toUpperCase());
  if (hit !== undefined) {
    return { text: hit, known: true, raw };
  }
  return { text: raw, known: false, raw };
}

/**
 * Slack 사건 알림의 판 표지(T38). `template.v1`·`llm-report.v2`처럼 판 번호가 달라도 앞머리(첫 `.` 앞)로 찾는다.
 * 모르는 판은 원문 그대로(미등록 값), 판이 없으면 null(표지를 두지 않는다).
 */
export function lookupSlackMessageVersion(version: string | null | undefined): LabelLookup | null {
  if (version === null || version === undefined || version.trim() === '') return null;
  const raw = version.trim();
  const prefix = raw.split('.')[0];
  const hit = lookupLabel('slackMessageVersion', prefix);
  return hit.known ? { ...hit, raw } : { text: raw, known: false, raw };
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
 * 에스컬레이션 사유(zeek_AD zeekad_review_reason). `llm=analyst_review, decision_model=analyst_review` 같은
 * `주체=선택지` 나열은 `AI 리포트: 에스컬레이션 · 판단 모델: 에스컬레이션`으로 바꾸고, 그 밖의 문장은 그대로 둔다.
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

/**
 * 탐지 모델 종류와 툴팁 설명(zeek_AD 데이터 계약 v2 '모델 표시 이름' 확정 문구). 키는 `detectionModel` 사전과 같다.
 */
export const DETECTION_MODEL_INFO: Record<string, { kind: string; description: string }> = {
  tail_rarity_v2: {
    kind: '통계 기준선',
    description:
      '5분 구간의 통신 특징 42개(연결 수, 목적지 포트 수, 연결 실패 비율, 프로토콜 로그 등) 중 정상 기간에 거의 없던 값이 있는 정도. 가장 드문 특징 하나가 점수다. 정찰·스캔, 인증 실패 반복에 강하다.',
  },
  transformer_v2: {
    kind: 'Transformer',
    description:
      '이 자산의 직전 1시간(5분 구간 12개)으로 다음 5분을 예측하고, 실제와 다른 정도. 다른 자산이 아니라 자기 평소 흐름과 비교한다. 이력이 없는 첫 구간에서는 높게 나올 수 있다.',
  },
  tgn_recon: {
    kind: 'TGN(시간 그래프 신경망)',
    description:
      '호스트 사이의 연결을 시간 그래프로 학습해, 예상하기 어려운 연결이 나온 정도(구간 안에서 가장 예상 밖인 연결 하나 기준). beacon처럼 양은 적어도 상대가 특이한 통신을 올린다. 이상 호스트와 통신한 정상 호스트도 함께 올라갈 수 있다.',
  },
};

export interface DetectionModelLookup extends LabelLookup {
  /** 모델 종류(미등록이면 null) */
  kind: string | null;
  /** zeek_AD 툴팁 설명(미등록이면 null) */
  description: string | null;
  /** 상세·툴팁용 "모델 종류 · 식별자"(미등록이면 식별자만) */
  kindAndId: string;
  /** 툴팁 글: "모델 종류 · 식별자" + 설명. 미등록이면 미등록 값 툴팁 */
  tooltip: string;
}

/** 탐지 모델 식별자 → 표시 이름·종류·설명. 사전에 없는 식별자는 known=false("미등록 값"). */
export function detectionModelInfo(id: string | null | undefined): DetectionModelLookup {
  const base = lookupLabel('detectionModel', id);
  const key = base.raw.toLowerCase();
  const info = base.known && base.raw && Object.prototype.hasOwnProperty.call(DETECTION_MODEL_INFO, key)
    ? DETECTION_MODEL_INFO[key]
    : null;
  if (!info) {
    return {
      ...base,
      kind: null,
      description: null,
      kindAndId: base.raw,
      tooltip: base.raw ? unregisteredTitle(base.raw) : '',
    };
  }
  const kindAndId = `${info.kind} · ${base.raw}`;
  return {
    ...base,
    kind: info.kind,
    description: info.description,
    kindAndId,
    tooltip: `${kindAndId}\n${info.description}`,
  };
}

/**
 * AI 리포트 검증 표지의 뜻(T37). 큐 "리포트·판단" 칸의 가운데 칩과 상세 검증 표지의 툴팁·접근성 이름에 쓴다.
 * 공개 데이터의 실패 사례에서 드러난 검사(리포트 글의 숫자·가명이 근거 사실에 있는가)까지만 말한다.
 * 검증이 리포트의 해석까지 보증한다고 읽히는 말은 쓰지 않는다(SPEC 2026-11-23 T37 결정).
 */
export const VERIFICATION_DESCRIPTION = {
  passed: 'AI 리포트 검증 통과: 탐지 파이프라인이 리포트 글을 근거 사실과 대조했습니다(글 속 숫자·가명 등). 해석이 맞다는 뜻은 아닙니다',
  // T43: 목록 응답에는 사유가 없으므로 검증 실패·호출 실패 가운데 어느 것인지 단정하지 않는다
  failedQueue: 'AI 리포트를 쓰지 못함: 검증 실패 또는 호출 실패로 템플릿 리포트로 대체됐습니다. 사유는 상세에서 봅니다',
  failedDetail: 'AI 리포트 검증 실패: 리포트 글에 근거 사실과 맞지 않는 내용이 있습니다. 검증 실패 사유를 확인합니다',
} as const;

/**
 * T43 리포트 종류의 뜻(zeek_AD 계약 v2: `llm` = LLM 리포트가 검증 통과, `template` = 검증 실패·호출 실패로 규칙 템플릿으로 바꿈).
 * 템플릿 리포트의 내용을 의심하라는 말로 읽히지 않게, 화면에 보이는 리포트가 무엇인지를 먼저 말한다.
 */
export const REPORT_KIND_DESCRIPTION = {
  llm: 'AI 작성 리포트',
  template: '템플릿 리포트: AI 리포트를 쓰지 못해 사실만 나열한 템플릿 리포트로 대체됐습니다',
} as const;

/** 미등록 값 툴팁 문구 */
export function unregisteredTitle(raw: string): string {
  return `미등록 값: ${raw} (표시 이름 사전에 없음)`;
}

/**
 * 수집 구간(캡처) 표시 이름(zeek_AD 데이터 계약 v2 "수집 구간(캡처) 표시 이름" 절, Q65, zeek_AD 커밋 0117401).
 * 캡처 ID는 DB 값 그대로 두고 화면에만 이 이름을 쓴다. 원래 ID와 zeek_AD 설명은 툴팁에 둔다.
 * 열람 허용 패턴(`cic17-*` 등)은 이 사전을 쓰지 않고 ID 그대로 보인다.
 */
const CAPTURE_WEEKDAY: Record<string, string> = { mon: '월', tue: '화', wed: '수', thu: '목', fri: '금' };

const CAPTURE_FORMAT_TOOLTIP = {
  cic17: '공개 데이터셋 CIC-IDS2017의 원본 트래픽(평가용). 월요일 정상만 학습에 썼다.',
  syn1: (day: string) =>
    `CIC ${day}요일 Zeek 로그 사본에 합성 패턴 5종(beacon, 느린 유출, DNS 터널, 측면 이동, 느린 정찰)을 하나씩 코드로 끼워 넣었다. 네트워크로 보낸 트래픽이 아니다(탐지 저장소 설계 결정 DD-008).`,
  lab: '배포 VM이 격리 실습망에서 실제로 수집한 트래픽(날짜는 UTC). 하루가 처리 단위다.',
};

/**
 * 실습망 캡처별 덧붙일 표시와 내용(zeek_AD 표, 배포 VM DB 기준 2026-11-23, 이름은 2026-11-26 판). 키는 캡처 ID다.
 * 덧붙임(note)은 계약 표와 글자 그대로다. 내용(description)은 계약의 '내용' 칸을 T62 규칙으로 옮긴 글이다:
 * 호스트 주소는 옮기지 않고(화면 번들은 조회자 마스킹을 거치지 않는다) 그 자리는 "주소는 탐지 저장소 데이터 계약 v2 …"로 가리킨다.
 * 마크다운 링크는 글자만, 백틱·굵은 글씨는 빼고, 문장 끝에 마침표를 붙이고, 탐지 저장소 문서를 가리키는 출처 앞머리는 "탐지 저장소"다.
 * 캡처 표시 이름 사전에 한해 실습망 캡처 ID를 앱 코드에 둔다(2026-11-21 결정, StaticSecurityAndConfigTest 허용 파일).
 * 표에 없는 새 lab-*는 덧붙임 없이 보인다.
 */
export const LAB_CAPTURE_NOTES: Record<string, { note: string; description: string }> = {
  'lab-20261119': {
    note: 'Kali 공격 + 정상 배경',
    description:
      'Kali 공격만(실행 1), 정상 배경 35분(월요일 재생 + 합성 정상 클라이언트) 사이에 공격(실행 2). 시험 호스트 구분은 탐지 저장소 2026-11-19 전달 글 5절.',
  },
  'lab-20261122': {
    note: 'Kali 공격 6종 + 타깃 VM',
    description:
      '세그먼트 센서 확장(DD-020) 뒤의 공격 시험: 느린 스캔, 비커닝, 분할 유출, SMB 공유 탐색, SSH 무차별 대입, DNS 터널(빠른 스캔은 lab-20261119에 있다. 정답은 탐지 저장소 configs/ground-truth/lab-attacks.v1.json, 단계 7 진행 기록 열두째 작업). 호스트는 Kali(공격자)와 그 별칭(정상 배경용 서버), 타깃 VM과 그 IP 별칭(공유 탐색용)이다(주소는 탐지 저장소 데이터 계약 v2 "실습망 캡처별 표시"). 스레드 묶음이 처음 기록된 캡처다.',
  },
  'lab-20261123': {
    note: '시험(위 캡처의 뒤 시간)',
    description:
      'lab-20261122 시험 뒤 UTC 날짜가 넘어간 구간. 5분에 패킷 몇 개의 유휴 트래픽이고 공격 실행 기록은 없다. 알림은 모두 lab-20261122 묶음의 답글이다.',
  },
  'lab-20261118': {
    note: '시험',
    description: '배포 VM 첫 실행. Kali nmap 첫 시험, ping·파일 회전 시험.',
  },
  'lab-20261201': {
    note: '시험(가짜 패킷)',
    description:
      'VM을 만들기 전 이 PC에서 시험용 생성기로 만든 패킷(날짜도 가짜). DB를 옮길 때 함께 넘어갔다. 시연 화면에서는 숨긴다(DB에서 지우지 않는다).',
  },
};

export interface CaptureLookup extends LabelLookup {
  /** 툴팁 글: zeek_AD 설명(형식별·실습망별) + 원래 캡처 ID. 미등록이면 미등록 값 툴팁 */
  tooltip: string;
}

/** 캡처 ID → 표시 이름. 규칙에 맞지 않는 ID는 known=false(원래 ID 그대로, "미등록 값"). */
export function captureInfo(id: string | null | undefined): CaptureLookup {
  if (id === null || id === undefined || id.trim() === '') {
    return { text: '-', known: true, raw: '', tooltip: '' };
  }
  const raw = id.trim();
  const idLine = `캡처 ID: ${raw}`;
  const weekday = /^(cic17|syn1)-(mon|tue|wed|thu|fri)$/.exec(raw);
  if (weekday) {
    const day = CAPTURE_WEEKDAY[weekday[2]];
    if (weekday[1] === 'cic17') {
      return { text: `CIC-IDS2017 ${day}요일`, known: true, raw, tooltip: `${CAPTURE_FORMAT_TOOLTIP.cic17}\n${idLine}` };
    }
    return { text: `CIC ${day}요일 + 합성 패턴`, known: true, raw, tooltip: `${CAPTURE_FORMAT_TOOLTIP.syn1(day)}\n${idLine}` };
  }
  const lab = /^lab-(\d{4})(\d{2})(\d{2})$/.exec(raw);
  if (lab) {
    const base = `실습망 ${lab[1]}-${lab[2]}-${lab[3]}`;
    const extra = Object.prototype.hasOwnProperty.call(LAB_CAPTURE_NOTES, raw) ? LAB_CAPTURE_NOTES[raw] : null;
    if (extra) {
      return {
        text: `${base} · ${extra.note}`,
        known: true,
        raw,
        tooltip: `${CAPTURE_FORMAT_TOOLTIP.lab}\n${extra.description}\n${idLine}`,
      };
    }
    return { text: base, known: true, raw, tooltip: `${CAPTURE_FORMAT_TOOLTIP.lab}\n${idLine}` };
  }
  return { text: raw, known: false, raw, tooltip: unregisteredTitle(raw) };
}

/** 글만 필요한 곳(<option> 등)의 캡처 표시 이름 */
export function captureText(id: string | null | undefined): string {
  return captureInfo(id).text;
}

/**
 * 짧은 수집원 이름(T24). 좁은 칸(인시던트 큐 수집원 칸, 현황판, 운영 현황 수집원 상태)에 쓴다.
 * 전체 이름·캡처 ID는 툴팁·화면 판독기 글자에 둔다. 규칙: `cic17-<요일>` → "CIC 수", `syn1-<요일>` → "CIC+합성 수"(T62),
 * `lab-YYYYMMDD` → "실습 MM-DD", 규칙 밖 → 캡처 ID 그대로. 실습망 날짜는 UTC다(전체 이름 툴팁의 설명 유지).
 */
export function captureShortName(id: string | null | undefined): string {
  if (id === null || id === undefined || id.trim() === '') {
    return '-';
  }
  const raw = id.trim();
  const weekday = /^(cic17|syn1)-(mon|tue|wed|thu|fri)$/.exec(raw);
  if (weekday) {
    const day = CAPTURE_WEEKDAY[weekday[2]];
    return weekday[1] === 'cic17' ? `CIC ${day}` : `CIC+합성 ${day}`;
  }
  const lab = /^lab-(\d{4})(\d{2})(\d{2})$/.exec(raw);
  if (lab) {
    return `실습 ${lab[2]}-${lab[3]}`;
  }
  return raw;
}

/** 실습망 짧은 이름에 연도를 붙인 형태("실습 2026-11-19"). 다른 규칙은 그대로다. */
function captureShortNameWithYear(raw: string): string {
  const lab = /^lab-(\d{4})(\d{2})(\d{2})$/.exec(raw.trim());
  return lab ? `실습 ${lab[1]}-${lab[2]}-${lab[3]}` : captureShortName(raw);
}

/**
 * 사용자의 허용 캡처 목록(큐·overview 응답의 수집원 목록) 안에서 짧은 이름을 정한다.
 * 짧은 이름이 겹치는 캡처에는 연도를 붙인다(실습망 같은 월·일이 다른 해에 있을 때).
 */
export function captureShortNames(ids: readonly string[]): Map<string, string> {
  const byShort = new Map<string, string[]>();
  for (const id of ids) {
    const s = captureShortName(id);
    byShort.set(s, [...(byShort.get(s) ?? []), id]);
  }
  const out = new Map<string, string>();
  for (const [short, members] of byShort) {
    const distinct = new Set(members);
    for (const id of members) {
      out.set(id, distinct.size > 1 ? captureShortNameWithYear(id) : short);
    }
  }
  return out;
}

/** 짧은 이름 표(없으면 규칙 그대로) */
export function shortNameOf(names: Map<string, string> | null | undefined, id: string | null | undefined): string {
  if (!id) return '-';
  return names?.get(id) ?? captureShortName(id);
}
