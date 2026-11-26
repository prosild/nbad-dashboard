export type UserRole = 'VIEWER' | 'ANALYST' | 'ADMIN';

export interface AuthCsrfResponse {
  headerName: string;
  parameterName: string;
  token: string;
}

export interface AuthUserDto {
  username: string;
  displayName: string;
  role: UserRole;
  maskedView: boolean;
  totpEnabled: boolean;
  totpVerified: boolean;
  totpRequired: boolean;
  allowedCapturePatterns: string[];
}

/** T50: 안내 문구 아래에 붙는 링크 하나(서버가 검사한 https 주소와 일반 텍스트 라벨) */
export interface LoginNoticeLink {
  url: string;
  label: string;
}

/** T21: 로그인 화면 안내 문구(설정이 없으면 빈 문자열). T50: 링크가 없으면 link 필드 자체가 없다 */
export interface LoginNoticeResponse {
  notice: string;
  link?: LoginNoticeLink;
}

export interface AuthMeResponse {
  authenticated: boolean;
  user: AuthUserDto | null;
}

export interface AuthLoginResponse {
  authenticated: boolean;
  user: AuthUserDto;
  nextRoute: string;
}

export interface TotpSetupResponse {
  secret: string;
  otpauthUri: string;
  issuer: string;
  accountName: string;
}

export interface TotpVerifyResponse {
  succeeded: boolean;
  code: string;
  message: string;
  user: AuthUserDto;
}

export interface ActionResultResponse {
  succeeded: boolean;
  code: string;
  message: string;
}

export interface ApiErrorResponse {
  status: number;
  code: string;
  message: string;
}

export interface ScoringJob {
  jobId: number;
  captureId: string;
  bundleId: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  incidentCount: number | null;
}

export interface IncidentQueueItem {
  jobId: number;
  captureId: string;
  bundleId: string;
  queueRank: number;
  incidentId: string;
  hostIp: string;
  zeekadRole: string;
  eventStart: string | null;
  eventEnd: string | null;
  zeekadPickedBy: string | null;
  zeekadAlsoFlaggedBy: string[];
  connectionCount: number | null;
  hostName: string[];
  zeekadStatus: string | null;
  zeekadResolution: string | null;
  statusUpdatedAt: string | null;
  zeekadReportJobId: number | null;
  hasReport: boolean;
  zeekadReportKind: string | null;
  zeekadVerificationPassed: boolean | null;
  zeekadWouldSend: boolean;
  zeekadReviewAction: string | null;
  zeekadReviewPending: boolean;
  /** T21 경보 발송: 사건 알림 Slack 기록이 있는 인시던트(feedback_summary.alerted와 같은 식). 발송 판단(zeekadWouldSend)과 다르다. */
  alerted: boolean;
  multiModelFlagged?: boolean;
}

export interface IncidentQueueResponse {
  maskedView: boolean;
  allowedCaptures: string[];
  selectedCaptureId: string | null;
  selectedJob: ScoringJob | null;
  captureJobs: ScoringJob[];
  incidents: IncidentQueueItem[];
  availableModels: string[];
  availableRoles: string[];
}

/* ───────────── T23 통합 인시던트 큐 ───────────── */

export type QueuePriority = 'high' | 'medium' | 'low';
export type SourceType = 'live' | 'imported';

/** T25 담당자 한 사람. enabled=false면 "비활성" 표지 */
export interface AssigneeRef {
  username: string;
  displayName: string;
  enabled: boolean;
}

/** 통합 큐 한 행: 큐 행 필드 + 서버가 계산한 탐지 시각·수집원 종류·우선순위·진행 중 */
export interface UnifiedQueueItem extends IncidentQueueItem {
  detectedAt: string | null;
  sourceType: SourceType;
  /** 종결이면 null */
  priority: QueuePriority | null;
  ongoing: boolean;
  /** T25 담당자(없으면 null = 미배정) */
  assignee?: AssigneeRef | null;
  /** T25 착수 목표 시각(실습망·신규·우선순위 있음이 아니면 null) */
  ackDueAt?: string | null;
  /** T25 착수 지연 */
  ackOverdue?: boolean;
  /** T27 인시던트 번호(매기지 못했으면 null) */
  incidentNo?: number | null;
  /** T45 알림 묶음 표지: 가장 큰 묶음의 최초 알림 인시던트 번호(구성원 2건 이상인 묶음이 없으면 null) */
  threadHeadNo?: number | null;
  /** T45 그 묶음의 구성원 수(허용 캡처 전체 기준, `period=all&thread=` 목록의 건수와 같다) */
  threadMemberCount?: number | null;
}

export interface UnifiedQueueSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  reviewPending: number;
  alerted: number;
  byStatus: Record<string, number>;
  /** T25 착수 지연 수(띠 축을 뺀 집합) */
  overdue?: number;
}

export interface QueueSource {
  captureId: string;
  sourceType: SourceType;
  latestJobId: number | null;
  /** T29 그 수집원 최신 큐 인시던트의 가장 늦은 탐지 시각(없으면 null) */
  lastDetectedAt?: string | null;
}

export interface UnifiedQueueResponse {
  items: UnifiedQueueItem[];
  total: number;
  page: number;
  size: number;
  pageCount: number;
  summary: UnifiedQueueSummary;
  anchor: string;
  anchorMode: string;
  snapshot: boolean;
  period: string;
  /** T34 실제 기간 경계(UTC, (시작, 끝]). 전체면 null */
  periodStart?: string | null;
  periodEnd?: string | null;
  latestDetectedAt: string | null;
  /** 기간 시작 이하에 탐지된 행(같은 조건)의 가장 늦은 탐지 시각(T29부터 결과가 있어도 준다) */
  newestOutsidePeriod: string | null;
  /** T29 기간만 전체로 넓히면 더 보이는 수(같은 조건). 기간 전체면 0, 알 수 없으면 null */
  outsidePeriod?: number | null;
  sources: QueueSource[];
  maskedView: boolean;
  availableModels: string[];
  availableRoles: string[];
}

export interface QueueNewCountResponse {
  count: number;
  latestDetectedAt: string | null;
  since: string;
}

export interface QueueNeighborKey {
  jobId: number;
  queueRank: number;
  hostIp: string | null;
  /** T27 인시던트 번호(없으면 null) */
  incidentNo?: number | null;
}

/** T27 GET /api/incidents/no/{번호}: 지금 위치. latest=false면 최신 큐에 없고 마지막 성공 작업 위치다 */
export interface IncidentNoLocation {
  incidentNo: number;
  jobId: number;
  queueRank: number;
  latest: boolean;
}

export interface QueueNeighborsResponse {
  current: QueueNeighborKey | null;
  position: number | null;
  total: number;
  prev: QueueNeighborKey | null;
  next: QueueNeighborKey | null;
}

export interface TimeContextResponse {
  anchor: string;
  anchorMode: string;
  snapshot: boolean;
}

/** 상세 헤더 메타데이터(T23) */
export interface IncidentQueueMeta {
  sourceType: SourceType;
  detectedAt: string | null;
  priority: QueuePriority | null;
  ongoing: boolean;
  latestJobId: number | null;
  latestQueueRank: number | null;
  /** T25: 경과를 셀 기준 시각, 착수 목표 시각, 착수 지연 */
  anchor?: string | null;
  ackDueAt?: string | null;
  ackOverdue?: boolean;
}

/** T25 현재 담당. assignee가 null이면 미배정 */
export interface IncidentAssignment {
  assignee: AssigneeRef | null;
  assignedAt: string | null;
  assignedByDisplay: string | null;
}

/** T25 담당 변경 이력 한 행(from·to가 null이면 미배정). reason: manual · auto_on_start */
export interface AssignmentHistoryItem {
  jobId: number | null;
  from: AssigneeRef | null;
  to: AssigneeRef | null;
  actorDisplay: string | null;
  reason: string;
  changedAt: string | null;
}

/** T56 대응 조치 기록 한 행. recordedAt은 조치한 시각이 아니라 기록한 시각이다. note는 조회자에게 오지 않는다(null) */
export interface ResponseActionItem {
  /** block_ip · isolate_host · lock_account · handover · monitor · none · other */
  action: string;
  note: string | null;
  actorDisplay: string | null;
  recordedAt: string | null;
}

export interface AssigneeCandidate {
  username: string;
  displayName: string;
}

export interface IncidentModelScore {
  jobId: number;
  incidentId: string;
  zeekadModel: string;
  candidateWindows: number | null;
  windows: number | null;
  windowRatioLabel?: string;
}

export interface AssetNameRecord {
  captureId: string | null;
  hostIp: string | null;
  kerberosUser: string | null;
  ntlmUser: string | null;
  extraAttributes: Record<string, unknown>;
}

/** 프로토콜 로그 하위 수치. metrics가 null이면 근거에 그 프로토콜 키가 없었다(0과 구분). */
export interface ProtocolLogEntry {
  protocol: string;
  metrics: Record<string, unknown> | null;
}

export interface EvidenceView {
  available: boolean;
  statusMessage: string | null;
  connectionCount: number | null;
  /** 자산(인시던트 대상 호스트) 기준 송신 IP 바이트 */
  bytesSent: number | null;
  /** 자산 기준 수신 IP 바이트 */
  bytesReceived: number | null;
  payloadBytesInflated: number | null;
  transportCounts: Record<string, unknown>;
  serviceProtocolCounts: Record<string, unknown>;
  connStateCounts: Record<string, unknown>;
  topPeers: Array<Record<string, unknown>>;
  uniquePeers: number | null;
  topPorts: Array<Record<string, unknown>>;
  uniquePorts: number | null;
  protocolLogs: ProtocolLogEntry[];
  representativeConnections: Array<Record<string, unknown>>;
  limits: string[];
  additionalFields: Record<string, unknown>;
}

export interface FactItem {
  id: string;
  name: string;
  /** 글 값(객체·배열은 JSON 글). 화면 호환용 */
  value: string;
  /**
   * T37 구조 값(JSON 그대로, 조회자는 글 잎·객체 키의 IPv4가 가려짐).
   * null: 값이 null이거나 없음, 또는 조회자 마스킹 뒤 키가 겹쳐 싣지 않음(그때 value가 원문 자리를 맡는다).
   */
  valueJson?: unknown;
}

export interface ClaimItem {
  claim: string;
  facts: FactItem[];
}

export interface ExplanationItem {
  explanation: string;
  facts: FactItem[];
  attackIds: string[];
}

export interface SendRecommendationItem {
  choice: string | null;
  reason: string | null;
  facts: FactItem[];
}

export interface AttackCandidateItem {
  attackId: string;
  name: string;
  tactics: string[];
}

export interface ReportView {
  present: boolean;
  reportKind: string | null;
  reportVersion: string | null;
  inputVersion: string | null;
  llmModelRequested: string | null;
  llmModelVersion: string | null;
  llmSeconds: number | null;
  llmInputTokens: number | null;
  llmOutputTokens: number | null;
  llmThinkingTokens: number | null;
  llmError: string | null;
  verificationPassed: boolean | null;
  verificationReason: string | null;
  verificationProblems: string[];
  createdAt: string | null;
  sourceRun: string | null;
  pseudonyms: Record<string, string>;
  observationSummary: string | null;
  claims: ClaimItem[];
  possibleExplanations: ExplanationItem[];
  sendRecommendation: SendRecommendationItem | null;
  limitations: string[];
  followUp: string[];
  attackCandidates: AttackCandidateItem[];
  /** T37: 근거 사실 전체(원래 순서, 인용하지 않은 것 포함) */
  allFacts?: FactItem[];
  /** T37: 검증 문제 구조 목록(객체 {kind, value, where} 또는 글) */
  verificationProblemItems?: unknown[];
}

export interface SendDecisionView {
  present: boolean;
  wouldSend: boolean | null;
  decidedBy: string | null;
  policyId: string | null;
  policyChoice: string | null;
  policyMandatory: boolean | null;
  policyReasons: string[];
  llmChoice: string | null;
  decisionModel: string | null;
  decisionModelChoice: string | null;
  decisionModelConfidence: number | null;
  decisionModelProbabilities: Record<string, number>;
  decisionModelError: string | null;
  opinionMismatch: boolean;
}

export interface SlackDeliveryView {
  jobId: number | null;
  messageKind: string | null;
  messageVersion: string | null;
  deliveryMode: string | null;
  deliveryStatus: string | null;
  dryRunOrRecorded: boolean;
  slackTs: string | null;
  deliveredAt: string | null;
  error: string | null;
  createdAt: string | null;
  payloadJson: string;
  threadParent: string | null;
  threadKey: string | null;
  threadRoleLabel: string | null;
  replyBroadcast: boolean;
}

export interface SlackThreadGroup {
  threadKey: string;
  deliveries: SlackDeliveryView[];
  /** T40 묶음 머리가 지금 인시던트 */
  headIsSelf: boolean;
  /** T40 머리 인시던트 번호(머리를 볼 수 있을 때만, 아니면 null) */
  headIncidentNo: number | null;
  /** T40 묶음 인시던트 가운데 허용 캡처 안 최신 큐에 있는 수(머리를 볼 수 없으면 0) */
  memberCount: number;
}

export interface AnalystReviewView {
  present: boolean;
  reviewJobId: number | null;
  reviewReason: string | null;
  requestedAt: string | null;
  reviewAction: string | null;
  analystDisplay: string | null;
  decidedAt: string | null;
  resumedAt: string | null;
  resumeFailed: boolean;
  pending: boolean;
  resumeStatusLabel: string | null;
  canDecide: boolean;
}

export interface StatusHistoryItem {
  jobId: number | null;
  fromStatus: string | null;
  toStatus: string;
  resolution: string | null;
  actorDisplay: string | null;
  reason: string | null;
  changedAt: string | null;
}

export interface IncidentDetailView {
  incident: IncidentQueueItem;
  job: ScoringJob | null;
  modelScores: IncidentModelScore[];
  assetNames: AssetNameRecord[];
  evidence: EvidenceView;
  report: ReportView;
  sendDecision: SendDecisionView;
  slackDeliveries: SlackDeliveryView[];
  slackThreadGroups: SlackThreadGroup[];
  analystReview: AnalystReviewView;
  currentStatus: string;
  currentResolution: string | null;
  statusUpdatedAt: string | null;
  statusUpdatedByDisplay: string | null;
  statusHistory: StatusHistoryItem[];
  canTransition: boolean;
  nextAllowedStatus: string | null;
}

export interface IncidentDetailApiResponse {
  maskedView: boolean;
  canDecideReview: boolean;
  detail: IncidentDetailView;
  /** T23: 수집원·탐지 시각·서버 우선순위·진행 중(없으면 null) */
  queueMeta?: IncidentQueueMeta | null;
  /** T25: 현재 담당, 담당 이력(시간 역순), 담당을 바꿀 수 있는지(분석가·관리자이고 종결 아님) */
  assignment?: IncidentAssignment | null;
  assignmentHistory?: AssignmentHistoryItem[];
  canAssign?: boolean;
  /** T27 인시던트 번호(매기지 못했으면 null) */
  incidentNo?: number | null;
  /** T56: 대응 조치 기록(시간 역순), 기록할 수 있는지(분석가·관리자이고 신규가 아님) */
  responseActions?: ResponseActionItem[];
  canRecordResponse?: boolean;
}

export interface AnalystReviewItem {
  jobId: number | null;
  reviewJobId: number | null;
  captureId: string | null;
  incidentId: string;
  queueRank: number | null;
  hostIp: string | null;
  zeekadRole: string | null;
  zeekadReviewReason: string | null;
  requestedAt: string | null;
  zeekadReviewAction: string | null;
  analyst: string | null;
  analystDisplay: string | null;
  decidedAt: string | null;
  zeekadReviewResumedAt: string | null;
  zeekadReviewResumeFailed: boolean | null;
  /** T27 인시던트 번호(매기지 못했으면 null) */
  incidentNo?: number | null;
  pending?: boolean;
  resumeFailed?: boolean;
  resumeStatusLabel?: string;
}

export interface ReviewsApiResponse {
  maskedView: boolean;
  canDecideReview: boolean;
  allowedCaptures: string[];
  selectedCaptureId: string | null;
  pendingOnly: boolean;
  reviews: AnalystReviewItem[];
}

export interface ModelBundle {
  bundleId: string;
  registryName: string | null;
  registryVersion: string | null;
  manifestSha256: string | null;
  registeredAt: string | null;
  thresholds: Record<string, unknown> | null;
  thresholdEntries?: Record<string, string>;
}

export interface FeedbackSummaryRecord {
  captureId: string | null;
  bundleId: string | null;
  zeekadPickedBy: string | null;
  incidents: number | null;
  alerted: number | null;
  resolved: number | null;
  truePositive: number | null;
  falsePositive: number | null;
  benign: number | null;
  zeekadPrecision: number | null;
  zeekadAlertPrecision: number | null;
  zeekadAlertResolvedRate: number | null;
  alertedResolved: number | null;
  extraAttributes: Record<string, unknown>;
  allModel?: boolean;
  effectiveAlertedResolved?: number | null;
  precisionSummaryText?: string;
  alertPrecisionSummaryText?: string;
}

export interface SlackSummary {
  jobId: number | null;
  captureId: string | null;
  zeekadMessageVersion: string | null;
  zeekadDeliveryMode: string | null;
  zeekadDeliveryStatus: string | null;
  slackPayload: Record<string, unknown> | null;
  slackTs: string | null;
  deliveredAt: string | null;
  createdAt: string | null;
  dryRunOrRecorded?: boolean;
  payloadTextPreview?: string;
  payloadChannel?: string;
}

export interface OperationsApiResponse {
  maskedView: boolean;
  allowedCaptures: string[];
  selectedCaptureId: string | null;
  /** T24: period가 있으면 기간 안(완료 시각, 없으면 시작 시각)만, 최대 500건 */
  jobs: ScoringJob[];
  /** 조건 수집원의 작업이 쓴 모델 버전만 */
  bundles: ModelBundle[];
  /** 누적(기간 없음), 수집원 조건만 적용 */
  feedbackSummaries: FeedbackSummaryRecord[];
  /** T24: period가 있으면 기간 안(기록 시각)만 */
  slackSummaries: SlackSummary[];
  period?: string | null;
  /** T34 실제 기간 경계(UTC). 전체·period 없음이면 null */
  periodStart?: string | null;
  periodEnd?: string | null;
  source?: string | null;
  anchor?: string | null;
  jobsTruncated?: boolean;
  jobsTotal?: number;
  /** 캡처마다 최신 끝난 작업·최신 성공 작업(기간 무관) */
  latestJobs?: LatestJobs[];
  /** 허용 캡처 전체와 수집원 종류(조건 줄 선택지) */
  sources?: QueueSource[];
  /** T25: period가 있을 때만 */
  handlingTimes?: HandlingTimes;
  /** T25: 지금의 담당 현황(기간 무관) */
  workload?: Workload;
}

/** T25 한 지표: 건수, 중앙값·p90(초, n = 0이면 null), 제외, 표본 부족 */
export interface TimeStat {
  n: number;
  medianSeconds: number | null;
  p90Seconds: number | null;
  excluded: number;
  smallSample: boolean;
}

export interface ResolutionStat {
  /** true_positive · false_positive · benign · none */
  resolution: string;
  stat: TimeStat;
}

export interface HandlingTimes {
  detection: TimeStat;
  acknowledge: TimeStat;
  resolve: { all: TimeStat; byResolution: ResolutionStat[] };
}

export interface AssigneeLoad {
  username: string;
  displayName: string;
  enabled: boolean;
  open: number;
  investigating: number;
}

export interface Workload {
  unclosed: number;
  assigned: number;
  unassigned: number;
  ackOverdue: number;
  byAssignee: AssigneeLoad[];
}

/** T24 탐지 작업 요약(VIEWER면 오류 글의 IP가 가려진다). error는 실패 작업에만 있다 */
export interface JobRef {
  jobId: number;
  captureId: string;
  bundleId: string | null;
  status: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
}

export interface LatestJobs {
  captureId: string;
  latestEnded: JobRef | null;
  latestSucceeded: JobRef | null;
}

/* ───────────── T24 현황판 overview ───────────── */

export type TrendBucketUnit = '5m' | '1h' | '6h' | '1d' | '1w';

/** 구간 (start, end], UTC ISO. partial = 일부만 기간 안 */
export interface TrendBucket {
  start: string;
  end: string;
  partial: boolean;
  high: number;
  medium: number;
  low: number;
  none: number;
  total: number;
}

export interface DashboardTrend {
  bucket: TrendBucketUnit;
  buckets: TrendBucket[];
  unbucketed: { noDetectedAt: number; afterAnchor: number };
}

export type SensorHealth = 'ok' | 'stale' | 'down' | 'failed' | 'none';
export type CaptureState = 'active' | 'ended' | 'imported' | 'failed' | 'none';

export interface SensorRow {
  sensorKey: string;
  label: string;
  health: SensorHealth;
  latestJob: JobRef | null;
  activeCaptureId: string | null;
  lastScoredAt: string | null;
  lastActivityAt: string | null;
  total: number;
  high: number;
  alerted: number;
  failedJobs: number;
  captureCount: number;
}

export interface CaptureRow {
  captureId: string;
  sourceType: SourceType;
  sensorKey: string | null;
  state: CaptureState;
  latestJob: JobRef | null;
  lastScoredAt: string | null;
  lastActivityAt: string | null;
  total: number;
  high: number;
  alerted: number;
  failedJobs: number;
}

export interface DashboardAlerting {
  latestDeliveryMode: string | null;
  latestDeliveryStatus: string | null;
  latestDryRun: boolean;
  latestCreatedAt: string | null;
  latestDeliveredAt: string | null;
  latestCaptureId: string | null;
  summariesInPeriod: number;
}

export interface DashboardOverviewResponse {
  anchor: string;
  anchorMode: string;
  snapshot: boolean;
  period: string;
  /** T34 실제 기간 경계(UTC). 전체면 null */
  periodStart?: string | null;
  periodEnd?: string | null;
  timeZone: string;
  staleAfterSeconds: number;
  downAfterSeconds: number;
  trend: DashboardTrend;
  sensors: SensorRow[];
  captures: CaptureRow[];
  alerting: DashboardAlerting;
  maskedView: boolean;
  /** T45b 위협 가시성. 옛 응답에는 없을 수 있어 선택 필드다(없으면 빈 값으로 그린다) */
  attack?: DashboardAttack;
  topHosts?: DashboardTopHosts;
  topThreads?: TopThreadRow[];
  /** 알림 묶음이 많아 서버가 묶음 계산을 생략했다(topThreads는 빈 목록) */
  topThreadsOmitted?: boolean;
}

/** T45b ATT&CK 전술 한 줄. tactic = 슬러그, count = 같은 조건 큐 attack=슬러그의 total */
export interface AttackTacticCount {
  tactic: string;
  count: number;
}

/** T45b ATT&CK 기법 한 줄. attackId = 대문자 ID, count = 같은 조건 큐 attack=ID의 total */
export interface AttackTechniqueCount {
  attackId: string;
  name: string | null;
  count: number;
}

/** T45b 리포트의 ATT&CK 후보 분포. techniques는 상위 10개, techniqueCount는 고유 기법 수 전체 */
export interface DashboardAttack {
  incidentsWithCandidates: number;
  tactics: AttackTacticCount[];
  techniques: AttackTechniqueCount[];
  techniqueCount: number;
}

/** T45b 위험 호스트 한 줄. hostIp는 조회자면 가려진 값(A.B.*.*)이고 그 대역을 묶은 줄이다 */
export interface TopHostRow {
  hostIp: string;
  high: number;
  medium: number;
  low: number;
  total: number;
  lastDetectedAt: string | null;
}

export interface DashboardTopHosts {
  originator: TopHostRow[];
  responder: TopHostRow[];
}

/** T45b 알림 묶음 한 줄. periodIncidentCount = 지금 조건 안 구성원 수, totalMemberCount = 묶음 전체 구성원 수 */
export interface TopThreadRow {
  headIncidentNo: number;
  headHostIp: string | null;
  headPickedBy: string | null;
  periodIncidentCount: number;
  totalMemberCount: number;
  latestDetectedAt: string | null;
}

export interface AdminUserDto {
  id: number;
  username: string;
  displayName: string;
  role: UserRole;
  totpEnabled: boolean;
  failedAttempts: number;
  lockedUntil: string | null;
  enabled: boolean;
  createdAt: string | null;
  updatedAt: string | null;
  capturePatterns: string[];
}

export interface AdminUsersListResponse {
  users: AdminUserDto[];
  roles: UserRole[];
}

export interface AdminUserMutationResponse {
  message: string;
  user: AdminUserDto;
}

export interface AuditLog {
  id: number;
  occurredAt: string;
  actorUsername: string | null;
  actorRole: string | null;
  actionType: string;
  targetCaptureId: string | null;
  targetJobId: number | null;
  targetIncidentId: string | null;
  detailJson: string | null;
  clientIp: string | null;
}

export interface AdminAuditLogsResponse {
  logs: AuditLog[];
  actionTypes: string[];
  selectedActionType: string;
  selectedActorUsername: string;
  selectedLimit: number;
}
