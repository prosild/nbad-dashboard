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

/** T21: 로그인 화면 안내 문구(설정이 없으면 빈 문자열) */
export interface LoginNoticeResponse {
  notice: string;
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

/** 통합 큐 한 행: 큐 행 필드 + 서버가 계산한 탐지 시각·수집원 종류·우선순위·진행 중 */
export interface UnifiedQueueItem extends IncidentQueueItem {
  detectedAt: string | null;
  sourceType: SourceType;
  /** 종결이면 null */
  priority: QueuePriority | null;
  ongoing: boolean;
}

export interface UnifiedQueueSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  reviewPending: number;
  alerted: number;
  byStatus: Record<string, number>;
}

export interface QueueSource {
  captureId: string;
  sourceType: SourceType;
  latestJobId: number | null;
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
  latestDetectedAt: string | null;
  newestOutsidePeriod: string | null;
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
  value: string;
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
  jobs: ScoringJob[];
  bundles: ModelBundle[];
  feedbackSummaries: FeedbackSummaryRecord[];
  slackSummaries: SlackSummary[];
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
