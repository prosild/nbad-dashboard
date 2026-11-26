import type { QueuePriority, QueueSource } from './api';

/** GET /api/hosts 한 줄(T46). 조회자면 hostIp가 가려진 대역(A.B.*.*)이고 한 줄이 그 대역의 호스트 전부다 */
export interface HostRiskItem {
  hostIp: string;
  /** 글자 순 앞 5개. 전체 수는 hostNameCount */
  hostNames: string[];
  hostNameCount: number;
  /** 글자 순 앞 5개(조회자는 가린 이름). 전체 수는 accountCount */
  accounts: string[];
  accountCount: number;
  /** 미종결 우선순위별 건수(종결은 우선순위가 없다) */
  high: number;
  medium: number;
  low: number;
  /** 종결 포함 전체 */
  incidents: number;
  connections: number;
  /** 탐지 모델 식별자(건수 많은 순) */
  models: string[];
  lastDetectedAt: string | null;
  /** 같은 캡처에서 목적지로 탐지된 뒤 출발지로 탐지됨(조회자는 늘 false) */
  roleTransition: boolean;
  /** T52 이 줄의 호스트(조회자는 대역 안의 호스트 하나라도)가 중요 자산인지 */
  assetCritical?: boolean;
  /** T52 중요 자산 이름(분석가·관리자만. 조회자는 늘 null) */
  criticalAssetName?: string | null;
}

export interface HostRiskResponse {
  items: HostRiskItem[];
  /** 검색·전환 거르기를 적용한 뒤의 줄 수 */
  total: number;
  page: number;
  size: number;
  pageCount: number;
  anchor: string | null;
  anchorMode: string;
  snapshot: boolean;
  period: string;
  periodStart: string | null;
  periodEnd: string | null;
  sources: QueueSource[];
  maskedView: boolean;
}

/** 상세의 같은 호스트 인시던트 한 건(T46). 원문 인시던트 ID는 오지 않는다 */
export interface RelatedHostIncident {
  incidentNo: number | null;
  jobId: number;
  queueRank: number;
  captureId: string;
  hostIp: string;
  zeekadRole: string | null;
  eventStart: string | null;
  detectedAt: string | null;
  /** 종결이면 null */
  priority: QueuePriority | null;
  zeekadStatus: string | null;
  zeekadResolution: string | null;
  zeekadPickedBy: string | null;
  connectionCount: number | null;
  /** T52 중요 자산 여부, 기본 우선순위, 이름(조회자는 null) */
  assetCritical?: boolean;
  priorityBase?: QueuePriority | null;
  criticalAssetName?: string | null;
}

export interface RelatedHostIncidentsResponse {
  /** 이 인시던트의 호스트(조회자는 가린 대역) */
  hostIp: string | null;
  /** 자신을 뺀 전체 건수 */
  total: number;
  /** 발생 시각이 가까운 최대 10건(발생 시각 최근 순) */
  items: RelatedHostIncident[];
  maskedView: boolean;
}
