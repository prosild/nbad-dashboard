/**
 * 운영 지표 계산과 판정 집계 문장(docs/ui-terminology.md '운영 지표 정의').
 * 계산식은 zeek_AD dashboard.feedback_summary 뷰 정의를 따른다:
 * - 정탐률 = 정탐 / 판정 완료 (zeekad_precision)
 * - 경보 정탐률 = 경보 발송 ∧ 정탐 / 경보 발송 ∧ 판정 완료 (zeekad_alert_precision)
 * - 경보 판정률 = 경보 발송 ∧ 판정 완료 / 경보 발송 (zeekad_alert_resolved_rate. 경보 판정 수를 되돌릴 때만 쓰고 화면 글에는 쓰지 않는다, T67)
 * 문장 형식은 백엔드 FeedbackSummaryRecord#getPrecisionSummaryText·getAlertPrecisionSummaryText와 같다(둘이 다르면 안 된다.
 * 두 시험이 같은 기대값 파일 src/test/fixtures/feedback-summary-text-cases.json을 읽는다).
 */
import type { FeedbackSummaryRecord, ScoringJob } from '../types/api';
import { formatNumber } from './format';

/** 판정이 이 건수보다 적으면 비율 대신 "표본 부족"을 쓴다. */
export const SAMPLE_MIN = 10;
export const SAMPLE_SHORT_LABEL = '표본 부족';
export const SAMPLE_SHORT_TOOLTIP = `판정 ${SAMPLE_MIN}건 미만이라 비율을 믿기 어렵습니다`;

/** 0~1 비율 값(뷰가 소수 셋째 자리로 반올림한 값) → "60.0%" */
export function ratioPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) {
    return '-';
  }
  return `${(Math.round(ratio * 1000) / 10).toFixed(1)}%`;
}

export function isAllModelRow(row: FeedbackSummaryRecord): boolean {
  if (row.allModel !== undefined) {
    return row.allModel;
  }
  return (row.zeekadPickedBy ?? '').trim().toLowerCase() === 'all';
}

/** 경보 발송 ∧ 판정 완료 건수. 백엔드 getEffectiveAlertedResolved와 같은 규칙. */
export function effectiveAlertedResolved(row: FeedbackSummaryRecord): number | null {
  if (row.alertedResolved !== null && row.alertedResolved !== undefined) {
    return row.alertedResolved;
  }
  const alerted = row.alerted;
  if (alerted !== null && alerted !== undefined && alerted > 0 && row.zeekadAlertResolvedRate !== null && row.zeekadAlertResolvedRate !== undefined) {
    return Math.round(row.zeekadAlertResolvedRate * alerted);
  }
  if (alerted === 0) {
    return 0;
  }
  return null;
}

/**
 * 정탐률 문장(T67). 판정 수 ÷ 인시던트 수의 백분율은 쓰지 않는다(탐지율로 읽힌다). 두 수를 "/"로 나란히 둔다.
 * 예: "정탐률 60.0% · 분석가 판정 12건 / 모델이 올린 인시던트 18건", "표본 부족 · 분석가 판정 5건 / 모델이 올린 인시던트 2,277건",
 * "분석가 판정 없음 / 모델이 올린 인시던트 5건", "분석가 판정 없음"(인시던트도 0). 인시던트 0이면 "/ …" 없이 앞머리만.
 */
export function precisionSummaryText(row: Pick<FeedbackSummaryRecord, 'incidents' | 'resolved' | 'zeekadPrecision'>): string {
  const resolved = row.resolved ?? 0;
  const incidents = row.incidents ?? 0;
  const tail = incidents > 0 ? ` / 모델이 올린 인시던트 ${formatNumber(incidents)}건` : '';
  if (resolved <= 0) {
    return `분석가 판정 없음${tail}`;
  }
  const head = resolved < SAMPLE_MIN ? SAMPLE_SHORT_LABEL : `정탐률 ${ratioPercent(row.zeekadPrecision)}`;
  return `${head} · 분석가 판정 ${formatNumber(resolved)}건${tail}`;
}

/**
 * 경보 정탐률 문장(T67). 판정 수 ÷ 경보 수의 백분율은 쓰지 않는다.
 * 예: "경보 정탐률 75.0% · 분석가 판정 12건 / 경보 16건", "표본 부족 · 분석가 판정 4건 / 경보 6건", "분석가 판정 없음 / 경보 2건",
 * "경보 3건 · 분석가 판정 수 알 수 없음", "경보 없음"
 */
export function alertPrecisionSummaryText(row: FeedbackSummaryRecord): string {
  const alerted = row.alerted ?? 0;
  if (alerted <= 0) {
    return '경보 없음';
  }
  const eff = effectiveAlertedResolved(row);
  if (eff === null) {
    return `경보 ${formatNumber(alerted)}건 · 분석가 판정 수 알 수 없음`;
  }
  const tail = ` / 경보 ${formatNumber(alerted)}건`;
  if (eff <= 0) {
    return `분석가 판정 없음${tail}`;
  }
  const head = eff < SAMPLE_MIN ? SAMPLE_SHORT_LABEL : `경보 정탐률 ${ratioPercent(row.zeekadAlertPrecision)}`;
  return `${head} · 분석가 판정 ${formatNumber(eff)}건${tail}`;
}

/** 정탐률 값(표본 부족이면 null). 표본 부족일 때 실제 값은 툴팁으로 보인다. */
export function precisionValue(resolved: number, precision: number | null | undefined): number | null {
  if (resolved < SAMPLE_MIN || precision === null || precision === undefined || !Number.isFinite(precision)) {
    return null;
  }
  return precision;
}

/** 표본 부족일 때 툴팁: 실제 값과 기준 */
export function sampleShortTooltip(label: string, resolved: number, precision: number | null | undefined): string {
  return `${label} ${ratioPercent(precision)}(판정 ${formatNumber(resolved)}건). ${SAMPLE_SHORT_TOOLTIP}.`;
}

/** 판정 관련 수가 모두 0인 행(판정·경보 없음). 표에서 한 줄로 줄인다. */
export function isQuietRow(row: FeedbackSummaryRecord): boolean {
  return (row.resolved ?? 0) === 0 && (row.alerted ?? 0) === 0;
}

function isSucceeded(job: ScoringJob): boolean {
  return (job.status ?? '').toLowerCase() === 'succeeded';
}

/**
 * 캡처마다 쓸 모델 버전 하나를 고른다. feedback_summary는 캡처마다 최신 탐지 작업 하나로 만들어져 보통 '모든 모델 합계' 행이 하나다.
 * 한 캡처에 '모든 모델 합계' 행이 둘 이상이면, 그 캡처의 최근 성공 탐지 작업과 같은 모델 버전 행을 쓴다(없으면 응답 순서의 첫 행).
 * T24: jobs에는 기간으로 거른 작업 목록이 아니라 /api/operations latestJobs의 최신 성공 작업을 넘긴다(누적 표가 기간에 따라 바뀌지 않게).
 */
export function selectSummaryRows(summaries: FeedbackSummaryRecord[], jobs: ScoringJob[]): {
  allRows: FeedbackSummaryRecord[];
  modelRows: FeedbackSummaryRecord[];
} {
  const allByCapture = new Map<string, FeedbackSummaryRecord[]>();
  for (const row of summaries) {
    if (!isAllModelRow(row) || !row.captureId) continue;
    const list = allByCapture.get(row.captureId) ?? [];
    list.push(row);
    allByCapture.set(row.captureId, list);
  }
  const chosenBundle = new Map<string, string | null>();
  const allRows: FeedbackSummaryRecord[] = [];
  for (const [captureId, rows] of allByCapture) {
    let chosen = rows[0];
    if (rows.length > 1) {
      const latestOk = jobs
        .filter((j) => j.captureId === captureId && isSucceeded(j))
        .reduce<ScoringJob | null>((best, j) => (!best || j.jobId > best.jobId ? j : best), null);
      chosen = rows.find((r) => latestOk && r.bundleId === latestOk.bundleId) ?? rows[0];
    }
    chosenBundle.set(captureId, chosen.bundleId);
    allRows.push(chosen);
  }
  allRows.sort((a, b) => (a.captureId ?? '').localeCompare(b.captureId ?? ''));
  const modelRows = summaries.filter(
    (row) =>
      !isAllModelRow(row) &&
      row.captureId !== null &&
      chosenBundle.has(row.captureId) &&
      chosenBundle.get(row.captureId) === row.bundleId,
  );
  return { allRows, modelRows };
}

export interface OverviewTotals {
  incidents: number;
  alerted: number;
  resolved: number;
  unresolved: number;
  truePositive: number;
  /** 경보 발송 ∧ 판정 완료 합(행 하나라도 알 수 없으면 null) */
  alertedResolved: number | null;
  /**
   * 경보 발송 ∧ 정탐 합. 뷰가 건수를 주지 않아 행마다 경보 정탐률(소수 셋째 자리) × 경보 판정 수를 반올림해 되돌린다.
   * 경보 판정 수가 1,000건 이상인 행이 있으면 반올림 오차가 생길 수 있어 null로 둔다.
   */
  alertedTruePositive: number | null;
}

/** 캡처별 '모든 모델 합계' 행을 더한다(인시던트 목록과 같은 기준: 캡처마다 최신 탐지 작업). */
export function sumAllRows(allRows: FeedbackSummaryRecord[]): OverviewTotals {
  const totals: OverviewTotals = {
    incidents: 0,
    alerted: 0,
    resolved: 0,
    unresolved: 0,
    truePositive: 0,
    alertedResolved: 0,
    alertedTruePositive: 0,
  };
  for (const row of allRows) {
    totals.incidents += row.incidents ?? 0;
    totals.alerted += row.alerted ?? 0;
    totals.resolved += row.resolved ?? 0;
    totals.truePositive += row.truePositive ?? 0;
    const eff = effectiveAlertedResolved(row);
    totals.alertedResolved = eff === null || totals.alertedResolved === null ? null : totals.alertedResolved + eff;
    if (eff === null || totals.alertedTruePositive === null || eff >= 1000) {
      totals.alertedTruePositive = null;
    } else if (eff > 0) {
      const p = row.zeekadAlertPrecision;
      totals.alertedTruePositive =
        p === null || p === undefined || !Number.isFinite(p) ? null : totals.alertedTruePositive + Math.round(p * eff);
    }
  }
  totals.unresolved = Math.max(0, totals.incidents - totals.resolved);
  return totals;
}

/** 합계를 판정 집계 행 모양으로 바꾼다(상태 카드 문장을 행 문장과 같은 함수로 만들기 위해). */
export function totalsAsRow(t: OverviewTotals): FeedbackSummaryRecord {
  return {
    captureId: null,
    bundleId: null,
    zeekadPickedBy: 'all',
    incidents: t.incidents,
    alerted: t.alerted,
    resolved: t.resolved,
    truePositive: t.truePositive,
    falsePositive: null,
    benign: null,
    zeekadPrecision: t.resolved > 0 ? t.truePositive / t.resolved : null,
    zeekadAlertPrecision:
      t.alertedResolved !== null && t.alertedResolved > 0 && t.alertedTruePositive !== null
        ? t.alertedTruePositive / t.alertedResolved
        : null,
    zeekadAlertResolvedRate: t.alertedResolved !== null && t.alerted > 0 ? t.alertedResolved / t.alerted : null,
    alertedResolved: t.alertedResolved,
    extraAttributes: {},
    allModel: true,
  };
}
