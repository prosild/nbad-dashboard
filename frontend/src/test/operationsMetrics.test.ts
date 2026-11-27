import { describe, expect, it } from 'vitest';
import type { FeedbackSummaryRecord, OperationsApiResponse, ScoringJob } from '../types/api';
import { latestSucceededJobs } from '../pages/OperationsPage';
import {
  alertPrecisionSummaryText,
  precisionSummaryText,
  precisionValue,
  selectSummaryRows,
  sumAllRows,
  totalsAsRow,
} from '../utils/operations';
import sharedCases from './fixtures/feedback-summary-text-cases.json';

function row(partial: Partial<FeedbackSummaryRecord>): FeedbackSummaryRecord {
  return {
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    zeekadPickedBy: 'all',
    incidents: 0,
    alerted: 0,
    resolved: 0,
    truePositive: 0,
    falsePositive: 0,
    benign: 0,
    zeekadPrecision: null,
    zeekadAlertPrecision: null,
    zeekadAlertResolvedRate: null,
    alertedResolved: null,
    extraAttributes: {},
    ...partial,
  };
}

function job(partial: Partial<ScoringJob>): ScoringJob {
  return {
    jobId: 1,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    status: 'succeeded',
    startedAt: null,
    finishedAt: null,
    error: null,
    incidentCount: null,
    ...partial,
  };
}

/**
 * T67: 판정 수 ÷ 인시던트(경보) 수의 백분율이 없는지. 남는 백분율은 앞머리의 정탐률·경보 정탐률 하나뿐이다
 * (백엔드 FeedbackSummaryRecordTest#assertNoResolvedShareOfIncidents와 같은 규칙).
 */
function expectNoResolvedShare(text: string): void {
  expect(text, text).not.toMatch(/건\(\s*[\d.]+%\)/);
  expect(text, text).not.toMatch(/\d\/[\d,]+건/);
  const percents = text.match(/%/g) ?? [];
  expect(percents.length, text).toBeLessThanOrEqual(1);
  if (percents.length === 1) {
    expect(text, text).toMatch(/^(정탐률|경보 정탐률) [\d.]+% · /);
  }
}

describe('판정 집계 문장(백엔드 FeedbackSummaryRecordTest와 같은 기대값)', () => {
  it('분석가 판정 없음·표본 부족·정탐률. 뒤에 "모델이 올린 인시던트 M건"', () => {
    expect(precisionSummaryText(row({ incidents: 5, resolved: 0 }))).toBe('분석가 판정 없음 / 모델이 올린 인시던트 5건');
    expect(precisionSummaryText(row({ incidents: 0, resolved: 0 }))).toBe('분석가 판정 없음');
    expect(precisionSummaryText(row({ incidents: 5, resolved: 3, zeekadPrecision: 0.6 }))).toBe(
      '표본 부족 · 분석가 판정 3건 / 모델이 올린 인시던트 5건',
    );
    expect(precisionSummaryText(row({ incidents: 1234, resolved: 9, zeekadPrecision: 0.556 }))).toBe(
      '표본 부족 · 분석가 판정 9건 / 모델이 올린 인시던트 1,234건',
    );
    expect(precisionSummaryText(row({ incidents: 1234, resolved: 10, zeekadPrecision: 0.6 }))).toBe(
      '정탐률 60.0% · 분석가 판정 10건 / 모델이 올린 인시던트 1,234건',
    );
    expect(precisionSummaryText(row({ incidents: 50, resolved: 18, zeekadPrecision: 0.278 }))).toBe(
      '정탐률 27.8% · 분석가 판정 18건 / 모델이 올린 인시던트 50건',
    );
    // 판정 > 0이고 인시던트 0이면 "/ …" 없이 같은 앞머리
    expect(precisionSummaryText(row({ incidents: 0, resolved: 3, zeekadPrecision: 0.6 }))).toBe('표본 부족 · 분석가 판정 3건');
    expect(precisionSummaryText(row({ incidents: 0, resolved: 12, zeekadPrecision: 0.75 }))).toBe('정탐률 75.0% · 분석가 판정 12건');
  });

  it('경보 없음·분석가 판정 없음·표본 부족·경보 정탐률. 뒤에 "경보 b건"', () => {
    expect(alertPrecisionSummaryText(row({ alerted: 0 }))).toBe('경보 없음');
    expect(alertPrecisionSummaryText(row({ alerted: 2, zeekadAlertResolvedRate: 0 }))).toBe('분석가 판정 없음 / 경보 2건');
    expect(alertPrecisionSummaryText(row({ alerted: 3 }))).toBe('경보 3건 · 분석가 판정 수 알 수 없음');
    expect(alertPrecisionSummaryText(row({ alerted: 4, alertedResolved: 2, zeekadAlertPrecision: 0.5 }))).toBe(
      '표본 부족 · 분석가 판정 2건 / 경보 4건',
    );
    // alerted_resolved가 없으면 경보 판정률 × 경보 수로 되돌린다
    expect(alertPrecisionSummaryText(row({ alerted: 4, zeekadAlertResolvedRate: 0.75, zeekadAlertPrecision: 0.67 }))).toBe(
      '표본 부족 · 분석가 판정 3건 / 경보 4건',
    );
    expect(alertPrecisionSummaryText(row({ alerted: 20, alertedResolved: 9, zeekadAlertPrecision: 0.778 }))).toBe(
      '표본 부족 · 분석가 판정 9건 / 경보 20건',
    );
    expect(alertPrecisionSummaryText(row({ alerted: 20, alertedResolved: 10, zeekadAlertPrecision: 0.7 }))).toBe(
      '경보 정탐률 70.0% · 분석가 판정 10건 / 경보 20건',
    );
  });

  it('T67: 공유 기대값 파일(백엔드 FeedbackSummaryRecordTest가 같은 파일을 읽는다)의 모든 경우가 같은 글이고 판정 ÷ 인시던트·경보 백분율이 없다', () => {
    expect(sharedCases.precision.length).toBeGreaterThanOrEqual(10);
    expect(sharedCases.alert.length).toBeGreaterThanOrEqual(10);
    for (const c of sharedCases.precision) {
      const text = precisionSummaryText(row(c.input as Partial<FeedbackSummaryRecord>));
      expect(text, JSON.stringify(c.input)).toBe(c.expected);
      expectNoResolvedShare(text);
    }
    for (const c of sharedCases.alert) {
      const text = alertPrecisionSummaryText(row(c.input as Partial<FeedbackSummaryRecord>));
      expect(text, JSON.stringify(c.input)).toBe(c.expected);
      expectNoResolvedShare(text);
    }
  });

  it('표본 부족 경계: 판정 9건이면 값이 없고 10건이면 값이 있다', () => {
    expect(precisionValue(9, 0.9)).toBeNull();
    expect(precisionValue(10, 0.9)).toBe(0.9);
    expect(precisionValue(10, null)).toBeNull();
  });
});

describe('현황판 합계', () => {
  it('캡처별 모든 모델 합계 행을 더하고 탐지 모델 행은 따로 모은다', () => {
    const summaries = [
      row({ captureId: 'cic17-wed', incidents: 79, alerted: 9, resolved: 1, truePositive: 1, alertedResolved: 1, zeekadAlertPrecision: 1 }),
      row({ captureId: 'cic17-wed', zeekadPickedBy: 'tgn_recon', incidents: 30, resolved: 1, truePositive: 1 }),
      row({ captureId: 'syn1-thu', incidents: 21, alerted: 3, resolved: 12, truePositive: 6, alertedResolved: 3, zeekadAlertPrecision: 0.667 }),
      row({ captureId: 'syn1-thu', zeekadPickedBy: 'tgn_recon', incidents: 10, resolved: 9, truePositive: 3 }),
    ];
    const { allRows, modelRows } = selectSummaryRows(summaries, []);
    expect(allRows.map((r) => r.captureId)).toEqual(['cic17-wed', 'syn1-thu']);
    const totals = sumAllRows(allRows);
    expect(totals).toMatchObject({ incidents: 100, alerted: 12, resolved: 13, unresolved: 87, truePositive: 7 });
    expect(totals.alertedResolved).toBe(4);
    expect(totals.alertedTruePositive).toBe(3);
    const asRow = totalsAsRow(totals);
    expect(precisionSummaryText(asRow)).toBe('정탐률 53.8% · 분석가 판정 13건 / 모델이 올린 인시던트 100건');
    expect(alertPrecisionSummaryText(asRow)).toBe('표본 부족 · 분석가 판정 4건 / 경보 12건');

    // T24: 현황판의 '탐지 모델 상태' 패널(modelStatuses)은 없어졌다. 탐지 모델별 행은 운영 현황 판정 집계 표에서 펼쳐 본다.
    expect(modelRows.map((r) => [r.captureId, r.zeekadPickedBy, r.incidents])).toEqual([
      ['cic17-wed', 'tgn_recon', 30],
      ['syn1-thu', 'tgn_recon', 10],
    ]);
  });

  it('한 캡처에 모든 모델 합계 행이 둘이면 최근 성공 탐지 작업의 모델 버전 행만 쓴다', () => {
    const summaries = [
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', incidents: 79 }),
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/2', incidents: 50 }),
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', zeekadPickedBy: 'tgn_recon', incidents: 30 }),
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/2', zeekadPickedBy: 'tgn_recon', incidents: 20 }),
    ];
    const jobs = [
      job({ jobId: 7, bundleId: 'zeekad-fusion/2', status: 'succeeded' }),
      job({ jobId: 8, bundleId: 'zeekad-fusion/3', status: 'failed' }),
      job({ jobId: 5, bundleId: 'zeekad-fusion/3', status: 'succeeded' }),
    ];
    const { allRows, modelRows } = selectSummaryRows(summaries, jobs);
    expect(allRows).toHaveLength(1);
    expect(allRows[0].bundleId).toBe('zeekad-fusion/2');
    expect(sumAllRows(allRows).incidents).toBe(50);
    expect(modelRows.map((r) => r.incidents)).toEqual([20]);
  });

  it('T24: 누적 표의 모델 버전은 기간으로 거른 jobs가 아니라 latestJobs의 최신 성공 작업으로 고른다', () => {
    const summaries = [
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/3', incidents: 79 }),
      row({ captureId: 'cic17-wed', bundleId: 'zeekad-fusion/2', incidents: 50 }),
    ];
    const ref = (jobId: number, bundleId: string, status: string) => ({
      jobId,
      captureId: 'cic17-wed',
      bundleId,
      status,
      startedAt: null,
      finishedAt: null,
      error: null,
    });
    const base = {
      maskedView: false,
      allowedCaptures: ['cic17-wed'],
      selectedCaptureId: null,
      bundles: [],
      feedbackSummaries: summaries,
      slackSummaries: [],
      latestJobs: [{ captureId: 'cic17-wed', latestEnded: ref(8, 'zeekad-fusion/3', 'failed'), latestSucceeded: ref(7, 'zeekad-fusion/2', 'succeeded') }],
    } as unknown as OperationsApiResponse;
    // 기간 1시간: 기간 안 작업 없음 / 기간 전체: 작업 있음. 어느 쪽이든 고른 행은 같다.
    for (const jobs of [[], [job({ jobId: 5, bundleId: 'zeekad-fusion/3' })]]) {
      const data = { ...base, jobs } as OperationsApiResponse;
      const { allRows } = selectSummaryRows(data.feedbackSummaries, latestSucceededJobs(data));
      expect(allRows.map((r) => r.bundleId)).toEqual(['zeekad-fusion/2']);
    }
    expect(latestSucceededJobs({ ...base, latestJobs: undefined } as OperationsApiResponse)).toEqual([]);
  });
});
