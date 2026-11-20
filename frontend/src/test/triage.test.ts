import { describe, expect, it } from 'vitest';
import type { IncidentQueueItem } from '../types/api';
import {
  computePriority,
  isClosedStatus,
  normalizeStatus,
  pageWindow,
  parsePageSize,
  sortIncidents,
} from '../utils/triage';

function item(overrides: Partial<IncidentQueueItem> = {}): IncidentQueueItem {
  return {
    jobId: 1,
    captureId: 'cic17-wed',
    bundleId: 'zeekad-fusion/3',
    queueRank: 1,
    incidentId: 'x',
    hostIp: '10.0.0.1',
    zeekadRole: 'originator',
    eventStart: '2026-11-18T01:00:00Z',
    eventEnd: '2026-11-18T01:10:00Z',
    zeekadPickedBy: 'ae_v2',
    zeekadAlsoFlaggedBy: [],
    connectionCount: 10,
    hostName: [],
    zeekadStatus: 'open',
    zeekadResolution: null,
    statusUpdatedAt: null,
    zeekadReportJobId: null,
    hasReport: false,
    zeekadReportKind: null,
    zeekadVerificationPassed: null,
    zeekadWouldSend: false,
    zeekadReviewAction: null,
    zeekadReviewPending: false,
    ...overrides,
  };
}

describe('자동 분류 우선순위(computePriority)', () => {
  it('높음: 알림 보냄 또는 판단 대기', () => {
    expect(computePriority(item({ zeekadWouldSend: true }))).toBe('high');
    expect(computePriority(item({ zeekadReviewPending: true }))).toBe('high');
    // 높음 조건이 중간 조건보다 앞선다
    expect(computePriority(item({ zeekadWouldSend: true, hasReport: true, zeekadAlsoFlaggedBy: ['a'] }))).toBe('high');
  });

  it('중간: 함께 탐지한 모델 1개 이상 또는 보고서 있음', () => {
    expect(computePriority(item({ zeekadAlsoFlaggedBy: ['iforest_v1'] }))).toBe('medium');
    expect(computePriority(item({ zeekadAlsoFlaggedBy: ['a', 'b'] }))).toBe('medium');
    expect(computePriority(item({ hasReport: true }))).toBe('medium');
  });

  it('경계: 함께 탐지 0개면 낮음, 1개면 중간. multiModelFlagged 필드는 쓰지 않는다', () => {
    expect(computePriority(item({ zeekadAlsoFlaggedBy: [] }))).toBe('low');
    expect(computePriority(item({ zeekadAlsoFlaggedBy: [], multiModelFlagged: true }))).toBe('low');
    expect(computePriority(item({ zeekadAlsoFlaggedBy: ['a'], multiModelFlagged: false }))).toBe('medium');
    expect(computePriority(item({ zeekadAlsoFlaggedBy: null as unknown as string[] }))).toBe('low');
  });

  it('낮음: 그 밖', () => {
    expect(computePriority(item())).toBe('low');
  });

  it('종료: 우선순위 없음(null). 대소문자 무시', () => {
    expect(computePriority(item({ zeekadStatus: 'closed', zeekadWouldSend: true }))).toBeNull();
    expect(computePriority(item({ zeekadStatus: 'CLOSED', hasReport: true }))).toBeNull();
    expect(computePriority(item({ zeekadStatus: ' Closed ' }))).toBeNull();
  });

  it('상태 없음(null·빈 문자열)은 신규, 등록되지 않은 상태 값은 종료가 아닌 것으로 본다', () => {
    expect(normalizeStatus(null)).toBe('open');
    expect(normalizeStatus('')).toBe('open');
    expect(computePriority(item({ zeekadStatus: null, zeekadWouldSend: true }))).toBe('high');
    expect(computePriority(item({ zeekadStatus: '', hasReport: true }))).toBe('medium');
    expect(isClosedStatus('archived')).toBe(false);
    expect(computePriority(item({ zeekadStatus: 'archived' }))).toBe('low');
    expect(computePriority(item({ zeekadStatus: 'INVESTIGATING', zeekadReviewPending: true }))).toBe('high');
  });
});

describe('정렬(sortIncidents)', () => {
  const high = item({ queueRank: 3, zeekadWouldSend: true, connectionCount: 5, eventStart: '2026-11-18T03:00:00Z' });
  const medium = item({ queueRank: 1, hasReport: true, connectionCount: null, eventStart: null });
  const low = item({ queueRank: 2, connectionCount: 50, eventStart: '2026-11-18T01:00:00Z' });
  const closed = item({ queueRank: 4, zeekadStatus: 'closed', connectionCount: 500, eventStart: '2026-11-18T05:00:00Z' });
  const high2 = item({ queueRank: 5, zeekadReviewPending: true, zeekadStatus: 'investigating', connectionCount: 5 });
  const all = [closed, low, high2, medium, high];
  const ranks = (list: IncidentQueueItem[]) => list.map((i) => i.queueRank);

  it('우선순위 오름: 높음→중간→낮음, 같은 값은 순위 오름, 종료는 맨 뒤', () => {
    expect(ranks(sortIncidents(all, 'priority', 'asc'))).toEqual([3, 5, 1, 2, 4]);
  });

  it('우선순위 내림에서도 종료는 맨 뒤, 같은 값의 2차 키는 순위 오름 그대로', () => {
    expect(ranks(sortIncidents(all, 'priority', 'desc'))).toEqual([2, 1, 3, 5, 4]);
  });

  it('순위 정렬', () => {
    expect(ranks(sortIncidents(all, 'rank', 'asc'))).toEqual([1, 2, 3, 4, 5]);
    expect(ranks(sortIncidents(all, 'rank', 'desc'))).toEqual([5, 4, 3, 2, 1]);
  });

  it('연결 수·시각의 null은 방향과 상관없이 맨 뒤', () => {
    expect(ranks(sortIncidents(all, 'connections', 'desc'))).toEqual([4, 2, 3, 5, 1]);
    expect(ranks(sortIncidents(all, 'connections', 'asc'))).toEqual([3, 5, 2, 4, 1]);
    // high2의 eventStart는 기본값 01:00 → low(01:00)와 같으면 순위 오름
    expect(ranks(sortIncidents(all, 'start', 'desc'))).toEqual([4, 3, 2, 5, 1]);
    expect(ranks(sortIncidents(all, 'start', 'asc'))).toEqual([2, 5, 3, 4, 1]);
  });

  it('상태 순서: 신규 → 조사 중 → 종료', () => {
    expect(ranks(sortIncidents(all, 'status', 'asc'))).toEqual([1, 2, 3, 5, 4]);
    expect(ranks(sortIncidents(all, 'status', 'desc'))).toEqual([4, 5, 1, 2, 3]);
  });

  it('원본 배열을 바꾸지 않는다', () => {
    const copy = [...all];
    sortIncidents(all, 'rank', 'asc');
    expect(all).toEqual(copy);
  });
});

describe('페이지 나눔(pageWindow, parsePageSize)', () => {
  it('허용 밖 size는 50', () => {
    expect(parsePageSize('25')).toBe(25);
    expect(parsePageSize('100')).toBe(100);
    expect(parsePageSize('30')).toBe(50);
    expect(parsePageSize(null)).toBe(50);
    expect(parsePageSize('abc')).toBe(50);
  });

  it('경계: 첫 쪽, 마지막 쪽, 범위 밖은 마지막 쪽, 잘못된 값은 1쪽', () => {
    expect(pageWindow(241, null, 50)).toMatchObject({ page: 1, pageCount: 5, from: 1, to: 50 });
    expect(pageWindow(241, '5', 50)).toMatchObject({ page: 5, from: 201, to: 241 });
    expect(pageWindow(241, '9', 50)).toMatchObject({ page: 5, from: 201, to: 241 });
    expect(pageWindow(241, '0', 50)).toMatchObject({ page: 1 });
    expect(pageWindow(241, '-2', 50)).toMatchObject({ page: 1 });
    expect(pageWindow(241, '1.5', 50)).toMatchObject({ page: 1 });
    expect(pageWindow(100, '2', 50)).toMatchObject({ page: 2, pageCount: 2, from: 51, to: 100 });
    expect(pageWindow(0, '3', 50)).toMatchObject({ page: 1, pageCount: 1, from: 0, to: 0 });
  });
});
