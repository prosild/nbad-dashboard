import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SORT_DIR,
  isClosedStatus,
  migrateLegacyQueueParams,
  normalizeStatus,
  parsePage,
  parsePageSize,
  parsePeriod,
  parseQueueQuery,
  parseSource,
  queueApiParams,
} from '../utils/triage';

/**
 * T23: 우선순위 계산·정렬·쪽 나눔은 서버(SQL)로 옮겼다. 옛 computePriority·sortIncidents·pageWindow 시험은
 * Gradle T23UnifiedQueueIntegrationTest의 조합 표(우선순위·정렬 세부·쪽 이음)가 맡는다.
 * 여기서는 화면에 남은 URL 해석·API 파라미터·옛 주소 정리를 본다.
 */

describe('상태 정규화(상세 조치 패널이 쓴다)', () => {
  it('null·빈 값은 신규, 대소문자·공백 무시, 등록되지 않은 값은 종결이 아니다', () => {
    expect(normalizeStatus(null)).toBe('open');
    expect(normalizeStatus('')).toBe('open');
    expect(normalizeStatus(' INVESTIGATING ')).toBe('investigating');
    expect(isClosedStatus(' Closed ')).toBe(true);
    expect(isClosedStatus('archived')).toBe(false);
  });
});

describe('목록 쿼리 해석(parseQueueQuery)', () => {
  it('기본값: 기간 24시간, 우선순위 오름, 1쪽, 50건', () => {
    const q = parseQueueQuery(new URLSearchParams(''));
    expect(q).toMatchObject({
      period: '24h',
      source: null,
      captureId: null,
      priority: null,
      reviewPending: false,
      alerted: false,
      sortKey: 'priority',
      sortDir: 'asc',
      page: 1,
      size: 50,
    });
  });

  it('정렬 키만 주면 그 열의 처음 방향, 허용 밖 값은 기본값으로 읽는다', () => {
    expect(parseQueueQuery(new URLSearchParams('sort=detected')).sortDir).toBe(DEFAULT_SORT_DIR.detected);
    expect(parseQueueQuery(new URLSearchParams('sort=detected')).sortDir).toBe('desc');
    expect(parseQueueQuery(new URLSearchParams('sort=status')).sortDir).toBe('asc');
    expect(parseQueueQuery(new URLSearchParams('sort=rank&dir=desc'))).toMatchObject({ sortKey: 'priority', sortDir: 'desc' });
    expect(parseQueueQuery(new URLSearchParams('priority=critical')).priority).toBeNull();
    expect(parseQueueQuery(new URLSearchParams('period=2d')).period).toBe('24h');
    expect(parseQueueQuery(new URLSearchParams('source=cloud')).source).toBeNull();
    expect(parseQueueQuery(new URLSearchParams('captureId=%20%20')).captureId).toBeNull();
  });

  it('기간·수집원·쪽 값', () => {
    expect(parsePeriod('all')).toBe('all');
    expect(parsePeriod('1h')).toBe('1h');
    expect(parsePeriod(null)).toBe('24h');
    expect(parseSource('live')).toBe('live');
    expect(parseSource('imported')).toBe('imported');
    expect(parsePageSize('25')).toBe(25);
    expect(parsePageSize('100')).toBe(100);
    expect(parsePageSize('30')).toBe(50);
    expect(parsePageSize(null)).toBe(50);
    expect(parsePageSize('abc')).toBe(50);
    expect(parsePage('3')).toBe(3);
    expect(parsePage('0')).toBe(1);
    expect(parsePage('-2')).toBe(1);
    expect(parsePage('1.5')).toBe(1);
    expect(parsePage(null)).toBe(1);
  });
});

describe('API 파라미터(queueApiParams)', () => {
  const q = parseQueueQuery(
    new URLSearchParams('period=7d&source=live&captureId=lab-x&priority=high&reviewPending=true&alerted=true&status=open&asset=10.0&sort=start&dir=asc&page=3&size=25'),
  );

  it('목록: 거르기·정렬·쪽을 모두 보낸다', () => {
    expect(queueApiParams(q)).toEqual({
      period: '7d',
      source: 'live',
      captureId: 'lab-x',
      priority: 'high',
      reviewPending: 'true',
      alerted: 'true',
      pickedBy: undefined,
      role: undefined,
      status: 'open',
      hasReport: undefined,
      wouldSend: undefined,
      asset: '10.0',
      sort: 'start',
      dir: 'asc',
      page: '3',
      size: '25',
    });
  });

  it('이전·다음은 쪽을 빼고, 새 인시던트 수는 기간·정렬·쪽을 뺀다', () => {
    const nb = queueApiParams(q, { paging: false });
    expect(nb.page).toBeUndefined();
    expect(nb.size).toBeUndefined();
    expect(nb.sort).toBe('start');
    const nc = queueApiParams(q, { paging: false, sort: false, period: false });
    expect(nc.period).toBeUndefined();
    expect(nc.sort).toBeUndefined();
    expect(nc.dir).toBeUndefined();
    expect(nc.priority).toBe('high');
    expect(nc.asset).toBe('10.0');
  });
});

describe('옛 주소 정리(migrateLegacyQueueParams)', () => {
  it('jobId는 지우고 안내 대상, sort=rank는 기본 정렬, captureId는 남긴다', () => {
    const r = migrateLegacyQueueParams(new URLSearchParams('captureId=cic17-wed&jobId=42&sort=rank&dir=desc&status=open'));
    expect(r.changed).toBe(true);
    expect(r.droppedJob).toBe(true);
    expect(r.next.toString()).toBe('captureId=cic17-wed&status=open');
  });

  it('바꿀 것이 없으면 그대로', () => {
    const r = migrateLegacyQueueParams(new URLSearchParams('period=all&sort=detected'));
    expect(r.changed).toBe(false);
    expect(r.droppedJob).toBe(false);
  });

  it('jobId 없이 sort=rank만 있으면 안내 없이 바꾼다', () => {
    const r = migrateLegacyQueueParams(new URLSearchParams('sort=rank'));
    expect(r.changed).toBe(true);
    expect(r.droppedJob).toBe(false);
    expect(r.next.toString()).toBe('');
  });
});
