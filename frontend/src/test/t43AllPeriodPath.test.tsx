import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { allPeriodReason, SourceStatusList, type AllPeriodContext } from '../components/dashboard/SourceStatus';
import { EmptyPeriodText, sameInstant } from '../components/OutsidePeriodNotice';
import type { CaptureRow, DashboardOverviewResponse, QueueSource, SensorRow, UnifiedQueueResponse } from '../types/api';

/**
 * T43 현황판 "전체 기간" 길과 0건 안내 한 문단.
 * - 현황판 줄: 기간 안 0건이고 지금 조건 큐 응답의 마지막 탐지가 기간 밖인 캡처(가져온 데이터 줄, 센서 아래 캡처 표지)에만
 *   period=all&captureId=… 링크를 나란히 둔다. 원래 링크는 기간을 유지한다. 센서 줄에는 두지 않는다.
 * - 0건 안내: 고른 캡처의 마지막 탐지와 기간 밖 가장 최근 탐지가 같은 순간이면 한 문단.
 */

const ANCHOR = '2026-11-23T00:48:35Z';
const H24_START = '2026-11-22T00:48:35Z';
const OLD = '2026-11-12T02:28:09Z'; // 기준 시각 10일 전쯤
const RECENT = '2026-11-22T20:00:00Z'; // 기간 안

function cap(captureId: string, total: number, extra: Partial<CaptureRow> = {}): CaptureRow {
  return {
    captureId,
    sourceType: captureId.startsWith('lab-') ? 'live' : 'imported',
    sensorKey: captureId.startsWith('lab-') ? 'lab-*' : null,
    state: captureId.startsWith('lab-') ? 'active' : 'imported',
    latestJob: null,
    lastScoredAt: OLD,
    lastActivityAt: null,
    total,
    high: 0,
    alerted: 0,
    failedJobs: 0,
    ...extra,
  };
}

const SENSOR: SensorRow = {
  sensorKey: 'lab-*',
  label: '실습망 센서',
  health: 'ok',
  latestJob: null,
  activeCaptureId: 'lab-20261122',
  lastScoredAt: RECENT,
  lastActivityAt: RECENT,
  total: 0,
  high: 0,
  alerted: 0,
  failedJobs: 0,
  captureCount: 2,
};

function overview(captures: CaptureRow[], sensors: SensorRow[] = []): DashboardOverviewResponse {
  return {
    anchor: ANCHOR,
    anchorMode: 'latest-data',
    snapshot: true,
    period: '24h',
    periodStart: H24_START,
    periodEnd: ANCHOR,
    timeZone: 'Asia/Seoul',
    staleAfterSeconds: 900,
    downAfterSeconds: 3600,
    trend: { bucket: '1h', buckets: [], unbucketed: { noDetectedAt: 0, afterAnchor: 0 } },
    sensors,
    captures,
    alerting: {
      latestDeliveryMode: null,
      latestDeliveryStatus: null,
      latestDryRun: false,
      latestCreatedAt: null,
      latestDeliveredAt: null,
      latestCaptureId: null,
      summariesInPeriod: 0,
    },
    maskedView: false,
  };
}

function src(captureId: string, lastDetectedAt: string | null | undefined): QueueSource {
  const s: QueueSource = { captureId, sourceType: captureId.startsWith('lab-') ? 'live' : 'imported', latestJobId: 1 };
  return lastDetectedAt === undefined ? s : { ...s, lastDetectedAt };
}

function ctx(sources: QueueSource[], period: Partial<AllPeriodContext> = {}): AllPeriodContext {
  return { period: '24h', periodStart: H24_START, periodEnd: ANCHOR, anchor: ANCHOR, snapshot: true, sources, ...period };
}

function renderList(ov: DashboardOverviewResponse, allPeriod: AllPeriodContext | null, periodQuery = 'period=24h') {
  return render(
    <MemoryRouter>
      <SourceStatusList overview={ov} shortNames={new Map()} periodQuery={periodQuery} allPeriod={allPeriod} />
    </MemoryRouter>,
  );
}

const hrefParams = (a: Element) => new URLSearchParams((a.getAttribute('href') ?? '').split('?')[1] ?? '');
const allPeriodLink = (captureId: string) => document.querySelector(`[data-all-period="${captureId}"]`);

describe('T43 현황판 가져온 데이터 줄: "전체 기간" 링크', () => {
  it('기간 24시간·기간 안 0건·마지막 탐지 기간 밖이면 period=all&captureId 링크가 줄 링크와 나란히 있다', async () => {
    const { container } = renderList(overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', OLD)]));
    const link = allPeriodLink('cic17-fri') as HTMLAnchorElement;
    expect(link).not.toBeNull();
    expect(link.tagName).toBe('A');
    expect(link).toHaveTextContent('전체 기간');
    expect(link.getAttribute('href')).toBe('/incidents?period=all&captureId=cic17-fri');
    expect(link.getAttribute('aria-label')).toMatch(/전체 기간 보기 \(선택한 기간에는 인시던트 0건 · 마지막 탐지 11-12 11:28\(기준 시각 10일 전\)\)$/);
    expect(link).toHaveAttribute('title', '선택한 기간에는 인시던트 0건 · 마지막 탐지 11-12 11:28(기준 시각 10일 전)');
    // 원래 줄 링크는 기간을 유지하고 수 0을 그대로 보인다
    const row = container.querySelector('[data-capture="cic17-fri"]') as HTMLAnchorElement;
    expect(hrefParams(row).get('period')).toBe('24h');
    expect(hrefParams(row).get('captureId')).toBe('cic17-fri');
    expect(within(row).getByTitle('기간 안 인시던트')).toHaveTextContent(/^0$/);
    // 링크 안에 링크가 없고 두 링크는 형제다
    expect(container.querySelectorAll('a a')).toHaveLength(0);
    expect(row.parentElement).toBe(link.parentElement);
    // 키보드로 두 링크에 차례로 닿는다
    const user = userEvent.setup();
    await user.tab();
    expect(row).toHaveFocus();
    await user.tab();
    expect(link).toHaveFocus();
  });

  it('기간 안에 1건 이상, 기간 전체, 마지막 탐지 없음, 큐 응답에 그 캡처 없음, 큐 응답 자체가 없으면 새 링크가 없다', () => {
    const cases: [string, DashboardOverviewResponse, AllPeriodContext | null][] = [
      ['기간 안 1건', overview([cap('cic17-fri', 1)]), ctx([src('cic17-fri', OLD)])],
      ['기간 전체', overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', OLD)], { period: 'all', periodStart: null, periodEnd: null })],
      ['마지막 탐지 null', overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', null)])],
      ['마지막 탐지 칸 없음', overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', undefined)])],
      ['큐 응답에 그 캡처 없음', overview([cap('cic17-fri', 0)]), ctx([src('cic17-wed', OLD)])],
      ['큐 응답 없음', overview([cap('cic17-fri', 0)]), null],
      ['마지막 탐지가 기간 안(기간 안 0건이어도)', overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', RECENT)])],
    ];
    for (const [name, ov, c] of cases) {
      const { container, unmount } = renderList(ov, c);
      expect(allPeriodLink('cic17-fri'), name).toBeNull();
      expect(container.querySelector('[data-capture="cic17-fri"]'), name).not.toBeNull();
      unmount();
    }
  });

  it('지정 기간(custom)에서도 같은 규칙: 경계 밖이면 링크, 경계 안이면 없음', () => {
    const custom = { period: 'custom', periodStart: '2026-11-20T00:00:00Z', periodEnd: '2026-11-21T00:00:00Z' };
    const q = 'period=custom&start=2026-11-20T00%3A00%3A00Z&end=2026-11-21T00%3A00%3A00Z';
    const { container, unmount } = renderList(overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', OLD)], custom), q);
    expect(allPeriodLink('cic17-fri')?.getAttribute('href')).toBe('/incidents?period=all&captureId=cic17-fri');
    expect(hrefParams(container.querySelector('[data-capture="cic17-fri"]') as Element).get('period')).toBe('custom');
    unmount();
    // 기간 끝 뒤에 탐지된 것도 기간 밖이다
    renderList(overview([cap('cic17-fri', 0)]), ctx([src('cic17-fri', '2026-11-22T00:00:00Z')], custom), q);
    expect(allPeriodLink('cic17-fri')).not.toBeNull();
  });

  it('조건이 참이 아닌 줄은 지금과 똑같다(링크 하나, 같은 주소)', () => {
    const { container } = renderList(overview([cap('cic17-fri', 0), cap('cic17-wed', 3)]), ctx([src('cic17-fri', OLD), src('cic17-wed', OLD)]));
    const items = container.querySelectorAll('ul[aria-label="가져온 데이터"] > li');
    expect(items).toHaveLength(2);
    const wed = [...items].find((li) => li.querySelector('[data-capture="cic17-wed"]')) as Element;
    expect(wed.querySelectorAll('a')).toHaveLength(1);
    expect(wed.querySelector('a')?.getAttribute('href')).toBe('/incidents?period=24h&captureId=cic17-wed');
  });
});

describe('T43 센서 아래 캡처 표지와 센서 줄', () => {
  const captures = [cap('lab-20261122', 2), cap('lab-20261119', 0, { state: 'ended' })];

  it('지난 날짜 캡처 표지에 아이콘 링크가 붙고(읽기 글·툴팁에 "전체 기간"), 센서 줄에는 새 링크가 없다', () => {
    const { container } = renderList(overview(captures, [SENSOR]), ctx([src('lab-20261119', OLD), src('lab-20261122', RECENT)]));
    const link = allPeriodLink('lab-20261119') as HTMLAnchorElement;
    expect(link).not.toBeNull();
    expect(link.getAttribute('href')).toBe('/incidents?period=all&captureId=lab-20261119');
    expect(link.getAttribute('aria-label')).toContain('전체 기간 보기');
    expect(link.getAttribute('title')).toMatch(/^전체 기간 보기: 선택한 기간에는 인시던트 0건 · 마지막 탐지 /);
    // 표지 원래 링크는 기간 유지
    const group = container.querySelector('[data-capture-chip-group="lab-20261119"]') as Element;
    const chip = group.querySelector('[data-capture-chip]') as Element;
    expect(hrefParams(chip).get('period')).toBe('24h');
    expect(container.querySelectorAll('a a')).toHaveLength(0);
    // 기간 안에 있는 표지는 그대로
    expect(allPeriodLink('lab-20261122')).toBeNull();
    expect(container.querySelector('[data-capture-chip-group="lab-20261122"]')).toBeNull();
    // 센서 줄: 링크 하나(source=live, 기간 유지), "전체 기간" 링크 없음
    const sensor = container.querySelector('[data-sensor="lab-*"]') as Element;
    const sensorLink = screen.getByRole('link', { name: '실습망 센서 인시던트 목록' });
    expect(hrefParams(sensorLink).get('source')).toBe('live');
    expect(hrefParams(sensorLink).get('period')).toBe('24h');
    const sensorLinks = [...sensor.querySelectorAll('a')].filter((a) => !a.closest('[data-capture-chip-group], [data-capture-chip]'));
    expect(sensorLinks).toEqual([sensorLink]);
    expect(sensor.querySelectorAll('[data-all-period]')).toHaveLength(1);
  });

  it('센서 캡처가 모두 기간 안 0건·마지막 탐지 기간 밖이어도 센서 줄에는 새 링크가 없다', () => {
    const { container } = renderList(
      overview([cap('lab-20261122', 0), cap('lab-20261119', 0, { state: 'ended' })], [SENSOR]),
      ctx([src('lab-20261119', OLD), src('lab-20261122', OLD)]),
    );
    expect(container.querySelectorAll('[data-all-period]')).toHaveLength(2);
    const sensorLink = screen.getByRole('link', { name: '실습망 센서 인시던트 목록' });
    expect(sensorLink.querySelector('[data-all-period]')).toBeNull();
    expect(sensorLink.textContent).not.toContain('전체 기간');
  });

  it('표지도 같은 경우에는 새 링크가 없다(마지막 탐지 없음, 큐 응답에 없음, 기간 전체)', () => {
    for (const c of [
      ctx([src('lab-20261119', null)]),
      ctx([]),
      ctx([src('lab-20261119', OLD)], { period: 'all', periodStart: null, periodEnd: null }),
    ]) {
      const { container, unmount } = renderList(overview(captures, [SENSOR]), c);
      expect(container.querySelectorAll('[data-all-period]')).toHaveLength(0);
      unmount();
    }
  });
});

describe('T43 allPeriodReason', () => {
  it('기간 경계 정각(시작 이하)은 기간 밖이다', () => {
    expect(allPeriodReason(cap('cic17-fri', 0), ctx([src('cic17-fri', H24_START)]))).not.toBeNull();
    expect(allPeriodReason(cap('cic17-fri', 0), ctx([src('cic17-fri', ANCHOR)]))).toBeNull();
  });
});

/* ───────────────────────── 0건 안내 ───────────────────────── */

function emptyQueue(extra: Partial<UnifiedQueueResponse> = {}): UnifiedQueueResponse {
  return {
    items: [],
    total: 0,
    page: 1,
    size: 50,
    pageCount: 1,
    summary: { total: 0, high: 0, medium: 0, low: 0, closed: 0, reviewPending: 0, alerted: 0, overdue: 0 } as unknown as UnifiedQueueResponse['summary'],
    anchor: ANCHOR,
    anchorMode: 'latest-data',
    snapshot: true,
    period: '24h',
    periodStart: H24_START,
    periodEnd: ANCHOR,
    latestDetectedAt: null,
    newestOutsidePeriod: OLD,
    outsidePeriod: 241,
    sources: [src('cic17-fri', OLD), src('cic17-wed', '2026-11-12T03:10:00Z'), src('lab-20261119', '2026-11-19T03:00:00Z')],
    maskedView: false,
    availableModels: [],
    availableRoles: [],
    ...extra,
  };
}

const count = (text: string, part: string) => text.split(part).length - 1;

describe('T43 0건 안내: 같은 사실은 한 번', () => {
  it('고른 캡처의 마지막 탐지 = 기간 밖 가장 최근 탐지면 한 문단(이름·건수·시각·상대 시각이 한 번씩)', () => {
    const { container } = render(<EmptyPeriodText queue={emptyQueue()} sourceValue="cap:cic17-fri" />);
    expect(screen.queryByTestId('source-outside')).toBeNull();
    expect(container.querySelectorAll('p')).toHaveLength(1);
    const text = container.textContent ?? '';
    expect(text).toBe(
      '이 기간에 CIC-IDS2017 금요일에서 탐지된 인시던트가 없습니다. 선택한 기간 밖에 241건이 있고 마지막 탐지는 2026-11-12 11:28:09(기준 시각 10일 전)입니다.',
    );
    for (const part of ['CIC-IDS2017 금요일', '241건', '2026-11-12 11:28:09', '기준 시각 10일 전']) {
      expect(count(text, part), part).toBe(1);
    }
  });

  it('표기만 다른 같은 순간(초 아래 자릿수, 오프셋 표기)도 한 문단', () => {
    for (const newest of ['2026-11-12T02:28:09.731Z', '2026-11-12T11:28:09+09:00', '2026-11-12T11:28:09.000123+09:00']) {
      const { container, unmount } = render(<EmptyPeriodText queue={emptyQueue({ newestOutsidePeriod: newest })} sourceValue="cap:cic17-fri" />);
      expect(screen.queryByTestId('source-outside'), newest).toBeNull();
      expect(container.querySelectorAll('p'), newest).toHaveLength(1);
      expect(container.textContent).toContain('2026-11-12 11:28:09');
      unmount();
    }
    expect(sameInstant('2026-11-12T02:28:09Z', '2026-11-12T02:28:10Z')).toBe(false);
    expect(sameInstant('2026-11-12T02:28:09Z', null)).toBe(false);
  });

  it('두 시각이 다르면 두 문단(지금 조건의 값과 수집원의 값을 섞지 않는다)', () => {
    const { container } = render(
      <EmptyPeriodText queue={emptyQueue({ newestOutsidePeriod: '2026-11-11T00:00:00Z', outsidePeriod: 12 })} sourceValue="cap:cic17-fri" />,
    );
    expect(container.querySelectorAll('p')).toHaveLength(2);
    expect(container.querySelector('p')).toHaveTextContent(
      '이 기간에 탐지된 인시던트가 없습니다. 선택한 기간 밖 인시던트 12건 · 가장 최근 탐지: 2026-11-11 09:00:00',
    );
    expect(screen.getByTestId('source-outside')).toHaveTextContent(
      '고른 수집원 CIC-IDS2017 금요일의 마지막 탐지 11-12 11:28(기준 시각 10일 전)이 선택한 기간 밖입니다.',
    );
  });

  it('다른 거르기가 걸려 있어도 두 시각이 같으면 한 문단(건수는 지금 조건의 값)', () => {
    const { container } = render(<EmptyPeriodText queue={emptyQueue({ outsidePeriod: 7 })} sourceValue="cap:cic17-fri" />);
    expect(screen.queryByTestId('source-outside')).toBeNull();
    expect(container.textContent).toContain('선택한 기간 밖에 7건이 있고 마지막 탐지는 2026-11-12 11:28:09(기준 시각 10일 전)입니다.');
  });

  it('수집원 종류를 고르면 두 문단(여러 캡처가 섞인다)', () => {
    const { container } = render(<EmptyPeriodText queue={emptyQueue({ sources: [src('cic17-fri', OLD)] })} sourceValue="src:imported" />);
    expect(container.querySelectorAll('p')).toHaveLength(2);
    expect(screen.getByTestId('source-outside')).toHaveTextContent('고른 수집원 가져온 데이터의 마지막 탐지');
  });

  it('수집원을 고르지 않으면 지금 그대로(한 문단, 수집원 문단 없음)', () => {
    const { container } = render(<EmptyPeriodText queue={emptyQueue()} sourceValue="" />);
    expect(container.querySelectorAll('p')).toHaveLength(1);
    expect(container.textContent).toBe('이 기간에 탐지된 인시던트가 없습니다. 선택한 기간 밖 인시던트 241건 · 가장 최근 탐지: 2026-11-12 11:28:09');
  });

  it('지정 기간은 기간 밖 가장 최근 탐지가 없으므로(null) 두 문단을 그대로 둔다', () => {
    const { container } = render(
      <EmptyPeriodText
        queue={emptyQueue({ period: 'custom', periodStart: '2026-11-20T00:00:00Z', periodEnd: '2026-11-21T00:00:00Z', newestOutsidePeriod: null })}
        sourceValue="cap:cic17-fri"
      />,
    );
    expect(container.querySelectorAll('p')).toHaveLength(2);
    expect(container.querySelector('p')).not.toHaveTextContent('가장 최근 탐지');
  });
});
