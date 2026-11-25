import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { DetailHeader } from '../components/incident/DetailHeader';
import { COPY_FEEDBACK_MS } from '../components/incident/InvestigationLinks';
import { EvidenceSection } from '../components/incident/EvidenceSection';
import { AllFactsTable, FactEvidence } from '../components/incident/FactEvidence';
import { peerStrokeWidth } from '../components/incident/PeerTopologySvg';
import { SummaryTab } from '../components/incident/SummaryTab';
import { ToastProvider } from '../components/ToastContext';
import { NEW_INCIDENT_POLL_MS } from '../pages/IncidentQueuePage';
import type { EvidenceView, FactItem, IncidentDetailView, IncidentQueueItem, UnifiedQueueItem } from '../types/api';
import { describeFact, extractBaselineComparison, formatTimes } from '../utils/factLabels';
import { csvCell, incidentMarkdown, QUEUE_CSV_HEADERS, queueCsv, queueCsvFileName } from '../utils/incidentExport';
import { ipScope, isIpText } from '../utils/ipScope';
import { baseDetail, DEFAULT_META, queueItem } from './detailFixture';
import { fakeNewCount, fakeQueue, unified, type FakeQueueOptions } from './fakeQueueServer';

/**
 * T44 상세·큐 분석 동선과 시각화: 탐지 모델 피벗, 상대 IP 대역 표지·복사, 주요 통신 구조(순수 SVG),
 * 평소 대비 배수 강조, 마크다운 요약 복사, 큐 CSV 내보내기. 백엔드 응답은 그대로이고 화면만 바뀐다.
 */

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  delete (URL as { createObjectURL?: unknown }).createObjectURL;
  delete (URL as { revokeObjectURL?: unknown }).revokeObjectURL;
});

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc">{loc.pathname + loc.search}</div>;
}

/** 인라인 style과 옛 용어가 없어야 한다(엄격한 CSP, 용어 회귀) */
function expectNoInlineStyle(root: HTMLElement) {
  expect(root.querySelector('[style]')).toBeNull();
  expect(root.textContent).not.toContain('주 탐지 모델');
}

/* ───────────────────────── 1. 탐지 모델 피벗 ───────────────────────── */

function renderWithRoutes(ui: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={['/detail']}>
      <ToastProvider>
        <Routes>
          <Route path="/detail" element={ui} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('T44 탐지 모델 피벗', () => {
  it('상세 헤더: 탐지 모델 이름이 전체 기간 pickedBy 목록으로 가고, 교차 탐지 배지는 그대로다', async () => {
    const user = userEvent.setup();
    const { container } = renderWithRoutes(<DetailHeader detail={baseDetail()} meta={DEFAULT_META} incidentNo={7} />);
    const link = screen.getByRole('link', { name: '탐지 모델 통신 관계 이상 인시던트 보기' });
    expect(link).toHaveAttribute('href', '/incidents?period=all&pickedBy=tgn_recon');
    expect(link).toHaveAttribute('title', '탐지 모델 통신 관계 이상 인시던트 보기');
    expect(within(link).getByText('통신 관계 이상')).toBeInTheDocument();
    // 요약 배지는 링크 밖에 그대로(헤더 줄바꿈 방지, 링크 안에 다른 링크·버튼 없음)
    expect(screen.getByText('교차 탐지 +1').closest('a')).toBeNull();
    expect(link.querySelector('a, button')).toBeNull();
    expectNoInlineStyle(container);

    await user.click(link);
    expect(screen.getByTestId('loc')).toHaveTextContent('/incidents?period=all&pickedBy=tgn_recon');
  });

  it('요약 탭: 모델별 탐지 윈도우의 모델마다(교차 탐지 모델 포함) 같은 링크가 붙는다', () => {
    const detail = baseDetail();
    detail.modelScores = [
      ...detail.modelScores,
      { jobId: 42, incidentId: detail.incident.incidentId, zeekadModel: 'tail_rarity_v2', candidateWindows: 2, windows: 9, windowRatioLabel: '2 / 9' },
    ];
    renderWithRoutes(<SummaryTab detail={detail} />);
    expect(screen.getByRole('link', { name: '탐지 모델 통신 관계 이상 인시던트 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&pickedBy=tgn_recon',
    );
    expect(screen.getByRole('link', { name: '탐지 모델 기준선 이탈 인시던트 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&pickedBy=tail_rarity_v2',
    );
  });

  it('사전에 없는 식별자도 값을 인코딩해 잇고, 모델이 없으면 링크를 만들지 않는다', () => {
    const odd = baseDetail();
    odd.incident = queueItem({ zeekadPickedBy: 'new model/1&x', zeekadAlsoFlaggedBy: [] });
    const first = renderWithRoutes(<DetailHeader detail={odd} meta={DEFAULT_META} />);
    expect(screen.getByRole('link', { name: '탐지 모델 new model/1&x 인시던트 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&pickedBy=new%20model%2F1%26x',
    );
    first.unmount();

    const none = baseDetail();
    none.incident = queueItem({ zeekadPickedBy: null, zeekadAlsoFlaggedBy: [] });
    renderWithRoutes(<DetailHeader detail={none} meta={DEFAULT_META} />);
    // T45: 헤더에 호스트 링크("호스트 … 인시던트 보기")가 생겨 탐지 모델 링크만 본다
    expect(screen.queryByRole('link', { name: /^탐지 모델 .*인시던트 보기$/ })).toBeNull();
    expect(screen.getAllByRole('link', { name: /인시던트 보기$/ }).map((a) => a.getAttribute('aria-label'))).toEqual([
      '호스트 192.168.10.5 인시던트 보기',
    ]);
  });
});

/* ───────────────────────── 2. 상대 IP 대역 표지·복사 ───────────────────────── */

describe('T44 상대 IP 대역 판별', () => {
  it('온전한 주소와 가려진 주소에 같은 경계를 쓴다', () => {
    for (const ip of ['10.0.0.1', '10.255.*.*', '172.16.0.1', '172.31.*.*', '192.168.0.1', '192.168.*.*']) {
      expect(ipScope(ip), ip).toBe('private');
    }
    for (const ip of ['172.15.*.*', '172.32.0.1', '192.167.1.1', '100.63.*.*', '100.128.0.1', '198.17.0.1', '198.20.0.1', '169.253.1.1', '8.8.8.8', '223.255.*.*']) {
      expect(ipScope(ip), ip).toBe('external');
    }
  });

  it('특수 대역과 주소가 아닌 글에는 표지를 달지 않는다', () => {
    const special = ['0.1.*.*', '127.0.0.1', '169.254.*.*', '100.64.*.*', '100.127.0.1', '198.18.*.*', '198.19.0.1', '224.0.*.*', '255.255.255.255'];
    const notIpv4 = ['::1', 'fe80::1', '-', '', '1.2.3.256', '300.2.*.*', '1.2.*.4', '1.*.*.*', '1.2.3.4:80', '01.2.3.4', '1.2.3', 'X1'];
    for (const ip of [...special, ...notIpv4]) expect(ipScope(ip), ip).toBeNull();
  });

  it('복사 버튼을 붙일 주소: IPv4·가려진 IPv4·IPv6만', () => {
    for (const ip of ['192.168.10.5', '172.16.*.*', '127.0.0.1', '::1', '2001:db8::1']) expect(isIpText(ip), ip).toBe(true);
    for (const v of ['-', '', 'X1', '<b>x</b>', '1.2.3.4:80', 'gggg::1', null, undefined, 5]) expect(isIpText(v), String(v)).toBe(false);
  });
});

const peerEvidence = (over: Partial<EvidenceView> = {}): EvidenceView => ({ ...baseDetail().evidence, ...over });

describe('T44 상대 IP 표지·복사 버튼', () => {
  it('요약 탭 주요 상대 IP: 사설 표지와 복사 버튼', async () => {
    const user = userEvent.setup();
    renderWithRoutes(<SummaryTab detail={baseDetail()} />);
    const card = screen.getByText('주요 상대 IP').parentElement as HTMLElement;
    expect(within(card).getByText('사설')).toHaveAttribute('title', '사설 네트워크 대역');
    // 알림 영역은 누르기 전부터 빈 채로 있다(누를 때 새로 끼우지 않는다)
    const live = card.querySelector('[data-copy-result]') as HTMLElement;
    expect(live).toHaveAttribute('aria-live', 'polite');
    expect(live.textContent).toBe('');
    await user.click(within(card).getByRole('button', { name: '상대 IP 172.16.0.1 복사' }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe('172.16.0.1'));
    expect(card.querySelector('[data-copy-result]')).toBe(live);
    // 안내 글은 클립보드 쓰기가 끝난 뒤의 상태 갱신으로 나온다. 클립보드 값과 따로 기다린다(T47)
    await waitFor(() => expect(live).toHaveTextContent('주소를 복사했습니다.'));
  });

  it('알림 영역(.sr-only)은 기준 상자(relative) 안에 둔다: 가로 스크롤 표에서 페이지를 넓히지 않게', () => {
    render(<EvidenceSection evidence={baseDetail().evidence} />);
    const regions = Array.from(document.querySelectorAll('[data-copy-result]'));
    expect(regions.length).toBeGreaterThan(0);
    for (const region of regions) {
      expect(region).toHaveClass('sr-only');
      // jsdom은 배치를 계산하지 않아 클래스만 본다. 실제 넘침은 handoff/T44/tools/layout-check.js가 잰다.
      expect(region.parentElement).toHaveClass('relative');
      expect(region.parentElement).toHaveAttribute('data-ip-actions');
    }
  });

  it('복사 알림은 잠시 뒤 처음 모양으로 돌아가고, 주요 세션 칸 글자는 누른 뒤에도 되돌아온다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<EvidenceSection evidence={baseDetail().evidence} />);
    const table = screen.getByText('주요 세션 (최대 10건)').parentElement as HTMLElement;
    const cell = within(within(table).getAllByRole('row')[1]).getAllByRole('cell')[1];
    expect(cell.textContent).toBe('192.168.10.5:52974');
    await user.click(within(cell).getByRole('button', { name: '출발지 IP 192.168.10.5 복사' }));
    await waitFor(() => expect(cell.querySelector('[data-copy-result]')).toHaveTextContent('주소를 복사했습니다.'));
    expect(cell.querySelector('svg')?.getAttribute('class')).toContain('lucide-check');
    await act(async () => {
      vi.advanceTimersByTime(COPY_FEEDBACK_MS);
    });
    expect(cell.textContent).toBe('192.168.10.5:52974');
    expect(cell.querySelector('svg')?.getAttribute('class')).toContain('lucide-copy');
  });

  it('요약 탭: 상대 IP가 없으면 표지·버튼 줄을 만들지 않는다', () => {
    const detail = baseDetail();
    detail.evidence = peerEvidence({ topPeers: [] });
    renderWithRoutes(<SummaryTab detail={detail} />);
    const card = screen.getByText('주요 상대 IP').parentElement as HTMLElement;
    expect(within(card).queryByRole('button')).toBeNull();
    expect(card.children).toHaveLength(2);
  });

  it('증적 탭 많이 통신한 상대 IP 표: 사설·외부 표지, 특수 대역은 표지 없이 복사만, 가려진 주소는 가려진 값을 복사', async () => {
    const user = userEvent.setup();
    render(
      <EvidenceSection
        evidence={peerEvidence({
          topPeers: [
            { ip: '172.16.*.*', connections: 9 },
            { ip: '8.8.8.8', connections: 5 },
            { ip: '169.254.1.1', connections: 2 },
            { ip: 'X1', connections: 1 },
          ],
          representativeConnections: [],
        })}
      />,
    );
    const table = screen.getByText('많이 통신한 상대 IP').parentElement as HTMLElement;
    const cell = (ip: string) => within(table).getByText(ip, { selector: 'td' });
    expect(within(cell('172.16.*.*')).getByText('사설')).toBeInTheDocument();
    const external = within(cell('8.8.8.8')).getByText('외부');
    expect(external).toHaveAttribute('title', '사설·루프백·링크 로컬 대역 밖 외부 주소');
    expect(table.textContent).not.toContain('공인');
    expect(within(cell('169.254.1.1')).queryByText(/사설|외부/)).toBeNull();
    expect(within(cell('169.254.1.1')).getByRole('button', { name: '상대 IP 169.254.1.1 복사' })).toBeInTheDocument();
    expect(within(cell('X1')).queryByRole('button')).toBeNull();

    await user.click(within(table).getByRole('button', { name: '상대 IP 172.16.*.* 복사' }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe('172.16.*.*'));
  });

  it('주요 세션 표: 칸 글자는 그대로이고 아이콘만 있는 복사 버튼(대역은 툴팁)', async () => {
    const user = userEvent.setup();
    render(<EvidenceSection evidence={baseDetail().evidence} />);
    const table = screen.getByText('주요 세션 (최대 10건)').parentElement as HTMLElement;
    const rows = within(table).getAllByRole('row');
    const cells = within(rows[1]).getAllByRole('cell');
    expect(cells.map((c) => c.textContent).slice(1, 3)).toEqual(['192.168.10.5:52974', '172.16.0.1:80']);
    const src = within(cells[1]).getByRole('button', { name: '출발지 IP 192.168.10.5 복사' });
    const dst = within(cells[2]).getByRole('button', { name: '목적지 IP 172.16.0.1 복사' });
    expect(src.textContent).toBe('');
    expect(src).toHaveAttribute('title', '출발지 IP 192.168.10.5 복사 · 사설 네트워크 대역');
    expect(dst).toHaveAttribute('title', '목적지 IP 172.16.0.1 복사 · 사설 네트워크 대역');
    expect(within(table).queryByText(/^(사설|외부)$/)).toBeNull();
    // 주소가 아닌 값(둘째 행 출발지)에는 버튼이 없다
    const cells2 = within(rows[2]).getAllByRole('cell');
    expect(within(cells2[1]).queryByRole('button')).toBeNull();
    expect(within(cells2[2]).getByRole('button', { name: '목적지 IP 172.16.0.2 복사' })).toBeInTheDocument();

    await user.click(dst);
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe('172.16.0.1'));
  });

  it('복사에 실패하면 실패를 알린다', async () => {
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    renderWithRoutes(<SummaryTab detail={baseDetail()} />);
    await user.click(screen.getByRole('button', { name: '상대 IP 172.16.0.1 복사' }));
    await waitFor(() => expect(document.querySelector('[data-copy-result]')).toHaveTextContent('주소를 복사하지 못했습니다.'));
  });
});

/* ───────────────────────── 3. 주요 통신 구조 ───────────────────────── */

const FIVE_PLUS = [
  { ip: '172.16.0.1', connections: 100 },
  { ip: '8.8.8.8', connections: 50 },
  { ip: '10.0.*.*', connections: 0 },
  { ip: '127.0.0.1', connections: 25 },
  { ip: '203.0.113.9', connections: 75 },
  { ip: '198.51.100.7', connections: 60 },
];

function topology(incident: IncidentQueueItem | undefined, evidence: EvidenceView) {
  const utils = render(<EvidenceSection evidence={evidence} incident={incident} />);
  const panel = screen.queryByRole('region', { name: '주요 통신 구조' });
  const lines = () => Array.from(panel?.querySelectorAll('line[data-peer-line]') ?? []);
  return { ...utils, panel, lines };
}

describe('T44 주요 통신 구조', () => {
  it('출발지 인시던트: 대상 호스트 → 상대 IP 화살표, 상위 5개, 세션 수에 비례한 선 굵기, 화면 판독기 표', () => {
    const { container, panel, lines } = topology(
      queueItem(),
      peerEvidence({ topPeers: FIVE_PLUS, representativeConnections: [] }),
    );
    expect(panel).not.toBeNull();
    const svg = panel!.querySelector('svg[aria-hidden="true"]') as SVGElement;
    expect(svg.querySelectorAll('[data-topology-peer]')).toHaveLength(5);
    expect(svg.textContent).toContain('192.168.10.5');
    expect(svg.textContent).toContain('ws-01.lab');
    expect(svg.textContent).toContain('사설 · 세션 100건');
    expect(svg.textContent).toContain('외부 · 세션 50건');
    // 특수 대역은 표지 없이 세션 수만
    expect(svg.querySelectorAll('[data-topology-peer]')[3].querySelector('text:last-of-type title')?.textContent).toBe('세션 25건');
    expect(svg.textContent).not.toContain('198.51.100.7');

    const ls = lines();
    expect(ls).toHaveLength(5);
    expect(ls.map((l) => l.getAttribute('stroke-width'))).toEqual(['5.5', '3.5', '1.5', '2.5', '4.5']);
    // 호스트 상자 오른쪽 가장자리에서 시작하고 화살촉이 붙는다
    const marker = svg.querySelector('marker') as SVGElement;
    for (const l of ls) {
      expect(l.getAttribute('x1')).toBe('200');
      expect(Number(l.getAttribute('x2'))).toBeGreaterThan(Number(l.getAttribute('x1')));
      expect(l.getAttribute('marker-end')).toBe(`url(#${marker.id})`);
    }
    expect(marker.id).toMatch(/^[A-Za-z0-9_-]+$/);

    expect(panel).toHaveTextContent('대상 호스트 → 상대 IP');
    const table = within(panel!).getByRole('table', { name: '주요 통신 구조' });
    expect(table.parentElement).toHaveClass('sr-only');
    expect(within(table).getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['대상 호스트', '방향', '상대 IP', '세션 수']);
    const bodyRows = within(table).getAllByRole('row').slice(1);
    expect(bodyRows).toHaveLength(5);
    expect(within(bodyRows[0]).getAllByRole('cell').map((c) => c.textContent)).toEqual([
      '192.168.10.5',
      '대상 호스트 → 상대 IP',
      '172.16.0.1',
      '100',
    ]);
    expectNoInlineStyle(container);
  });

  it('목적지 인시던트: 상대 IP → 대상 호스트 방향', () => {
    const { panel, lines } = topology(
      queueItem({ zeekadRole: 'responder' }),
      peerEvidence({ topPeers: FIVE_PLUS.slice(0, 2), representativeConnections: [] }),
    );
    for (const l of lines()) {
      expect(l.getAttribute('x1')).toBe('439.5');
      expect(Number(l.getAttribute('x2'))).toBeLessThan(Number(l.getAttribute('x1')));
      expect(l.getAttribute('marker-end')).toMatch(/^url\(#/);
    }
    expect(panel).toHaveTextContent('상대 IP → 대상 호스트');
  });

  it('그 밖의 방향 값: 화살표 없는 선', () => {
    const { panel, lines } = topology(
      queueItem({ zeekadRole: 'both' }),
      peerEvidence({ topPeers: FIVE_PLUS.slice(0, 2), representativeConnections: [] }),
    );
    for (const l of lines()) {
      expect(l.hasAttribute('marker-end')).toBe(false);
      expect(l.getAttribute('x1')).toBe('200');
      expect(l.getAttribute('x2')).toBe('439.5');
    }
    expect(panel).toHaveTextContent('방향 정보 없음');
  });

  it('세션 수가 숫자가 아니거나 음수면 0으로 보고, 최대가 0이면 기본 굵기 2', () => {
    expect(peerStrokeWidth(10, 10)).toBe(5.5);
    expect(peerStrokeWidth(0, 10)).toBe(1.5);
    expect(peerStrokeWidth(5, 10)).toBe(3.5);
    expect(peerStrokeWidth(0, 0)).toBe(2);
    const { lines, panel } = topology(
      queueItem(),
      peerEvidence({
        topPeers: [
          { ip: '10.0.0.1', connections: -5 },
          { ip: '10.0.0.2', connections: 'abc' },
          { ip: '10.0.0.3' },
        ],
        representativeConnections: [],
      }),
    );
    expect(lines().map((l) => l.getAttribute('stroke-width'))).toEqual(['2', '2', '2']);
    expect(panel!.querySelector('svg')!.textContent).toContain('세션 0건');
  });

  it('주요 포트는 상위 3개만 보조 배지로', () => {
    const { panel } = topology(
      queueItem(),
      peerEvidence({
        topPorts: [
          { port: 80, transport: 'tcp', connections: 1200 },
          { port: 443, transport: 'tcp', connections: 30 },
          { port: 53, transport: 'udp', connections: 20 },
          { port: 22, transport: 'tcp', connections: 10 },
        ],
        representativeConnections: [],
      }),
    );
    const ports = panel!.querySelector('[data-topology-ports]') as HTMLElement;
    expect(ports).toHaveTextContent('80/tcp');
    expect(ports).toHaveTextContent('세션 1,200건');
    expect(ports).toHaveTextContent('53/udp');
    expect(ports.textContent).not.toContain('22/tcp');
  });

  it('포트 정보가 없으면 배지 줄을 만들지 않는다', () => {
    const { panel } = topology(queueItem(), peerEvidence({ topPorts: [], representativeConnections: [] }));
    expect(panel).not.toBeNull();
    expect(panel!.querySelector('[data-topology-ports]')).toBeNull();
  });

  it('호스트 이름이 없으면 "대상 호스트"라고 적는다', () => {
    const { panel } = topology(queueItem({ hostName: [] }), peerEvidence({ representativeConnections: [] }));
    expect(panel!.querySelector('[data-topology-host] text:last-of-type title')?.textContent).toBe('대상 호스트');
  });

  it('상대 IP가 없거나, 증적이 없거나, 인시던트를 넘기지 않으면 그리지 않는다', () => {
    const empty = topology(queueItem(), peerEvidence({ topPeers: [], representativeConnections: [] }));
    expect(empty.panel).toBeNull();
    empty.unmount();
    const noIp = topology(queueItem(), peerEvidence({ topPeers: [{ connections: 3 }, { ip: 7 }, { ip: ' ' }], representativeConnections: [] }));
    expect(noIp.panel).toBeNull();
    noIp.unmount();
    const fallback = topology(queueItem(), peerEvidence({ available: false, statusMessage: '증적 요약이 없습니다.' }));
    expect(fallback.panel).toBeNull();
    fallback.unmount();
    const noIncident = topology(undefined, peerEvidence({ representativeConnections: [] }));
    expect(noIncident.panel).toBeNull();
  });
});

/* ───────────────────────── 4. 평소 대비 배수 강조 ───────────────────────── */

const BASE = { incident_max: 12, baseline_p50: 2, baseline_p95: 4, baseline_max: 20 };
const fact = (name: string, valueJson: unknown, id = 'F07'): FactItem => ({ id, name, value: JSON.stringify(valueJson), valueJson });

describe('T44 평소 대비 배수', () => {
  it('평소 p95를 넘은 수치만 뽑는다', () => {
    expect(extractBaselineComparison('baseline.connections_per_window', BASE)).toEqual({
      incidentMax: 12,
      baselineP95: 4,
      baselineMax: 20,
      ratioOverP95: 3,
    });
    expect(extractBaselineComparison('baseline.connections_per_window', { ...BASE, baseline_max: null, baseline_p50: null })).toEqual({
      incidentMax: 12,
      baselineP95: 4,
      baselineMax: null,
      ratioOverP95: 3,
    });
    // p95가 0 이하이거나 이번 인시던트 최대가 p95 이하
    for (const p95 of [0, -1, 12, 14]) {
      expect(extractBaselineComparison('baseline.connections_per_window', { ...BASE, baseline_p95: p95 }), String(p95)).toBeNull();
    }
    // 비율 지표, 사전에 없는 지표, 다른 이름
    expect(extractBaselineComparison('baseline.rejected_connection_ratio', BASE)).toBeNull();
    expect(extractBaselineComparison('baseline.new_metric_per_window', BASE)).toBeNull();
    expect(extractBaselineComparison('connection_count', BASE)).toBeNull();
    // 구조 값이 없거나 모양이 다름
    for (const v of [null, undefined, 12, '12', [], { incident_max: 12, baseline_p95: 4 }, { ...BASE, extra: 1 }, { ...BASE, incident_max: '12' }, { ...BASE, baseline_p95: null }, { ...BASE, baseline_max: 'x' }]) {
      expect(extractBaselineComparison('baseline.connections_per_window', v), JSON.stringify(v)).toBeNull();
    }
  });

  it('배수 글: 소수 한 자리까지, 1배로 보일 값만 둘째 자리까지', () => {
    expect(formatTimes(3)).toBe('3배');
    expect(formatTimes(2.54)).toBe('2.5배');
    expect(formatTimes(1.04)).toBe('1.04배');
    expect(formatTimes(1234.5)).toBe('1,234.5배');
  });

  it('인용 근거: 2배 이상은 주의 색조 표지와 비교 막대(막대 = 이번 인시던트 최대, 눈금 = 평소 p95)', () => {
    const f = fact('baseline.connections_per_window', BASE);
    const { container } = render(<FactEvidence facts={[f]} pseudonyms={{}} />);
    const row = container.querySelector('[data-fact-id="F07"]') as HTMLElement;
    // 기존 값 글은 그대로
    expect(describeFact(f, {}).text).toBe('이번 인시던트 최대 12 / 평소 중앙값 2 / 평소 p95 4 / 평소 최대 20 (평소 p95의 3배)');
    expect(row).toHaveTextContent('(평소 p95의 3배)');
    const badge = within(row).getByText('p95 대비 3배');
    expect(badge.className).toContain('amber');
    const svg = within(row).getByRole('img', { name: '이번 인시던트 최대가 평소 p95의 3배' });
    // 눈금 끝 = max(12, 20, 4) = 20
    expect(svg.querySelector('[data-baseline-bar]')).toHaveAttribute('width', '60');
    expect(svg.querySelector('[data-baseline-p95]')).toHaveAttribute('x1', '20');
    expect(svg.querySelector('[data-baseline-p95]')).toHaveAttribute('x2', '20');
    expectNoInlineStyle(container);
  });

  it('인용 근거: 2배 미만은 중립색, 평소 최대가 없으면 이번 인시던트 최대가 눈금 끝', () => {
    const { container } = render(
      <FactEvidence
        facts={[fact('baseline.dns_queries_per_window', { incident_max: 6, baseline_p50: 1, baseline_p95: 4, baseline_max: null })]}
        pseudonyms={{}}
      />,
    );
    const badge = screen.getByText('p95 대비 1.5배');
    expect(badge.className).not.toContain('amber');
    expect(badge.className).toContain('border-slate-700');
    expect(container.querySelector('[data-baseline-bar]')).toHaveAttribute('width', '100');
    expect(container.querySelector('[data-baseline-p95]')).toHaveAttribute('x1', '66.67');
  });

  it('p95 이하·p95가 0·비율 지표·구조 값 없음이면 표지와 막대를 그리지 않는다', () => {
    const { container } = render(
      <FactEvidence
        facts={[
          fact('baseline.connections_per_window', { ...BASE, incident_max: 4 }, 'F01'),
          fact('baseline.http_errors_per_window', { ...BASE, baseline_p95: 0 }, 'F02'),
          fact('baseline.rejected_connection_ratio', { incident_max: 0.9, baseline_p50: 0, baseline_p95: 0.05, baseline_max: 1 }, 'F03'),
          { id: 'F04', name: 'baseline.connections_per_window', value: JSON.stringify(BASE) },
          fact('connection_count', 155261, 'F05'),
        ]}
        pseudonyms={{}}
      />,
    );
    expect(container.querySelectorAll('[data-fact-id]')).toHaveLength(5);
    expect(container.querySelector('[data-baseline-comparison]')).toBeNull();
    expect(screen.queryByText(/p95 대비/)).toBeNull();
  });

  it('근거 사실 전체 표에는 글만 두고 막대를 그리지 않는다', () => {
    const f = fact('baseline.connections_per_window', BASE);
    const report = { ...baseDetail().report, allFacts: [f], claims: [{ claim: '세션이 많습니다.', facts: [f] }] };
    const { container } = render(<AllFactsTable report={report} />);
    expect(container).toHaveTextContent('(평소 p95의 3배)');
    expect(container.querySelector('[data-baseline-comparison]')).toBeNull();
    expect(container.querySelector('svg')).toBeNull();
  });
});

/* ───────────────────────── 5. 마크다운 요약 복사 ───────────────────────── */

const INTERNAL = ['zeekad_', 'dashboard.', 'evidence.v1', 'zeekad-fusion/3', 'cic17-wed|'];

describe('T44 인시던트 마크다운 요약', () => {
  it('기본 정보·주요 증적·리포트를 한국어 표시 이름으로 싣고 내부 식별자는 넣지 않는다', () => {
    const md = incidentMarkdown(baseDetail(), DEFAULT_META, 7);
    expect(md.split('\n').slice(0, 20)).toEqual([
      '# 인시던트 #7 요약',
      '',
      '## 기본 정보',
      '- 우선순위: High',
      '- 상태: 분석 중',
      '- 판정: -',
      '- 호스트: `192.168.10.5` · `ws-01.lab`',
      '- 방향: 출발지',
      '- 수집원: CIC-IDS2017 수요일',
      '- 탐지 시각: 2026-11-12 11:27:00 KST',
      '- 발생 구간: 2017-07-05 22:45:00 ~ 23:15:00 KST',
      '- 탐지 모델: 통신 관계 이상',
      '',
      '## 주요 증적',
      '- 세션 수: 155,261건',
      '- 송신 바이트: 1.7 GB',
      '- 수신 바이트: 118 MB',
      '- 주요 상대 IP: `172.16.0.1` · 세션 155,111건',
      '- 주요 포트: `80/tcp` · 세션 155,111건',
      '',
    ]);
    expect(md).toContain('## 리포트\n- 구분: AI 작성\n- 검증: 검증 통과\n');
    expect(md).toContain('### 관측 요약\n- 대상 호스트 H가 외부와 대량 세션을 주고받았습니다.');
    // 리포트 글의 꺾쇠는 글자 그대로 보이게 이스케이프한다
    expect(md).toContain('### 확인된 사실\n- 세션이 많습니다. \\<b\\>x\\</b\\>');
    expect(md).toContain('### 관련 ATT&CK 기법 후보\n- T1498 Network Denial of Service');
    expect(md).toContain('### 추가 확인 권고\n- 웹 서버 로그를 확인하세요.');
    expect(md).not.toContain('[템플릿 리포트');
    for (const word of INTERNAL) expect(md, word).not.toContain(word);
    // 이스케이프하지 않은 꺾쇠가 없다
    expect(md).not.toMatch(/(^|[^\\])[<>]/);
  });

  it('번호가 없으면 제목에 번호를 쓰지 않는다', () => {
    expect(incidentMarkdown(baseDetail(), null, null).split('\n')[0]).toBe('# 인시던트 요약');
    // 탐지 시각·우선순위를 모르면 "-"(시간대 표기를 붙이지 않는다)
    expect(incidentMarkdown(baseDetail(), null, null)).toContain('- 우선순위: -\n');
    expect(incidentMarkdown(baseDetail(), null, null)).toContain('- 탐지 시각: -\n');
  });

  it('템플릿 리포트면 대체 안내 줄을 넣는다', () => {
    const detail = baseDetail();
    detail.report = { ...detail.report, reportKind: 'template', verificationPassed: false };
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    expect(md).toContain('## 리포트\n- 구분: 템플릿 리포트\n- [템플릿 리포트 — AI 리포트 대체]\n- 검증: 검증 실패\n');
  });

  it('리포트가 없으면 리포트 절이 없다', () => {
    const detail = baseDetail();
    detail.report = { ...detail.report, present: false };
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    expect(md).not.toContain('## 리포트');
    expect(md.endsWith('- 주요 포트: `80/tcp` · 세션 155,111건\n')).toBe(true);
  });

  it('조회자: 받은 가려진 값을 그대로 싣는다(가린 주소의 *는 코드 표기 안에)', () => {
    const detail = baseDetail();
    const maskedId = 'cic17-wed|192.168.*.*|originator|100';
    detail.incident = queueItem({ incidentId: maskedId, hostIp: '192.168.*.*' });
    detail.evidence = peerEvidence({
      topPeers: [
        { ip: '172.16.*.*', connections: 9 },
        { ip: '203.0.*.*', connections: 4 },
      ],
    });
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    expect(md).toContain('- 호스트: `192.168.*.*` · `ws-01.lab`');
    expect(md).toContain('- 주요 상대 IP: `172.16.*.*` · 세션 9건, `203.0.*.*` · 세션 4건');
    expect(md).not.toContain(maskedId);
    expect(md).not.toContain('192.168.10.5');
    expect(md).not.toContain('172.16.0.1');
  });

  it('리포트 글에 내부 식별자가 인용돼 있어도 싣지 않고, 값이 줄을 나누거나 마크다운 구조를 만들지 못한다', () => {
    const detail = baseDetail();
    detail.incident = queueItem({ hostName: ['evil`\n# 제목 [x](http://e.example)'] });
    detail.report = {
      ...detail.report,
      observationSummary: `근거 zeekad_facts.connection_count 와 dashboard.incident_no, evidence.v1, ${detail.incident.incidentId}, ${detail.incident.bundleId}`,
      claims: [{ claim: '첫 줄\n## 둘째 줄 *강조* [링크](http://e.example)', facts: [] }],
    };
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    for (const word of INTERNAL) expect(md, word).not.toContain(word);
    expect(md).toContain('- 근거 (식별자 생략) 와 (식별자 생략), (식별자 생략), (식별자 생략), (식별자 생략)');
    expect(md).toContain("- 호스트: `192.168.10.5` · `evil' # 제목 [x](http://e.example)`");
    expect(md).toContain('- 첫 줄 ## 둘째 줄 \\*강조\\* \\[링크\\](http://e.example)');
    expect(md.split('\n').filter((line) => line.startsWith('#'))).toEqual([
      '# 인시던트 #7 요약',
      '## 기본 정보',
      '## 주요 증적',
      '## 리포트',
      '### 관측 요약',
      '### 확인된 사실',
      '### 관련 ATT&CK 기법 후보',
      '### 추가 확인 권고',
    ]);
  });

  it('내부 이름처럼 보이는 호스트 이름·도메인은 관측한 그대로 싣는다', () => {
    const detail = baseDetail();
    detail.incident = queueItem({ hostName: ['dashboard.corp.example', 'Dashboard.lab', 'zeekad_host'] });
    detail.report = {
      ...detail.report,
      observationSummary: '호스트 dashboard.corp.example 이 Dashboard.example 과 통신했습니다. 뷰 dashboard.incident_reports. 참고',
      claims: [{ claim: 'dashboard.latest_incident_queue', facts: [] }],
    };
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    expect(md).toContain('- 호스트: `192.168.10.5` · `dashboard.corp.example` · `Dashboard.lab` · `zeekad_host`');
    // 서술 글: 점이 더 이어지는 이름과 대문자로 시작한 글은 그대로, 소문자 `dashboard.<이름>`만 뺀다(문장 끝 마침표 포함)
    expect(md).toContain('- 호스트 dashboard.corp.example 이 Dashboard.example 과 통신했습니다. 뷰 (식별자 생략). 참고');
    expect(md).toContain('### 확인된 사실\n- (식별자 생략)\n');
  });

  it('증적이 없으면 큐의 세션 수만 쓰고 나머지는 "-"', () => {
    const detail = baseDetail();
    detail.evidence = peerEvidence({ available: false });
    const md = incidentMarkdown(detail, DEFAULT_META, 7);
    expect(md).toContain('- 세션 수: 155,261건\n- 송신 바이트: -\n- 수신 바이트: -\n- 주요 상대 IP: -\n- 주요 포트: -\n');
  });

  it('헤더 "요약 복사": 요약을 복사하고 토스트를 띄운다. 실패하면 실패 토스트', async () => {
    const user = userEvent.setup();
    const { container } = renderWithRoutes(<DetailHeader detail={baseDetail()} meta={DEFAULT_META} incidentNo={7} />);
    const button = screen.getByRole('button', { name: '요약 복사' });
    // 버튼 묶음은 좁은 폭에서 줄을 바꾼다(360px 가로 넘침 방지)
    expect(button.parentElement).toHaveClass('flex-wrap', 'max-w-full');
    expect(within(button.parentElement as HTMLElement).getAllByRole('button').map((b) => b.textContent)).toEqual([
      '요약 복사',
      '링크 복사',
      'ID 복사',
    ]);
    await user.click(button);
    expect(await screen.findByText('인시던트 요약을 복사했습니다.')).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(incidentMarkdown(baseDetail(), DEFAULT_META, 7));
    expectNoInlineStyle(container);

    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    await user.click(button);
    expect(await screen.findByText('인시던트 요약을 복사하지 못했습니다.')).toBeInTheDocument();
  });
});

/* ───────────────────────── 6. 큐 CSV 내보내기 ───────────────────────── */

describe('T44 CSV 칸', () => {
  it('앞의 스페이스만 건너뛴 첫 글자가 수식 시작이면 원문 앞에 작은따옴표를 붙인다(탭·줄바꿈은 지우지 않는다)', () => {
    for (const value of ['=1+1', ' =1+1', '   @a', '\t=1', '\n+1', '\r\n=1', '\r', '\t', '-1', '+1', '@SUM(A1)', '-']) {
      expect(csvCell(value), JSON.stringify(value)).toBe(`"'${value}"`);
    }
    // 수식 시작이 아닌 값은 그대로(앞 글자가 스페이스가 아닌 공백류면 그 뒤는 보지 않는다)
    for (const value of ['a=1', '1-2', 'ws-01.lab', '192.168.10.5', ' a', ' =1', '']) {
      expect(csvCell(value), JSON.stringify(value)).toBe(`"${value}"`);
    }
  });

  it('쌍따옴표는 두 번 쓰고 값 없음은 빈 칸', () => {
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell('=HYPERLINK("http://e.example","x")')).toBe('"\'=HYPERLINK(""http://e.example"",""x"")"');
    expect(csvCell(null)).toBe('""');
    expect(csvCell(undefined)).toBe('""');
    expect(csvCell(0)).toBe('"0"');
    expect(csvCell(155261)).toBe('"155261"');
  });
});

describe('T44 큐 CSV', () => {
  const full = unified(queueItem({ hostName: ['ws-01.lab', 'ws-01'], zeekadResolution: 'false_positive', zeekadStatus: 'closed' }), {
    detectedAt: '2026-11-20T00:00:00Z',
    priority: 'high',
    assignee: { username: 'analyst1', displayName: '분석가1', enabled: true },
  });
  const sparse: UnifiedQueueItem = {
    ...unified(
      queueItem({
        hostIp: '10.0.*.*',
        hostName: ['=cmd|\' /C calc\'!A0'],
        eventStart: null,
        eventEnd: null,
        zeekadPickedBy: null,
        zeekadAlsoFlaggedBy: [],
        zeekadReportKind: null,
        zeekadStatus: null,
        zeekadWouldSend: false,
        alerted: false,
        connectionCount: null,
      }),
      { priority: null },
    ),
    detectedAt: null,
  };

  it('UTF-8 BOM으로 시작하고 CRLF로 줄을 나누며 열 구성이 정해져 있다', () => {
    const csv = queueCsv([{ ...full, incidentNo: 12 }, sparse]);
    expect(csv.startsWith('﻿')).toBe(true);
    expect(csv.endsWith('\r\n')).toBe(true);
    const lines = csv.slice(1).split('\r\n');
    expect(lines).toHaveLength(4);
    expect(lines[3]).toBe('');
    expect(csv.replace(/\r\n/g, '')).not.toMatch(/[\r\n]/);
    expect(lines[0]).toBe(QUEUE_CSV_HEADERS.map((h) => `"${h}"`).join(','));
    expect([...QUEUE_CSV_HEADERS]).toEqual([
      // T45: 시각 열 머리줄에 시간대를 적는다(값은 그대로)
      '번호', '우선순위', '탐지 시각(KST)', '호스트 IP', '호스트 이름', '수집원', '통신 방향', '발생 시작(KST)', '발생 종료(KST)',
      '탐지 모델', '교차 탐지', '리포트 종류', '발송 판단', '경보 발송', '상태', '판정', '담당', '세션 수',
    ]);
  });

  it('화면과 같은 표시 이름·시각을 쓴다', () => {
    const lines = queueCsv([{ ...full, incidentNo: 12 }]).slice(1).split('\r\n');
    expect(lines[1]).toBe(
      [
        '12', 'High', '2026-11-20 09:00:00', '192.168.10.5', 'ws-01.lab, ws-01', 'CIC-IDS2017 수요일', '출발지',
        '2017-07-05 22:45:00', '2017-07-05 23:15:00', '통신 관계 이상', '기준선 이탈', 'AI 작성', '발송', '경보 발송',
        '종결', '오탐', '분석가1', '155261',
      ]
        .map((v) => `"${v}"`)
        .join(','),
    );
  });

  it('값이 없으면 "-"가 아니라 빈 칸이고, 수식으로 읽힐 호스트 이름은 막는다. 조회자의 가려진 주소는 그대로', () => {
    const lines = queueCsv([sparse]).slice(1).split('\r\n');
    expect(lines[1]).toBe(
      [
        '', '', '', '10.0.*.*', "'=cmd|' /C calc'!A0", 'CIC-IDS2017 수요일', '출발지', '', '', '', '', '', '보류', '발송 기록 없음',
        '신규', '', '', '',
      ]
        .map((v) => `"${v}"`)
        .join(','),
    );
    expect(lines[1]).not.toContain('"-"');
  });

  it('파일 이름은 KST 날짜·시각', () => {
    expect(queueCsvFileName(new Date('2026-11-25T06:41:14Z'))).toBe('incidents-20261125-1541.csv');
    expect(queueCsvFileName(new Date('2026-12-31T15:05:00Z'))).toBe('incidents-20270101-0005.csv');
  });
});

/* ── 큐 화면의 버튼 ── */

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const analyst = {
  username: 'analyst1',
  displayName: '분석가1',
  role: 'ANALYST',
  maskedView: false,
  totpEnabled: false,
  totpVerified: true,
  totpRequired: false,
  allowedCapturePatterns: ['*'],
};

function makeItem(i: number): UnifiedQueueItem {
  return unified(
    queueItem({
      jobId: 42,
      queueRank: i,
      incidentId: `cic17-wed|10.0.${i}.1|originator|${i}`,
      hostIp: `10.0.${i}.1`,
      hostName: i === 1 ? ['=1+1'] : [],
      zeekadStatus: 'open',
      zeekadReviewPending: false,
      alerted: false,
    }),
    { detectedAt: new Date(Date.UTC(2026, 10, 20, 0, i)).toISOString(), priority: 'low' },
  );
}

function renderQueue(path: string, items: () => UnifiedQueueItem[]) {
  const state = { fail: false };
  const opts = (): FakeQueueOptions => ({ anchor: '2026-11-20T01:30:00Z', items: items() });
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === '/api/auth/me') return json({ authenticated: true, user: analyst });
    if (url === '/api/time-context') return json({ anchor: '2026-11-20T01:30:00Z', anchorMode: 'now', snapshot: false });
    if (url.startsWith('/api/incidents/queue/new-count')) return json(fakeNewCount(url, opts()));
    if (url.startsWith('/api/incidents/queue')) {
      return state.fail ? json({ status: 500, code: 'INTERNAL', message: '서버 오류 문구' }, 500) : json(fakeQueue(url, opts()));
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
  return { fetchMock, state };
}

function readBytes(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

/** 내려받기를 가로챈다: 만든 Blob과 누른 링크의 파일 이름 */
function captureDownload() {
  const blobs: Blob[] = [];
  const downloads: string[] = [];
  const revoke = vi.fn();
  (URL as unknown as { createObjectURL: (b: Blob) => string }).createObjectURL = (b) => {
    blobs.push(b);
    return 'blob:t44';
  };
  (URL as unknown as { revokeObjectURL: (u: string) => void }).revokeObjectURL = revoke;
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
    downloads.push(this.download);
  });
  return { blobs, downloads, revoke };
}

const csvButton = () => screen.getByRole('button', { name: 'CSV 내보내기' });

describe('T44 인시던트 큐 "CSV 내보내기" 버튼', () => {
  it('지금 쪽의 행을 추가 요청 없이 CSV 파일로 내려받는다', async () => {
    const user = userEvent.setup();
    const all = Array.from({ length: 30 }, (_, k) => makeItem(k + 1));
    const { fetchMock } = renderQueue('/incidents?period=all&size=25&sort=detected&dir=asc', () => all);
    await screen.findByRole('table');
    expect(csvButton()).toBeEnabled();
    expect(csvButton().textContent).toBe('CSV 내보내기');
    const dl = captureDownload();
    const callsBefore = fetchMock.mock.calls.length;

    await user.click(csvButton());
    expect(fetchMock.mock.calls.length).toBe(callsBefore);
    expect(dl.downloads).toHaveLength(1);
    expect(dl.downloads[0]).toMatch(/^incidents-\d{8}-\d{4}\.csv$/);
    expect(dl.blobs[0].type).toBe('text/csv;charset=utf-8');
    const bytes = await readBytes(dl.blobs[0]);
    expect(Array.from(bytes.slice(0, 3))).toEqual([0xef, 0xbb, 0xbf]);
    const text = new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes);
    const lines = text.slice(1).split('\r\n');
    // 머리줄 + 지금 쪽 25행 + 끝 줄바꿈(전체 30건이 아니다)
    expect(lines).toHaveLength(27);
    expect(lines[1]).toContain('"10.0.1.1","\'=1+1"');
    expect(lines[25]).toContain('"10.0.25.1"');
    // 링크는 문서에 남기지 않고 주소도 놓는다
    expect(document.querySelector('a[download]')).toBeNull();
    await waitFor(() => expect(dl.revoke).toHaveBeenCalledWith('blob:t44'));
  });

  it('성공한 0건이면 버튼이 막힌다', async () => {
    renderQueue('/incidents?period=all', () => []);
    await waitFor(() => expect(document.querySelector('[data-empty]')).not.toBeNull());
    expect(csvButton()).toBeDisabled();
  });

  it('처음 불러오기가 실패하면 버튼이 막힌다', async () => {
    const q = renderQueue('/incidents?period=all', () => [makeItem(1)]);
    // 첫 큐 요청은 로그인 확인 뒤에 나가므로 그 전에 실패로 바꾼다
    q.state.fail = true;
    await screen.findByRole('alert');
    expect(screen.queryByRole('table')).toBeNull();
    expect(csvButton()).toBeDisabled();
  });

  it('같은 조건 다시 불러오기가 실패해 최신 값이 아니면 행이 남아 있어도 버튼이 막힌다', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' });
    const all = Array.from({ length: 12 }, (_, k) => makeItem(k + 1));
    let items = all.slice(0, 10);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const q = renderQueue('/incidents?sort=detected&dir=desc', () => items);
    await screen.findByRole('table');
    expect(csvButton()).toBeEnabled();
    await waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
    items = all;
    await act(async () => {
      vi.advanceTimersByTime(NEW_INCIDENT_POLL_MS);
    });
    await screen.findByText('새 인시던트 2건');

    q.state.fail = true;
    await user.click(screen.getByRole('button', { name: '불러오기' }));
    expect(await screen.findByTestId('stale-notice')).toHaveTextContent('최신 값이 아닙니다');
    expect(within(screen.getByRole('table')).getAllByRole('row').length).toBeGreaterThan(1);
    expect(csvButton()).toBeDisabled();
  });
});

/* ───────────────────────── 상세 화면에 함께 붙였을 때 ───────────────────────── */

describe('T44 상세 화면 구성', () => {
  it('증적 탭: 증적 요약 카드 아래, 분포 막대 위에 주요 통신 구조가 온다', () => {
    const detail: IncidentDetailView = baseDetail();
    const { container } = render(<EvidenceSection evidence={detail.evidence} assetNames={detail.assetNames} incident={detail.incident} />);
    const panel = screen.getByRole('region', { name: '주요 통신 구조' });
    const cards = screen.getByText('고유 목적지 포트 수');
    const dist = screen.getByText('전송 계층 분포');
    expect(cards.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(panel.compareDocumentPosition(dist) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expectNoInlineStyle(container);
  });
});
