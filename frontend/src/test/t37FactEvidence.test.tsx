import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { FactItem, ReportView } from '../types/api';
import { describeFact, describeProblem, factLabel, isKnownFactName, withPseudonymAddress } from '../utils/factLabels';
import { ReportClaims, ReportSection, ReportVerificationProblems } from '../components/incident/ReportSection';
import { VerificationBadge } from '../components/StatusBadge';
import { VERIFICATION_DESCRIPTION } from '../utils/labels';
import { baseDetail } from './detailFixture';
import { PUBLIC_FACT_NAMES } from './publicFactNames';

const ANALYST_PS = { H: '192.168.10.5', X1: '203.0.113.45', I1: '10.0.0.7' };
const VIEWER_PS = { H: '192.168.*.*', X1: '203.0.*.*', I1: '10.0.*.*' };

function fact(name: string, valueJson: unknown, id = 'F01', value?: string): FactItem {
  return {
    id,
    name,
    value: value ?? (valueJson === null ? '-' : typeof valueJson === 'object' ? JSON.stringify(valueJson) : String(valueJson)),
    valueJson,
  };
}

function view(name: string, valueJson: unknown, ps: Record<string, string> = ANALYST_PS) {
  return describeFact(fact(name, valueJson), ps);
}

function report(overrides: Partial<ReportView> = {}): ReportView {
  return { ...baseDetail().report, ...overrides };
}

describe('T37 근거 사실 사전', () => {
  it('공개 데이터의 사실 이름 102가지를 모두 덮는다(이름이 한국어로 바뀐다)', () => {
    expect(PUBLIC_FACT_NAMES).toHaveLength(102);
    const uncovered = PUBLIC_FACT_NAMES.filter((n) => !isKnownFactName(n));
    expect(uncovered).toEqual([]);
    const unchanged = PUBLIC_FACT_NAMES.filter((n) => factLabel(n) === n);
    expect(unchanged).toEqual([]);
  });

  it('숫자 묶음: 천 단위 구분, 바이트 단위, 초는 시간 표기, 순위', () => {
    expect(view('connection_count', 155261)).toMatchObject({ label: '세션 수', text: '155,261', valueKnown: true });
    expect(view('unique_peers', 12).label).toBe('고유 상대 IP 수');
    expect(view('unique_destination_ports', 27).label).toBe('고유 목적지 포트 수');
    expect(view('payload_bytes_inflated_connections', 724).text).toBe('724');
    expect(view('queue_rank', 3)).toMatchObject({ label: '탐지 순위', text: '3위' });
    expect(view('bytes_sent_by_host', 1791339786)).toMatchObject({ label: '자산 송신 바이트', text: '1.7 GB' });
    expect(view('bytes_received_by_host', 512).text).toBe('512 B');
    expect(view('incident_duration_seconds', 3900)).toMatchObject({ label: '인시던트 지속 시간', text: '1시간 5분' });
  });

  it('세션 상태·서비스 프로토콜·전송 계층은 기존 사전을 다시 쓰고 세션 수로 보인다', () => {
    expect(view('conn_state.REJ', 104)).toMatchObject({ label: '세션 상태 · 연결 거부', text: '104건' });
    expect(view('conn_state.S0', 1200)).toMatchObject({ label: '세션 상태 · 연결 시도, 응답 없음', text: '1,200건' });
    expect(view('protocol.unidentified', 5)).toMatchObject({ label: '서비스 프로토콜 · 식별 안 됨' });
    expect(view('protocol.ftp-data', 2).label).toBe('서비스 프로토콜 · ftp-data');
    expect(view('transport.tcp', 390)).toMatchObject({ label: '전송 계층 · tcp', text: '390건' });
  });

  it('프로토콜 로그 수치(dns·http·tls·smb·kerberos·ntlm·ssh·ftp·dce_rpc)', () => {
    expect(view('dns.queries', 80)).toMatchObject({ label: 'DNS 질의 수', text: '80' });
    expect(view('dns.max_query_length_chars', 30)).toMatchObject({ label: 'DNS 최장 질의 길이', text: '30자' });
    expect(view('http.errors', 1).label).toBe('HTTP 오류 응답');
    expect(view('tls.without_sni', 4).label).toBe('TLS SNI 없는 세션');
    expect(view('smb.mappings', 2).label).toBe('SMB 공유 폴더 연결');
    expect(view('kerberos.failures', 9).label).toBe('Kerberos 실패 수');
    expect(view('ntlm.auths', 9).label).toBe('NTLM 인증 수');
    expect(view('ssh.auth_failures', 9).label).toBe('SSH 인증 실패');
    expect(view('ftp.failed_replies', 9).label).toBe('FTP 실패 응답');
    expect(view('dce_rpc.calls', 3).label).toBe('DCE-RPC 호출 수');
    expect(view('dce_rpc.top_operation_1', { operation: 'NetrShareEnum', connections: 3 })).toMatchObject({
      label: 'DCE-RPC 주요 호출 1',
      text: 'NetrShareEnum · 세션 3건',
    });
  });

  it('방향·탐지 모델·함께 탐지한 모델(빈 배열은 "없음")·모델 이상 판정 구간', () => {
    expect(view('host_role', 'originator')).toMatchObject({ label: '통신 방향', text: '출발지' });
    expect(view('picked_by_model', 'tgn_recon')).toMatchObject({ label: '탐지 모델', text: '통신 관계 이상' });
    expect(view('also_flagged_by_models', ['tail_rarity_v2', 'transformer_v2']).text).toBe('기준선 이탈, 행위 패턴 이탈');
    expect(view('also_flagged_by_models', []).text).toBe('없음');
    expect(view('model_candidate_windows.transformer_v2', { candidate: 3, windows: 6 })).toMatchObject({
      label: '행위 패턴 이탈 이상 판정 구간',
      text: '3 / 6 구간',
    });
  });

  it('평소 대비: 네 값 한 줄, p95 배수, null 칸은 "-"(0 아님), 0으로 나누지 않음', () => {
    const v = view('baseline.connections_per_window', { incident_max: 1200, baseline_p50: 10, baseline_p95: 40, baseline_max: 90 });
    expect(v.label).toBe('평소 대비 · 구간당 세션 수');
    expect(v.text).toBe('이번 인시던트 최대 1,200 / 평소 중앙값 10 / 평소 p95 40 / 평소 최대 90 (평소 p95의 30배)');
    expect(v.wide).toBe(true);
    const nulls = view('baseline.dns_queries_per_window', { incident_max: 7, baseline_p50: null, baseline_p95: null, baseline_max: null });
    expect(nulls.text).toBe('이번 인시던트 최대 7 / 평소 중앙값 - / 평소 p95 - / 평소 최대 -');
    const zero = view('baseline.http_errors_per_window', { incident_max: 5, baseline_p50: 0, baseline_p95: 0, baseline_max: 0 });
    expect(zero.text).toBe('이번 인시던트 최대 5 / 평소 중앙값 0 / 평소 p95 0 / 평소 최대 0');
    const bytes = view('baseline.payload_bytes_sent_by_host_per_window', {
      incident_max: 2048,
      baseline_p50: 100.5,
      baseline_p95: 1024,
      baseline_max: 1500,
    });
    expect(bytes.text).toBe('이번 인시던트 최대 2.0 KB / 평소 중앙값 100.5 B / 평소 p95 1.0 KB / 평소 최대 1.5 KB (평소 p95의 2배)');
    expect(view('baseline.dns_max_query_length_chars', { incident_max: 60, baseline_p50: 20, baseline_p95: 30, baseline_max: 40 }).text).toContain(
      '이번 인시던트 최대 60자',
    );
    expect(view('baseline_windows', { baseline_windows: 288, incident_windows: 6 })).toMatchObject({
      label: '비교한 구간 수',
      text: '평소 288구간 · 이번 인시던트 6구간',
    });
  });

  it('비율(_ratio): 0~1이면 %, 범위 밖(음수·1 초과)은 바꾸지 않고 그대로', () => {
    const inRange = view('baseline.rejected_connection_ratio', { incident_max: 0.875, baseline_p50: 0, baseline_p95: 0.05, baseline_max: 1 });
    expect(inRange.text).toBe('이번 인시던트 최대 87.5% / 평소 중앙값 0% / 평소 p95 5% / 평소 최대 100%');
    const outOfRange = view('baseline.icmp_connection_ratio', { incident_max: 1.5, baseline_p50: -0.2, baseline_p95: 0.1, baseline_max: 0.3 });
    expect(outOfRange.text).toBe('이번 인시던트 최대 1.5 / 평소 중앙값 -0.2 / 평소 p95 10% / 평소 최대 30%');
  });

  it('상대 IP·목적지 포트·주요 세션: 가명에 역할에 맞는 주소를 붙인다(분석가 원문, 조회자 가린 주소)', () => {
    expect(view('top_peer_1', { peer: 'X1', connections: 210 }).text).toBe('X1(203.0.113.45) · 세션 210건');
    expect(view('top_peer_1', { peer: 'X1', connections: 210 }, VIEWER_PS).text).toBe('X1(203.0.*.*) · 세션 210건');
    expect(view('top_peer_2', { peer: 'X9', connections: 1 }).text).toBe('X9 · 세션 1건');
    expect(view('top_destination_port_1', { port: 88, transport: 'tcp', connections: 195 })).toMatchObject({
      label: '많이 쓴 목적지 포트 1',
      text: '88/tcp · 세션 195건',
    });
    const conn = {
      source: 'H',
      destination: 'X1',
      destination_port: 443,
      transport: 'tcp',
      protocol: 'ssl',
      conn_state: 'SF',
      duration_seconds: 1.25,
      source_bytes: 2048,
      destination_bytes: 300,
      start_seconds: -12.5,
    };
    const v = describeFact(fact('example_connection_1', conn), VIEWER_PS);
    expect(v).toMatchObject({ label: '주요 세션 1', wide: true, valueKnown: true });
    expect(v.text).toBe(
      'H(192.168.*.*) → X1(203.0.*.*):443/tcp · ssl · 정상 연결·종료 · 지속 1.2초 · 출발지가 보냄 2.0 KB · 목적지가 보냄 300 B',
    );
    expect(view('example_connection_2', { ...conn, duration_seconds: null }).text).toContain('지속 -');
  });

  it('섞인 글에는 주소를 붙이지 않고, 가명표에 없으면 그대로 둔다', () => {
    expect(withPseudonymAddress('X1:443', ANALYST_PS)).toBe('X1:443');
    expect(withPseudonymAddress('X1', ANALYST_PS)).toBe('X1(203.0.113.45)');
    expect(withPseudonymAddress('constructor', ANALYST_PS)).toBe('constructor');
    expect(withPseudonymAddress('X1', {})).toBe('X1');
    expect(view('top_peer_1', { peer: 'X1:443', connections: 1 }).text).toBe('X1:443 · 세션 1건');
  });

  it('모르는 이름·모르는 값 모양은 원문 그대로(지어내지 않음)', () => {
    const unknown = view('brand_new_metric', { a: 1 });
    expect(unknown).toMatchObject({ label: 'brand_new_metric', nameKnown: false, text: '{"a":1}', valueKnown: false, group: 'other' });
    const wrongShape = view('baseline.connections_per_window', 12);
    expect(wrongShape).toMatchObject({ nameKnown: true, valueKnown: false, text: '12' });
    const extraKey = view('top_peer_1', { peer: 'X1', connections: 1, extra: true });
    expect(extraKey.valueKnown).toBe(false);
    expect(view('host_role', 'sideways')).toMatchObject({ valueKnown: false, text: 'sideways' });
    expect(view('picked_by_model', 'new_model_v9')).toMatchObject({ valueKnown: false, text: 'new_model_v9' });
    expect(view('conn_state.ZZ', 1)).toMatchObject({ nameKnown: false, label: 'conn_state.ZZ' });
    expect(view('baseline.new_metric_per_window', { incident_max: 1 }).nameKnown).toBe(false);
    // 사전에 없는 이름이라도 값 글 전체가 가명이면 주소를 붙인다
    expect(view('new_peer_field', 'X1', VIEWER_PS).text).toBe('X1(203.0.*.*)');
  });

  it('구조 값이 없으면(조회자 키 겹침·옛 응답) 글 값 원문을 보인다', () => {
    const collided: FactItem = { id: 'F07', name: 'top_peer_1', value: '{"10.0.*.*":1}', valueJson: null };
    expect(describeFact(collided, VIEWER_PS)).toMatchObject({ valueKnown: false, text: '{"10.0.*.*":1}' });
    const old: FactItem = { id: 'F08', name: 'connection_count', value: '412' };
    expect(describeFact(old, VIEWER_PS)).toMatchObject({ valueKnown: false, text: '412', label: '세션 수' });
  });

  it('검증 문제 문장: 숫자·가명(주소 붙임, 가명표에 없으면 그대로)·위치, 모르는 kind와 글은 원문', () => {
    expect(describeProblem({ kind: 'number_not_in_facts', value: '1,234', where: 'claims[0].claim' }, VIEWER_PS)).toEqual({
      text: '리포트 글에서 근거 사실에 없는 숫자: "1,234"',
      known: true,
      where: 'claims[0].claim',
    });
    expect(describeProblem({ kind: 'number_not_in_facts', value: 443, where: null }, VIEWER_PS).text).toBe(
      '리포트 글에서 근거 사실에 없는 숫자: "443"',
    );
    expect(describeProblem({ kind: 'pseudonym_not_in_facts', value: 'X1', where: 'observation_summary' }, VIEWER_PS).text).toBe(
      '리포트 글에서 근거 사실에 없는 가명: "X1(203.0.*.*)"',
    );
    expect(describeProblem({ kind: 'pseudonym_not_in_facts', value: 'Z9', where: 'x' }, VIEWER_PS).text).toBe(
      '리포트 글에서 근거 사실에 없는 가명: "Z9"',
    );
    // T38: 값의 받침(있음 "524,288"·"443"·"X1", 없음 "1,234"·"Z9")과 상관없이 값 뒤에 조사가 붙지 않는다
    for (const value of ['524,288', '1,234', '443', '9']) {
      const text = describeProblem({ kind: 'number_not_in_facts', value, where: null }, VIEWER_PS).text;
      expect(text).toBe(`리포트 글에서 근거 사실에 없는 숫자: "${value}"`);
      expect(text).not.toMatch(/"[가이]/);
    }
    expect(describeProblem({ kind: 'new_check', value: 'a', where: 'b' }, VIEWER_PS)).toEqual({
      text: '{"kind":"new_check","value":"a","where":"b"}',
      known: false,
      where: null,
    });
    expect(describeProblem('옛 형식 문제 글', VIEWER_PS)).toEqual({ text: '옛 형식 문제 글', known: false, where: null });
  });
});

describe('T37 근거 화면', () => {
  const sixFacts: FactItem[] = [
    fact('connection_count', 155261, 'F01'),
    fact('bytes_sent_by_host', 2048, 'F02'),
    fact('top_peer_1', { peer: 'X1', connections: 210 }, 'F03'),
    fact('conn_state.SF', 300, 'F04'),
    fact('dns.queries', 12, 'F05'),
    fact('brand_new_metric', 'abc', 'F06'),
  ];

  it('문장 아래에 항목 이름 + 값 + 작은 번호(판독기 글자 포함)가 바로 보이고, 4개 넘으면 "근거 N개 더 보기"로 편다', async () => {
    const user = userEvent.setup();
    render(<ReportClaims report={report({ claims: [{ claim: '세션이 급증했습니다.', facts: sixFacts }], pseudonyms: VIEWER_PS })} />);
    expect(screen.getByText('문장 아래는 리포트가 인용한 근거 사실입니다. 끝의 번호는 근거 번호입니다')).toBeInTheDocument();
    expect(screen.queryByText(/근거 번호를 누르면/)).toBeNull();
    const list = screen.getByRole('list', { name: '근거 사실 6개' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(4);
    const first = within(list).getByText('근거 번호 F01').closest('li') as HTMLElement;
    expect(within(first).getByText('세션 수')).toBeInTheDocument();
    expect(within(first).getByText('155,261')).toBeInTheDocument();
    expect(first).toHaveAttribute('title', expect.stringContaining('zeek_AD 이름: connection_count'));
    expect(within(list).getByText('X1(203.0.*.*) · 세션 210건')).toBeInTheDocument();
    const more = screen.getByRole('button', { name: '근거 2개 더 보기' });
    expect(more).toHaveAttribute('aria-expanded', 'false');
    await user.click(more);
    expect(within(list).getAllByRole('listitem')).toHaveLength(6);
    expect(within(list).getByText('brand_new_metric')).toHaveAttribute('data-raw');
    expect(within(list).getByText('abc')).toHaveAttribute('data-raw');
    expect(screen.getByRole('button', { name: '근거 접기' })).toHaveAttribute('aria-expanded', 'true');
  });

  it('근거가 5개면(하나만 숨게 되면) 더 보기 버튼 없이 모두 보인다', () => {
    render(<ReportClaims report={report({ claims: [{ claim: '문장', facts: sixFacts.slice(0, 5) }], pseudonyms: VIEWER_PS })} />);
    expect(within(screen.getByRole('list', { name: '근거 사실 5개' })).getAllByRole('listitem')).toHaveLength(5);
    expect(screen.queryByRole('button', { name: /더 보기/ })).toBeNull();
  });

  it('인용한 번호가 사실 목록에 없으면 "근거 정보 없음"과 번호를 보인다', () => {
    const missing: FactItem = { id: 'F99', name: '근거 정보 없음', value: '-', valueJson: null };
    render(<ReportClaims report={report({ claims: [{ claim: '문장', facts: [missing] }] })} />);
    const li = screen.getByText('근거 번호 F99').closest('li') as HTMLElement;
    expect(within(li).getByText('근거 정보 없음')).toBeInTheDocument();
    expect(within(li).getByText('F99')).toBeInTheDocument();
  });

  it('AI 리포트 탭: 근거 사실 전체(접힘)는 묶음별 표이고 인용한 항목에 표시가 있다', () => {
    const all = [
      ...sixFacts,
      fact('baseline.connections_per_window', { incident_max: 9, baseline_p50: 1, baseline_p95: 3, baseline_max: 4 }, 'F07'),
      fact('example_connection_1', {
        source: 'H',
        destination: 'X1',
        destination_port: 80,
        transport: 'tcp',
        protocol: 'http',
        conn_state: 'SF',
        duration_seconds: 0.5,
        source_bytes: 10,
        destination_bytes: 20,
        start_seconds: 1,
      }, 'F08'),
    ];
    render(
      <ReportSection
        report={report({
          claims: [{ claim: '문장', facts: [all[0], all[2]] }],
          possibleExplanations: [{ explanation: '해석', facts: [all[6]], attackIds: [] }],
          sendRecommendation: { choice: 'send', reason: '이유', facts: [all[0]] },
          allFacts: all,
          pseudonyms: ANALYST_PS,
        })}
      />,
    );
    const summary = screen.getByText('근거 사실 전체 (8개)');
    const details = summary.closest('details') as HTMLElement;
    expect(details).not.toHaveAttribute('open');
    expect(within(details).getByText('리포트가 인용한 항목 3개')).toBeInTheDocument();
    const tables = within(details).getAllByRole('table');
    expect(tables.map((t) => t.querySelector('caption')?.textContent)).toEqual([
      '규모·방향 (2개)',
      '평소 대비 (1개)',
      '세션 상태·전송 계층·서비스 프로토콜 (1개)',
      '프로토콜 로그 (1개)',
      '상대 IP·목적지 포트 (1개)',
      '주요 세션 (1개)',
      '사전에 없는 항목 (1개)',
    ]);
    const rowF03 = within(details).getByText('F03').closest('tr') as HTMLElement;
    expect(within(rowF03).getByText('인용')).toBeInTheDocument();
    expect(within(rowF03).getByText('X1(203.0.113.45) · 세션 210건')).toBeInTheDocument();
    const rowF04 = within(details).getByText('F04').closest('tr') as HTMLElement;
    expect(within(rowF04).queryByText('인용')).toBeNull();
    expect(within(details).getByText('H(192.168.10.5) → X1(203.0.113.45):80/tcp · http · 정상 연결·종료 · 지속 500ms · 출발지가 보냄 10 B · 목적지가 보냄 20 B')).toBeInTheDocument();
  });

  it('근거 사실 전체가 없으면(옛 응답) 접힌 구역을 그리지 않는다', () => {
    render(<ReportSection report={report({ allFacts: undefined })} />);
    expect(screen.queryByText(/근거 사실 전체/)).toBeNull();
  });

  it('검증 실패 문제 항목을 문장으로 보인다(위치 포함, 모르는 kind는 원문)', () => {
    render(
      <ReportVerificationProblems
        report={report({
          verificationPassed: false,
          verificationReason: 'verification',
          verificationProblems: ['{"kind":"number_not_in_facts","value":"77","where":"claims[1].claim"}'],
          verificationProblemItems: [
            { kind: 'number_not_in_facts', value: '77', where: 'claims[1].claim' },
            { kind: 'pseudonym_not_in_facts', value: 'X1', where: 'observation_summary' },
            { kind: 'mystery', value: 1 },
          ],
          pseudonyms: VIEWER_PS,
        })}
      />,
    );
    const first = screen.getByText(/리포트 글에서 근거 사실에 없는 숫자: "77"/).closest('li') as HTMLElement;
    expect(within(first).getByText('claims[1].claim')).toHaveAttribute('data-raw');
    expect(first.textContent).toBe('리포트 글에서 근거 사실에 없는 숫자: "77" (위치: claims[1].claim)');
    expect(screen.getByText(/리포트 글에서 근거 사실에 없는 가명: "X1\(203\.0\.\*\.\*\)"/)).toBeInTheDocument();
    expect(screen.getByText('{"kind":"mystery","value":1}')).toHaveAttribute('data-raw');
    expect(screen.queryByText(/\{"kind":"number_not_in_facts"/)).toBeNull();
  });

  it('옛 응답(구조 목록 없음)이면 검증 문제 글을 원문 그대로 보인다', () => {
    render(
      <ReportVerificationProblems
        report={report({ verificationPassed: false, verificationReason: 'verification', verificationProblems: ['원문 문제'], verificationProblemItems: undefined })}
      />,
    );
    expect(screen.getByText('원문 문제')).toHaveAttribute('data-raw');
  });

  it('상세 검증 표지: 이름은 그대로, 툴팁·접근성 이름에 뜻(해석 보증 아님)', () => {
    const { rerender } = render(<VerificationBadge passed={true} />);
    const pass = screen.getByRole('img', { name: VERIFICATION_DESCRIPTION.passed });
    expect(pass).toHaveAttribute('title', VERIFICATION_DESCRIPTION.passed);
    expect(within(pass).getByText('검증 통과')).toBeInTheDocument();
    expect(VERIFICATION_DESCRIPTION.passed).toBe(
      'AI 리포트 검증 통과: zeek_AD가 리포트 글을 근거 사실과 대조했습니다(글 속 숫자·가명 등). 해석이 맞다는 뜻은 아닙니다',
    );
    rerender(<VerificationBadge passed={false} />);
    const fail = screen.getByRole('img', { name: VERIFICATION_DESCRIPTION.failedDetail });
    expect(fail).toHaveAttribute('title', VERIFICATION_DESCRIPTION.failedDetail);
    expect(within(fail).getByText('검증 실패')).toBeInTheDocument();
    expect(VERIFICATION_DESCRIPTION.failedDetail).toBe(
      'AI 리포트 검증 실패: 리포트 글에 근거 사실과 맞지 않는 내용이 있습니다. 검증 실패 사유를 확인합니다',
    );
  });
});
