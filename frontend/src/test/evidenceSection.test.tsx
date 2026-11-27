import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EvidenceSection } from '../components/incident/EvidenceSection';
import type { EvidenceView } from '../types/api';

const baseEvidence: EvidenceView = {
  available: true,
  statusMessage: '정상',
  connectionCount: 155261,
  bytesSent: 1791339786,
  bytesReceived: 0,
  payloadBytesInflated: null,
  transportCounts: { tcp: 155221, udp: 40 },
  serviceProtocolCounts: { http: 147460, gssapi: 10 },
  connStateCounts: { SF: 58598, RSTO: 91898 },
  topPeers: [{ ip: '172.16.*.*', connections: 155111 }],
  uniquePeers: 12,
  topPorts: [{ port: 137, transport: 'udp', connections: 40 }],
  uniquePorts: 27,
  protocolLogs: [
    { protocol: 'dns', metrics: { queries: 80, nxdomain: 0, max_query_length: 0 } },
    { protocol: 'dce_rpc', metrics: { calls: 10, top_operations: [{ operation: 'NetrShareEnum', connections: 10 }] } },
    { protocol: 'ntlm', metrics: null },
  ],
  representativeConnections: [],
  limits: ['점수는 정상(월요일) 대비 이상함이다. 공격 확정이 아니다'],
  additionalFields: { version: 'evidence.v1' },
};

describe('EvidenceSection', () => {
  it('정형 증적 칸(바이트·unique·서비스 프로토콜·상위 포트 전송 계층·프로토콜 로그 하위 수치·관측 한계)을 렌더링한다', () => {
    const { container } = render(<EvidenceSection evidence={baseEvidence} />);

    expect(screen.getByText('송신 바이트')).toBeInTheDocument();
    // 바이트 기준(인시던트 대상 호스트)은 툴팁으로 둔다
    expect(screen.getByText('송신 바이트').parentElement).toHaveAttribute('title', '인시던트 대상 호스트 기준');
    expect(screen.getByText('수신 바이트')).toBeInTheDocument();
    expect(screen.getByText('수신 바이트').parentElement).toHaveAttribute('title', '인시던트 대상 호스트 기준');
    expect(screen.queryByText(/orig_bytes|resp_bytes/)).not.toBeInTheDocument();
    expect(screen.getByText('1.7 GB')).toBeInTheDocument();
    expect(screen.getByText('고유 상대 IP 수').nextSibling).toHaveTextContent('12');
    expect(screen.getByText('고유 목적지 포트 수').nextSibling).toHaveTextContent('27');
    expect(screen.getByText('서비스 프로토콜 분포')).toBeInTheDocument();
    expect(screen.getByText('gssapi')).toBeInTheDocument();
    expect(screen.getByText('udp', { selector: 'td' })).toBeInTheDocument();

    const dns = screen.getByTestId('protocol-log-dns');
    expect(within(dns).getByText('질의 수').nextSibling).toHaveTextContent('80');
    // T68(B1): NXDOMAIN은 분석가가 그대로 쓰는 말이다(전에는 "없는 도메인 응답")
    expect(within(dns).getByText('NXDOMAIN 응답').nextSibling).toHaveTextContent('0');
    const dce = screen.getByTestId('protocol-log-dce_rpc');
    expect(within(dce).getByText('주요 호출').nextSibling).toHaveTextContent('NetrShareEnum · 10');

    expect(screen.getByText('점수는 정상(월요일) 대비 이상함이다. 공격 확정이 아니다')).toBeInTheDocument();
    expect(container.textContent).not.toContain('[object Object]');
  });

  it('키가 없는 값은 "값 없음", 관측한 0은 0으로 구분한다', () => {
    render(<EvidenceSection evidence={baseEvidence} />);

    // T68(A16): "부푼" → "과대 집계된", 툴팁은 탐지 저장소 limits 문장에서 가져왔다(설계자 답 L7)
    expect(screen.getByText('페이로드 바이트가 과대 집계된 세션 수').nextSibling).toHaveTextContent('값 없음');
    expect(screen.getByText('페이로드 바이트가 과대 집계된 세션 수').closest('[title]')).toHaveAttribute(
      'title',
      'Zeek 페이로드 바이트가 IP 바이트보다 큰 세션(바이트 값은 관측한 IP 바이트 기준)',
    );
    expect(screen.getByText('수신 바이트').nextSibling).toHaveTextContent('0 B');
    expect(within(screen.getByTestId('protocol-log-ntlm')).getByText('값 없음')).toBeInTheDocument();
    expect(within(screen.getByTestId('protocol-log-dns')).queryByText('값 없음')).not.toBeInTheDocument();
  });

  it('증적이 없으면 백엔드 상태 문구를 그대로 보여 준다', () => {
    render(
      <EvidenceSection
        evidence={{
          ...baseEvidence,
          available: false,
          statusMessage: '이 인시던트에는 증적 요약이 없습니다. 증적 조회는 정상입니다.',
        }}
      />,
    );
    expect(screen.getByRole('status')).toHaveTextContent('이 인시던트에는 증적 요약이 없습니다. 증적 조회는 정상입니다.');
  });
});
