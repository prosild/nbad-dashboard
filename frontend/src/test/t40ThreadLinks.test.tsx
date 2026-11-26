import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { ReportVerificationProblems } from '../components/incident/ReportSection';
import { SlackThreadsSection } from '../components/incident/SlackThreadsSection';
import type { ReportView, SlackDeliveryView, SlackThreadGroup } from '../types/api';
import { describeVerificationReason } from '../utils/factLabels';
import { parseQueueQuery, parseThread, queueApiParams } from '../utils/triage';
import { baseDetail } from './detailFixture';

/**
 * T40 알림 묶음 건너가기(상세 Slack 탭의 링크 네 경우, 큐 조건 파싱)와 검증 실패 표시 한국어(사유·문제 항목).
 */

function delivery(over: Partial<SlackDeliveryView> = {}): SlackDeliveryView {
  return {
    jobId: 7,
    messageKind: 'incident',
    messageVersion: 'incident.v2',
    deliveryMode: 'dry_run',
    deliveryStatus: 'recorded',
    dryRunOrRecorded: true,
    slackTs: null,
    deliveredAt: null,
    error: null,
    createdAt: '2026-11-22T03:00:00Z',
    payloadJson: '{"text":"알림"}',
    threadParent: 'lab-20261122|10.0.0.*|originator|1',
    threadKey: 'lab-20261122|10.0.0.*|originator|1',
    threadRoleLabel: '타 인시던트 후속 알림',
    replyBroadcast: false,
    ...over,
  };
}

function group(over: Partial<SlackThreadGroup>): SlackThreadGroup {
  return {
    threadKey: 'lab-20261122|10.0.0.*|originator|1',
    deliveries: [delivery()],
    headIsSelf: false,
    headIncidentNo: null,
    memberCount: 0,
    ...over,
  };
}

function renderGroups(groups: SlackThreadGroup[]) {
  return render(
    <MemoryRouter>
      <SlackThreadsSection threadGroups={groups} />
    </MemoryRouter>,
  );
}

describe('T40 상세 Slack 탭 묶음 링크', () => {
  it('붙은 인시던트(머리를 볼 수 있음): 최초 알림 인시던트 링크(그 인시던트 Slack 탭)와 같은 묶음 보기', () => {
    renderGroups([group({ headIncidentNo: 2269, memberCount: 9 })]);
    const head = screen.getByRole('link', { name: '최초 알림 인시던트 #2269' });
    expect(head).toHaveAttribute('href', '/incidents/2269?tab=slack');
    const members = screen.getByRole('link', { name: '같은 묶음 인시던트 9건 보기' });
    expect(members).toHaveAttribute('href', '/incidents?period=all&thread=2269');
    // 표지 글은 그대로
    expect(screen.getByText('타 인시던트 후속 알림')).toBeInTheDocument();
  });

  it('붙은 인시던트(머리를 볼 수 없음, 번호 null): 아무것도 더하지 않는다(이유 문구 없음)', () => {
    renderGroups([group({ threadKey: 'restricted-1', deliveries: [delivery({ threadParent: 'restricted-1', threadKey: 'restricted-1' })] })]);
    expect(screen.queryByTestId('slack-thread-links')).toBeNull();
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.getByText('타 인시던트 후속 알림')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('restricted-1');
  });

  it('머리 인시던트: 자기 링크 없이 같은 묶음 보기만', () => {
    renderGroups([
      group({
        headIsSelf: true,
        headIncidentNo: 31,
        memberCount: 2,
        deliveries: [delivery({ threadParent: null, threadRoleLabel: '최초 알림' })],
      }),
    ]);
    expect(screen.queryByRole('link', { name: /최초 알림 인시던트/ })).toBeNull();
    expect(screen.getByRole('link', { name: '같은 묶음 인시던트 2건 보기' })).toHaveAttribute(
      'href',
      '/incidents?period=all&thread=31',
    );
  });

  it('구성원이 1건 이하(기준 시각 전 묶음 포함): 아무것도 더하지 않는다', () => {
    renderGroups([
      group({
        headIsSelf: true,
        headIncidentNo: 31,
        memberCount: 1,
        deliveries: [delivery({ threadParent: null, threadRoleLabel: '최초 알림', createdAt: '2026-11-18T00:00:00Z' })],
      }),
    ]);
    expect(screen.queryByTestId('slack-thread-links')).toBeNull();
  });

  it('번호는 있고 구성원 1건인 붙은 인시던트: 최초 알림 링크만', () => {
    renderGroups([group({ headIncidentNo: 5, memberCount: 1 })]);
    const links = within(screen.getByTestId('slack-thread-links')).getAllByRole('link');
    expect(links.map((a) => a.textContent)).toEqual(['최초 알림 인시던트 #5']);
  });

  it('threadKey·incident_id 원문은 화면(속성 포함)에 없다', () => {
    const raw = 'lab-20261122|10.9.9.9|originator|1';
    const { container } = renderGroups([
      group({ threadKey: raw, headIncidentNo: 2269, memberCount: 3, deliveries: [delivery({ threadParent: raw, threadKey: raw })] }),
    ]);
    expect(container.innerHTML).not.toContain(raw);
  });
});

describe('T40 큐 thread 파싱', () => {
  it('숫자(양의 정수)만 받는다', () => {
    expect(parseThread('2269')).toBe(2269);
    for (const bad of ['', '0', '-1', '1.5', 'abc', '12abc', ' 12', '9999999999999999']) {
      expect(parseThread(bad)).toBeNull();
    }
    expect(parseThread(null)).toBeNull();
  });

  it('상세 이전·다음(from=)도 thread를 neighbors에 넘긴다', () => {
    const from = new URLSearchParams({ period: 'all', thread: '44', sort: 'detected' }).toString();
    const params = queueApiParams(parseQueueQuery(new URLSearchParams(from)), { paging: false });
    expect(params.thread).toBe('44');
    expect(params.period).toBe('all');
    expect(queueApiParams(parseQueueQuery(new URLSearchParams('thread=x1'))).thread).toBeUndefined();
  });
});

describe('T40 검증 실패 사유·문제 항목 한국어', () => {
  it('사유 사전: verification·call·call: 글, 모르는 값은 원문', () => {
    expect(describeVerificationReason('verification')).toEqual({
      text: '리포트 내용이 근거와 맞지 않음(숫자·가명·ATT&CK ID)',
      known: true,
      raw: 'verification',
    });
    expect(describeVerificationReason('call')).toEqual({ text: 'LLM 호출 실패', known: true, raw: 'call' });
    expect(describeVerificationReason('call: ClientError')).toEqual({
      text: 'LLM 호출 실패: ClientError',
      known: true,
      raw: 'call: ClientError',
    });
    expect(describeVerificationReason('timeout')).toEqual({ text: 'timeout', known: false, raw: 'timeout' });
    expect(describeVerificationReason('callback')).toEqual({ text: 'callback', known: false, raw: 'callback' });
    expect(describeVerificationReason(null)).toBeNull();
  });

  function failed(over: Partial<ReportView>): ReportView {
    return { ...baseDetail().report, verificationPassed: false, ...over };
  }

  it('화면: 아는 사유는 한국어(원문은 툴팁), 모르는 사유는 원문(data-raw)', () => {
    const { rerender } = render(<ReportVerificationProblems report={failed({ verificationReason: 'verification' })} />);
    const known = screen.getByText('리포트 내용이 근거와 맞지 않음(숫자·가명·ATT&CK ID)');
    expect(known).toHaveAttribute('title', '원래 값: verification');
    expect(known).not.toHaveAttribute('data-raw');
    rerender(<ReportVerificationProblems report={failed({ verificationReason: 'brand_new' })} />);
    expect(screen.getByText('brand_new')).toHaveAttribute('data-raw');
  });

  it('화면: attack_id_not_in_candidates는 문장, 모양이 다른 항목은 원문', () => {
    render(
      <ReportVerificationProblems
        report={failed({
          verificationReason: 'verification',
          verificationProblemItems: [
            { kind: 'attack_id_not_in_candidates', value: 'T1046', where: 'possible_explanations[0]' },
            { kind: 'attack_id_not_in_candidates', value: { x: 1 } },
          ],
        })}
      />,
    );
    expect(screen.getByText(/리포트가 인용한 ATT&CK ID 가운데 후보 목록에 없는 ID: "T1046"/)).toBeInTheDocument();
    expect(screen.getByText('{"kind":"attack_id_not_in_candidates","value":{"x":1}}')).toHaveAttribute('data-raw');
  });
});
