import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SlackThreadsSection } from '../components/incident/SlackThreadsSection';
import type { SlackDeliveryView, SlackThreadGroup } from '../types/api';
import { parseSlackMessage, slackTextLines } from '../utils/slackText';
import { lookupSlackMessageVersion } from '../utils/labels';

/** T38: Slack 알림 본문·전문·판 표지·스레드 기록 표지. 주소는 문서용 대역과 가린 모양만 쓴다. */

const BEFORE = '2026-11-18T19:00:13Z';
const AFTER = '2026-11-22T01:00:00Z';

function delivery(over: Partial<SlackDeliveryView> = {}): SlackDeliveryView {
  return {
    jobId: 1,
    messageKind: 'incident',
    messageVersion: 'template.v1',
    deliveryMode: 'dry_run',
    deliveryStatus: 'recorded',
    dryRunOrRecorded: true,
    slackTs: '1763500000.000100',
    deliveredAt: null,
    error: null,
    createdAt: BEFORE,
    payloadJson: JSON.stringify({ channel: 'C0SECRETCHAN', text: '본문' }),
    threadParent: null,
    threadKey: 'inc-1',
    threadRoleLabel: '최초 알림',
    replyBroadcast: false,
    ...over,
  };
}

const group = (...deliveries: SlackDeliveryView[]): SlackThreadGroup[] => [{ threadKey: 'inc-1', deliveries }];

// 본문과 블록 글 양쪽에 넣는 링크·토큰·맨 URL
const TOKENS =
  '<https://example.invalid/x|근거 보기> 링크 <https://example.invalid/y> 채널 <#C000|채널이름> 사용자 <@U000> 전체 <!channel>';

const FULL_PAYLOAD = {
  channel: 'C0SECRETCHAN',
  text: `[캡처] 조사 큐 1위 · 192.168.*.* (출발지) 판단 모델(transformer_v2, tail_rarity_v2) ${TOKENS}\n사건: https://example.invalid/z`,
  blocks: [
    { type: 'header', text: { type: 'plain_text', text: '[캡처] 조사 큐 1위 · 192.0.2.10 (출발지)' } },
    { type: 'context', elements: [{ type: 'mrkdwn', text: `${TOKENS}` }, { type: 'image', image_url: 'https://example.invalid/img.png', alt_text: '그림글' }] },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: '*시간*\n2026-11-19 04:00~04:05 UTC' },
        { type: 'mrkdwn', text: '*꼽은 모델*\ntransformer_v2, tail_rarity_v2' },
      ],
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: '*관측 요약*\nH가 rejected_connection_ratio 0.9로 높습니다.' },
      accessory: { type: 'button', text: { type: 'plain_text', text: '옆 버튼' }, url: 'https://example.invalid/acc' },
    },
    { type: 'section', text: { type: 'mrkdwn', text: '*주요 근거*\n• 연결이 많습니다 _(F01, F02)_' } },
    {
      type: 'context',
      elements: [
        { type: 'mrkdwn', text: '가명 안내: 실제 주소는 [근거 보기](내부 대시보드·근거 API)에서 확인한다' },
        { type: 'mrkdwn', text: '판단 규칙 score &gt;= 0.9, rank &lt;= 5' },
        { type: 'mrkdwn', text: '사건: https://example.invalid/z' },
      ],
    },
    { type: 'mystery', text: { type: 'mrkdwn', text: '모르는 블록 글' } },
    { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '근거 보기' }, url: 'https://example.invalid/btn' }] },
  ],
};

async function openFull(user: ReturnType<typeof userEvent.setup>) {
  for (const btn of screen.getAllByRole('button', { name: '알림 전문 보기' })) {
    await user.click(btn);
  }
}

describe('T38 Slack 알림 본문과 전문', () => {
  it('본문 text가 보이고 전문을 펴면 header·section(text·fields)·context가 글로, 버튼은 이름만 보인다', async () => {
    const user = userEvent.setup();
    const { container } = render(<SlackThreadsSection threadGroups={group(delivery({ payloadJson: JSON.stringify(FULL_PAYLOAD) }))} />);
    expect(screen.getByText(/조사 큐 1위 · 192\.168\.\*\.\* \(출발지\) 판단 모델\(transformer_v2, tail_rarity_v2\)/)).toBeInTheDocument();
    const toggle = screen.getByRole('button', { name: '알림 전문 보기' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('관측 요약')).toBeNull();
    await user.click(toggle);
    expect(screen.getByRole('button', { name: '알림 전문 접기' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('[캡처] 조사 큐 1위 · 192.0.2.10 (출발지)')).toBeInTheDocument();
    expect(screen.getByText('관측 요약').tagName).toBe('STRONG');
    expect(screen.getByText('H가 rejected_connection_ratio 0.9로 높습니다.')).toBeInTheDocument();
    expect(screen.getByText('시간').closest('dt')).not.toBeNull();
    expect(screen.getByText('2026-11-19 04:00~04:05 UTC')).toBeInTheDocument();
    expect(screen.getByText('꼽은 모델')).toBeInTheDocument();
    expect(screen.getAllByText('transformer_v2, tail_rarity_v2').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('(F01, F02)').tagName).toBe('EM');
    expect(screen.getByText('판단 규칙 score >= 0.9, rank <= 5')).toBeInTheDocument();
    expect(screen.getByText('가명 안내: 실제 주소는 [근거 보기](내부 대시보드·근거 API)에서 확인한다')).toBeInTheDocument();
    expect(screen.getByText('버튼: 근거 보기')).toBeInTheDocument();
    // 모르는 블록·그림 요소·accessory는 건너뛴다
    const html = container.innerHTML;
    for (const skipped of ['모르는 블록 글', '그림글', '옆 버튼']) {
      expect(html, skipped).not.toContain(skipped);
    }
    expect(container.querySelectorAll('a')).toHaveLength(0);
    expect(container.querySelectorAll('img')).toHaveLength(0);
  });

  it('URL·채널·slackTs·threadParent·원본 JSON 키가 DOM(속성 포함)에 없다. 링크 글 "근거 보기"는 남는다', async () => {
    const user = userEvent.setup();
    const { container } = render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({ payloadJson: JSON.stringify(FULL_PAYLOAD) }),
          delivery({
            createdAt: AFTER,
            messageVersion: 'llm-report.v1',
            threadParent: 'parent-incident-xyz',
            threadRoleLabel: '후속 알림',
            slackTs: '1763500099.000200',
            payloadJson: JSON.stringify(FULL_PAYLOAD),
          }),
        )}
      />,
    );
    await openFull(user);
    const html = container.innerHTML;
    for (const hidden of [
      'http',
      'example.invalid',
      'mailto',
      'C0SECRETCHAN',
      'C000',
      '채널이름',
      'U000',
      '!channel',
      '1763500000',
      '1763500099',
      'parent-incident-xyz',
      '"blocks"',
      '"channel"',
      '"text"',
      'image_url',
      'accessory',
      '사건:',
    ]) {
      expect(html, hidden).not.toContain(hidden);
    }
    // 본문의 링크 글과 블록의 링크 글 모두 남는다
    expect(screen.getAllByText(/근거 보기 링크 채널 사용자 전체/).length).toBe(4);
  });

  it('T39: 페이로드 맨 위의 reply_broadcast·zeekad_thread_parent(lab-20261122 새 키)는 그리지 않고 본문·전문만 보인다', async () => {
    const user = userEvent.setup();
    const payload = {
      channel: 'C0SECRETCHAN',
      text: '[캡처] 조사 큐 2위 · 10.10.*.* (출발지)',
      reply_broadcast: true,
      zeekad_thread_parent: 'lab-x|10.10.*.*|originator|1763820000',
      blocks: [
        { type: 'header', text: { type: 'plain_text', text: '[캡처] 조사 큐 2위' } },
        { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '근거 보기' }, url: 'http://127.0.*.*:8000/api/v1/jobs/1/incidents/2' }] },
      ],
    };
    expect(parseSlackMessage(JSON.stringify(payload)).body).not.toBeNull();
    const { container } = render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({ createdAt: AFTER }),
          delivery({
            createdAt: AFTER,
            threadParent: 'lab-x|10.10.*.*|originator|1763820000',
            threadRoleLabel: '머리 사건 후속 답글',
            replyBroadcast: true,
            payloadJson: JSON.stringify(payload),
          }),
        )}
      />,
    );
    await openFull(user);
    const html = container.innerHTML;
    for (const hidden of ['reply_broadcast', 'zeekad_thread_parent', 'lab-x', '1763820000', '127.0', ':8000', 'api/v1', 'C0SECRETCHAN', '"text"']) {
      expect(html, hidden).not.toContain(hidden);
    }
    expect(screen.getByText('[캡처] 조사 큐 2위 · 10.10.*.* (출발지)')).toBeTruthy();
  });

  it('글 풀이: 굵게·기울임은 낱말 경계 짝만, 낱말 안 밑줄·~·대괄호 글은 그대로, 엔티티는 마지막에 푼다', () => {
    const flat = (s: string) => slackTextLines(s).map((l) => l.map((seg) => seg.text).join(''));
    expect(flat('*관측 요약*\n• 근거 _(F01, F02)_')).toEqual(['관측 요약', '• 근거 (F01, F02)']);
    expect(flat('transformer_v2, tail_rarity_v2 그리고 rejected_connection_ratio')).toEqual([
      'transformer_v2, tail_rarity_v2 그리고 rejected_connection_ratio',
    ]);
    expect(flat('2026-11-19 04:00~04:05 UTC')).toEqual(['2026-11-19 04:00~04:05 UTC']);
    expect(flat('score &gt;= 0.9 &lt;= 5 &amp;gt;')).toEqual(['score >= 0.9 <= 5 &gt;']);
    expect(flat('[근거 보기](내부 대시보드·근거 API)')).toEqual(['[근거 보기](내부 대시보드·근거 API)']);
    expect(flat('a*b*c 2*3*4')).toEqual(['a*b*c 2*3*4']);
    // 엔티티로 쓴 링크 모양은 토큰으로 지우지 않는다(URL만 빠진다)
    expect(flat('&lt;https://example.invalid/q|글&gt;')).toEqual(['<>']);
    // mailto 링크 글만
    expect(flat('<mailto:a@example.invalid|메일> <mailto:b@example.invalid>')).toEqual(['메일']);
    // 그 밖의 <…> 글은 건드리지 않는다
    expect(flat('<글자>')).toEqual(['<글자>']);
    // 맨 URL을 지우고 이름만 남은 줄은 그리지 않는다
    expect(flat('위\n사건: https://example.invalid/z\n아래')).toEqual(['위', '아래']);
    const styled = slackTextLines('*굵게* 와 _기울임_')[0];
    expect(styled).toEqual([
      { text: '굵게', bold: true },
      { text: ' 와 ' },
      { text: '기울임', italic: true },
    ]);
  });

  it('HTML 모양 글(날것·엔티티)은 글자로만 보이고 요소가 생기지 않는다', async () => {
    const user = userEvent.setup();
    const raw = '<img src=x onerror=alert(1)>';
    const ent = '&lt;img src=x onerror=alert(1)&gt;';
    const { container } = render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({
            payloadJson: JSON.stringify({
              text: `날것 ${raw} 엔티티 ${ent}`,
              blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `블록 ${raw} ${ent}` } }],
            }),
          }),
        )}
      />,
    );
    await openFull(user);
    expect(screen.getByText(`날것 ${raw} 엔티티 ${raw}`)).toBeInTheDocument();
    expect(screen.getByText(`블록 ${raw} ${raw}`)).toBeInTheDocument();
    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
  });

  it('그릴 글이 버튼 이름뿐이면 전문 칸이 없다', () => {
    render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({
            payloadJson: JSON.stringify({
              text: '본문만',
              blocks: [{ type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '근거 보기' }, url: 'https://example.invalid/b' }] }],
            }),
          }),
        )}
      />,
    );
    expect(screen.getByText('본문만')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '알림 전문 보기' })).toBeNull();
  });

  it('깨진 payloadJson에서도 카드는 깨지지 않고 본문·전문 칸만 없다', () => {
    const broken = [
      '{',
      'null',
      '[]',
      JSON.stringify({ text: 42 }),
      JSON.stringify({ blocks: '글' }),
      JSON.stringify({ blocks: [{ type: 'section' }, { type: 'header' }] }),
      JSON.stringify({ blocks: [{ type: 'context', elements: '글' }, { type: 'actions', elements: {} }] }),
      JSON.stringify({ blocks: [null, 3, 'x', { type: 'section', text: 'x', fields: 'y' }] }),
    ];
    for (const payloadJson of broken) {
      expect(parseSlackMessage(payloadJson), payloadJson).toEqual({ body: null, blocks: null });
      const { container, unmount } = render(<SlackThreadsSection threadGroups={group(delivery({ payloadJson }))} />);
      expect(within(container).getByText('최초 알림')).toBeInTheDocument();
      expect(within(container).getByText('기록됨')).toBeInTheDocument();
      expect(within(container).queryByRole('button', { name: '알림 전문 보기' })).toBeNull();
      expect(container.innerHTML).not.toContain('{');
      unmount();
    }
  });
});

describe('T38 판 표지', () => {
  it('사전: 앞머리로 찾고 모르는 판은 원문, 판 없음은 null', () => {
    expect(lookupSlackMessageVersion('template.v1')).toMatchObject({ text: '즉시 알림(틀 문장)', known: true });
    expect(lookupSlackMessageVersion('llm-report.v1')).toMatchObject({ text: 'AI 리포트 알림', known: true });
    expect(lookupSlackMessageVersion('llm-report.v2')).toMatchObject({ text: 'AI 리포트 알림', known: true });
    expect(lookupSlackMessageVersion('digest.v9')).toMatchObject({ text: 'digest.v9', known: false });
    expect(lookupSlackMessageVersion(null)).toBeNull();
    expect(lookupSlackMessageVersion('')).toBeNull();
  });

  it('사건 알림에만 판 표지를 보이고 상태 알림은 "상태 변경 알림"만', () => {
    const { container } = render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({ jobId: 1, messageVersion: 'template.v1' }),
          delivery({ jobId: 2, messageVersion: 'llm-report.v1', createdAt: AFTER }),
          delivery({ jobId: 3, messageVersion: 'llm-report.v2', createdAt: AFTER }),
          delivery({ jobId: 4, messageVersion: 'digest.v9', createdAt: AFTER }),
          delivery({ jobId: 5, messageVersion: null, createdAt: AFTER }),
          delivery({ jobId: 6, messageKind: 'status', messageVersion: 'status:closed', createdAt: AFTER }),
        )}
      />,
    );
    expect(screen.getAllByText('즉시 알림(틀 문장)')).toHaveLength(1);
    expect(screen.getAllByText('AI 리포트 알림')).toHaveLength(2);
    expect(screen.getByText('digest.v9')).toHaveAttribute('data-unregistered');
    expect(screen.getByText('상태 변경 알림')).toBeInTheDocument();
    expect(container.innerHTML).not.toContain('status:closed');
    expect(screen.getAllByText('인시던트 알림')).toHaveLength(5);
  });
});

describe('T38 역할 표지와 스레드 기록 기준 시각', () => {
  const roleBadges = (container: HTMLElement) =>
    Array.from(container.querySelectorAll('span'))
      .map((el) => el.firstChild?.textContent ?? '')
      .filter((t) => ['최초 알림', '스레드 기록 없음', '후속 알림', '타 인시던트 후속 알림'].includes(t));

  it('기준 시각 전 부모 없는 둘: 첫째 "최초 알림", 둘째는 "스레드 기록 없음"과 툴팁·접근성 이름, 들여쓰기 없음', () => {
    const { container } = render(
      <SlackThreadsSection threadGroups={group(delivery({ jobId: 1 }), delivery({ jobId: 2, createdAt: '2026-11-18T19:02:13Z', messageVersion: 'llm-report.v1' }))} />,
    );
    expect(roleBadges(container)).toEqual(['최초 알림', '스레드 기록 없음']);
    const badge = screen.getByText('스레드 기록 없음');
    expect(badge).toHaveAttribute('title', '스레드 기록 도입(2026-11-19) 전의 알림입니다. 첫 알림의 스레드 답글인지 기록에 없습니다.');
    expect(badge.textContent).toContain('첫 알림의 스레드 답글인지 기록에 없습니다.');
    expect(container.querySelector('.ml-5')).toBeNull();
  });

  it('기준 시각 뒤 부모 없는 알림은 몇 번째든 "최초 알림"', () => {
    const { container } = render(
      <SlackThreadsSection threadGroups={group(delivery({ jobId: 1, createdAt: AFTER }), delivery({ jobId: 2, createdAt: AFTER }), delivery({ jobId: 3, createdAt: AFTER }))} />,
    );
    expect(roleBadges(container)).toEqual(['최초 알림', '최초 알림', '최초 알림']);
    expect(screen.queryByText('스레드 기록 없음')).toBeNull();
  });

  it('경계: 06:19:59Z는 전, 06:20:00Z·같은 시각의 +09:00 표기·createdAt 없음은 뒤', () => {
    const cases: [string | null, string][] = [
      ['2026-11-19T06:19:59Z', '스레드 기록 없음'],
      ['2026-11-19T06:20:00Z', '최초 알림'],
      ['2026-11-19T15:20:00+09:00', '최초 알림'],
      ['2026-11-19T15:19:59+09:00', '스레드 기록 없음'],
      [null, '최초 알림'],
      ['읽을 수 없는 값', '최초 알림'],
    ];
    for (const [createdAt, expected] of cases) {
      const { container, unmount } = render(
        <SlackThreadsSection threadGroups={group(delivery({ jobId: 1 }), delivery({ jobId: 2, createdAt, deliveredAt: AFTER }))} />,
      );
      expect(roleBadges(container), String(createdAt)).toEqual(['최초 알림', expected]);
      unmount();
    }
  });

  it('부모가 기록된 알림은 시각과 상관없이 서버 문구와 들여쓰기, 부모 없는 하나 뒤 답글에는 "스레드 기록 없음"이 없다', () => {
    const { container } = render(
      <SlackThreadsSection
        threadGroups={group(
          delivery({ jobId: 1, createdAt: AFTER }),
          delivery({ jobId: 2, createdAt: AFTER, threadParent: 'inc-1', threadRoleLabel: '후속 알림', messageVersion: 'llm-report.v1' }),
          delivery({ jobId: 3, createdAt: BEFORE, threadParent: 'inc-0', threadRoleLabel: '타 인시던트 후속 알림' }),
        )}
      />,
    );
    expect(roleBadges(container)).toEqual(['최초 알림', '후속 알림', '타 인시던트 후속 알림']);
    expect(container.querySelectorAll('.ml-5')).toHaveLength(2);
    expect(screen.queryByText('스레드 기록 없음')).toBeNull();
    // 묶음 머리글은 그대로
    expect(screen.getByText('메시지 3건')).toBeInTheDocument();
  });
});
