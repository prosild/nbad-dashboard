import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CodeLabel, DetectionModelName } from '../components/StatusBadge';
import { formatDateTime, formatDateTimeRange, formatDuration, formatSeconds } from '../utils/format';
import {
  DETECTION_MODEL_INFO,
  LABEL_DICTIONARIES,
  detectionModelInfo,
  labelText,
  lookupLabel,
  policyReasonText,
  reviewReasonText,
} from '../utils/labels';

describe('표시 이름 사전', () => {
  it('핵심 용어의 코드 값을 확정된 표시 이름으로 바꾼다', () => {
    expect(labelText('incidentStatus', 'open')).toBe('신규');
    expect(labelText('incidentStatus', 'investigating')).toBe('분석 중');
    expect(labelText('incidentStatus', 'closed')).toBe('종결');
    expect(labelText('resolution', 'true_positive')).toBe('정탐');
    expect(labelText('resolution', 'false_positive')).toBe('오탐');
    expect(labelText('resolution', 'benign')).toBe('정상');
    expect(labelText('reviewAction', 'confirm')).toBe('승인');
    expect(labelText('reviewAction', 'dismiss')).toBe('오탐 종결');
    expect(labelText('hostRole', 'originator')).toBe('출발지');
    expect(labelText('hostRole', 'responder')).toBe('목적지');
    expect(labelText('reportKind', 'llm')).toBe('AI 작성');
    // T43: 리포트 쪽 낱말을 "템플릿 리포트"로 통일했다
    expect(labelText('reportKind', 'template')).toBe('템플릿 리포트');
    expect(labelText('sendChoice', 'send')).toBe('전송');
    expect(labelText('sendChoice', 'hold')).toBe('보류');
    expect(labelText('sendChoice', 'analyst_review')).toBe('에스컬레이션');
    expect(labelText('sendChoice', 'need_more_evidence')).toBe('증적 보강 필요');
    expect(labelText('decidedBy', 'policy')).toBe('규칙');
    expect(labelText('decidedBy', 'llm')).toBe('AI 리포트');
    expect(labelText('decidedBy', 'decision_model')).toBe('판단 모델');
    expect(labelText('verification', true)).toBe('검증 통과');
    expect(labelText('verification', false)).toBe('검증 실패');
    expect(labelText('userRole', 'VIEWER')).toBe('조회자');
    expect(labelText('userRole', 'ANALYST')).toBe('분석가');
    expect(labelText('userRole', 'ADMIN')).toBe('관리자');
    expect(labelText('assetNameKind', 'kerberos_machine')).toBe('컴퓨터 계정');
    expect(labelText('assetAttribute', 'zeekad_name_kind')).toBe('이름 종류');
    expect(labelText('assetAttribute', 'zeekad_source_log')).toBe('출처 로그');
    expect(labelText('assetAttribute', 'first_seen')).toBe('처음 관측');
    expect(labelText('slackMessageKind', 'incident')).toBe('인시던트 알림');
    expect(labelText('slackDeliveryMode', 'dry_run')).toBe('Dry-run');
    expect(labelText('jobStatus', 'succeeded')).toBe('완료');
    expect(labelText('jobStatus', 'failed')).toBe('실패');
    expect(labelText('auditAction', 'INCIDENT_VIEW_UNMASKED')).toBe('마스킹 없이 인시던트 열람');
    expect(labelText('connState', 'SF')).toBe('정상 연결·종료');
    expect(labelText('priority', 'high')).toBe('High');
    expect(labelText('priority', 'medium')).toBe('Medium');
    expect(labelText('priority', 'low')).toBe('Low');
  });

  it('대소문자가 달라도 찾고 원래 코드 값을 함께 돌려준다', () => {
    expect(lookupLabel('incidentStatus', 'OPEN')).toEqual({ text: '신규', known: true, raw: 'OPEN' });
    expect(lookupLabel('userRole', 'viewer').text).toBe('조회자');
  });

  it('사전에 없는 값은 원래 값을 그대로 돌려주고 미등록으로 표시한다', () => {
    expect(lookupLabel('incidentStatus', 'reopened')).toEqual({ text: 'reopened', known: false, raw: 'reopened' });
    expect(labelText('auditAction', 'NEW_ACTION')).toBe('NEW_ACTION');
    expect(lookupLabel('resolution', null)).toEqual({ text: '-', known: true, raw: '' });
    expect(lookupLabel('jobStatus', 'constructor')).toEqual({ text: 'constructor', known: false, raw: 'constructor' });
  });

  it('미등록 값은 흐린 원문과 "미등록 값" 툴팁으로, 등록 값은 원래 코드를 툴팁으로 보여 준다', () => {
    render(
      <div>
        <CodeLabel dict="incidentStatus" value="reopened" />
        <CodeLabel dict="incidentStatus" value="open" />
      </div>,
    );
    const unknown = screen.getByText('reopened');
    expect(unknown).toHaveAttribute('data-unregistered');
    expect(unknown.getAttribute('title')).toContain('미등록 값: reopened');
    expect(screen.getByText('신규')).toHaveAttribute('title', 'open');
  });

  it('탐지 모델은 zeek_AD 확정 표시 이름·모델 종류·툴팁으로 바꾸고, 모델 버전 식별자는 사전에 넣지 않는다', () => {
    // T17 "사전에 모델 식별자가 없다" 단언은 2026-11-21 결정(탐지 모델 표시 이름 확정)로 뒤집혔다.
    expect(detectionModelInfo('tail_rarity_v2')).toMatchObject({
      text: '기준선 이탈',
      known: true,
      raw: 'tail_rarity_v2',
      kind: '통계 기준선',
      kindAndId: '통계 기준선 · tail_rarity_v2',
    });
    expect(detectionModelInfo('tail_rarity_v2').description).toBe(
      '5분 구간의 통신 특징 42개(연결 수, 목적지 포트 수, 연결 실패 비율, 프로토콜 로그 등) 중 정상 기간에 거의 없던 값이 있는 정도. 가장 드문 특징 하나가 점수다. 정찰·스캔, 인증 실패 반복에 강하다.',
    );
    expect(detectionModelInfo('transformer_v2')).toMatchObject({
      text: '행위 패턴 이탈',
      known: true,
      kind: 'Transformer',
      kindAndId: 'Transformer · transformer_v2',
    });
    expect(detectionModelInfo('transformer_v2').description).toBe(
      '이 자산의 직전 1시간(5분 구간 12개)으로 다음 5분을 예측하고, 실제와 다른 정도. 다른 자산이 아니라 자기 평소 흐름과 비교한다. 이력이 없는 첫 구간에서는 높게 나올 수 있다.',
    );
    expect(detectionModelInfo('tgn_recon')).toMatchObject({
      text: '통신 관계 이상',
      known: true,
      kind: 'TGN(시간 그래프 신경망)',
      kindAndId: 'TGN(시간 그래프 신경망) · tgn_recon',
    });
    expect(detectionModelInfo('tgn_recon').description).toBe(
      '호스트 사이의 연결을 시간 그래프로 학습해, 예상하기 어려운 연결이 나온 정도(구간 안에서 가장 예상 밖인 연결 하나 기준). beacon처럼 양은 적어도 상대가 특이한 통신을 올린다. 이상 호스트와 통신한 정상 호스트도 함께 올라갈 수 있다.',
    );
    expect(detectionModelInfo('transformer_v2').tooltip).toBe(
      `Transformer · transformer_v2\n${DETECTION_MODEL_INFO.transformer_v2.description}`,
    );
    // 표시 이름에 버전을 넣지 않는다.
    for (const name of Object.values(LABEL_DICTIONARIES.detectionModel)) {
      expect(name).not.toMatch(/v\d|_/);
    }
    // 사전에 없는 새 식별자는 미등록 값이다.
    expect(detectionModelInfo('iforest_v1')).toMatchObject({ text: 'iforest_v1', known: false, kind: null });
    expect(detectionModelInfo('iforest_v1').tooltip).toContain('미등록 값: iforest_v1');
    // 모델 버전 값(zeekad-fusion/N)은 그대로 둔다.
    const allKeys = Object.values(LABEL_DICTIONARIES).flatMap((dict) => Object.keys(dict));
    expect(allKeys.some((k) => k.startsWith('zeekad-fusion'))).toBe(false);
  });

  it('표에는 탐지 모델 표시 이름만, 상세에는 "모델 종류 · 식별자"를 data-raw로 함께 보인다', () => {
    const { container } = render(
      <div>
        <div data-testid="table">
          <DetectionModelName id="tgn_recon" />
        </div>
        <div data-testid="detail">
          <DetectionModelName id="transformer_v2" variant="detail" />
        </div>
        <div data-testid="unknown">
          <DetectionModelName id="iforest_v1" />
        </div>
      </div>,
    );
    expect(screen.getByTestId('table')).toHaveTextContent(/^통신 관계 이상$/);
    const tableTitle = screen.getByText('통신 관계 이상').getAttribute('title') ?? '';
    expect(tableTitle).toContain('TGN(시간 그래프 신경망) · tgn_recon');
    expect(tableTitle).toContain('beacon처럼');
    expect(screen.getByTestId('detail')).toHaveTextContent('행위 패턴 이탈');
    expect(screen.getByText('Transformer · transformer_v2')).toHaveAttribute('data-raw');
    expect(screen.getByText('iforest_v1')).toHaveAttribute('data-unregistered');
    expect(container.querySelectorAll('[data-raw]')).toHaveLength(1);
  });

  it('경보 규칙 사유와 에스컬레이션 사유의 조건식을 문장으로 바꾼다', () => {
    expect(policyReasonText('queue_rank 1 <= 5')).toMatchObject({ text: '탐지 순위 5위 이내(현재 1위)', known: true });
    expect(policyReasonText('flagging_models 3 >= 2')).toMatchObject({ text: '2개 이상 모델이 탐지(현재 3개)', known: true });
    expect(policyReasonText('다중 창 탐지')).toMatchObject({ text: '다중 창 탐지', known: true });
    expect(policyReasonText('new_rule_x 3 > 1')).toMatchObject({ text: 'new_rule_x 3 > 1', known: false });
    expect(reviewReasonText('llm=analyst_review, decision_model=analyst_review')).toMatchObject({
      text: 'AI 리포트: 에스컬레이션 · 판단 모델: 에스컬레이션',
      known: true,
    });
    expect(reviewReasonText('경계선 점수 검토')).toMatchObject({ text: '경계선 점수 검토', known: true });
  });
});

describe('시간 표기', () => {
  it('UTC 입력을 방문자 시간대와 상관없이 한국 표준시 YYYY-MM-DD HH:mm:ss로 바꾼다', () => {
    expect(formatDateTime('2017-07-05T13:45:00Z')).toBe('2017-07-05 22:45:00');
    expect(formatDateTime('2026-11-18T15:30:05Z')).toBe('2026-11-19 00:30:05');
    expect(formatDateTime('2017-07-05T11:54:41.816297Z')).toBe('2017-07-05 20:54:41');
    expect(formatDateTime(null)).toBe('-');
    expect(formatDateTime('not-a-date')).toBe('not-a-date');
  });

  it('구간과 기간을 한 형식으로 쓴다', () => {
    expect(formatDateTimeRange('2017-07-05T13:45:00Z', '2017-07-05T14:15:00Z')).toBe('2017-07-05 22:45:00 ~ 23:15:00');
    expect(formatDateTimeRange('2017-07-05T14:45:00Z', '2017-07-05T15:15:00Z')).toBe(
      '2017-07-05 23:45:00 ~ 2017-07-06 00:15:00',
    );
    expect(formatDuration('2026-11-18T01:00:00Z', '2026-11-18T01:45:00Z')).toBe('45분');
    expect(formatDuration('2026-11-18T01:00:00Z', '2026-11-18T02:05:00Z')).toBe('1시간 5분');
    expect(formatSeconds(1.4)).toBe('1.4초');
    expect(formatSeconds(30)).toBe('30초');
    expect(formatSeconds(95)).toBe('1분 35초');
  });
});
