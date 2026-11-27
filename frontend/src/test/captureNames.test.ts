import { describe, expect, it } from 'vitest';
import { LAB_CAPTURE_NOTES, captureInfo, captureText, captureShortName, captureShortNames, shortNameOf } from '../utils/labels';

/** 수집 구간(캡처) 표시 이름(zeek_AD 데이터 계약 v2, Q65) */
describe('캡처 표시 이름', () => {
  it('cic17-<요일>은 "CIC-IDS2017 <요일>요일"이고 툴팁에 설명과 원래 ID가 있다', () => {
    const info = captureInfo('cic17-wed');
    expect(info.text).toBe('CIC-IDS2017 수요일');
    expect(info.known).toBe(true);
    // T68(A19): 형식별 툴팁은 사용자용 합니다체(사실은 그대로)
    expect(info.tooltip).toContain('공개 데이터셋 CIC-IDS2017의 원본 트래픽입니다(평가용). 모델 학습에는 월요일 정상 트래픽만 썼습니다.');
    expect(info.tooltip).toContain('캡처 ID: cic17-wed');
  });

  it('syn1-<요일>은 "CIC <요일>요일 + 합성 패턴"이고 툴팁에 같은 요일이 들어간다', () => {
    const info = captureInfo('syn1-thu');
    expect(info.text).toBe('CIC 목요일 + 합성 패턴');
    // T62: 탐지 저장소 데이터 계약 v2 표의 툴팁. T68(A19): 사용자용 합니다체, 설계 결정 번호(DD-008)는 뺐다(사실은 그대로)
    expect(info.tooltip).toBe(
      'CIC 목요일 Zeek 로그 사본에 합성 패턴 5종(beacon, 느린 유출, DNS 터널, 측면 이동, 느린 정찰)을 하나씩 코드로 끼워 넣은 데이터입니다. ' +
        '실제 네트워크로 보낸 트래픽이 아닙니다.\n캡처 ID: syn1-thu',
    );
  });

  it('요일 mon~fri를 월~금으로 바꾼다', () => {
    expect(['mon', 'tue', 'wed', 'thu', 'fri'].map((d) => captureText(`cic17-${d}`))).toEqual([
      'CIC-IDS2017 월요일',
      'CIC-IDS2017 화요일',
      'CIC-IDS2017 수요일',
      'CIC-IDS2017 목요일',
      'CIC-IDS2017 금요일',
    ]);
  });

  it('T66·T68: 실습망 덧붙임 셋(lab-20261126 오탐 억제 규칙 뒤 재실행, lab-20261124·25 유휴(억제 규칙 전))은 설계자가 정한 글이다', () => {
    // T66: 탐지 저장소 data-contract-v2 "실습망 캡처별 표시"(2026-11-26 갱신). T68(A20·A19): 덧붙임은 설계자가 고친 이름,
    // 내용은 사용자용 합니다체이고 빠지면 안 되는 사실(설계자 답 M5)을 담는다
    expect(captureText('lab-20261126')).toBe('실습망 2026-11-26 · 오탐 억제 규칙 뒤 재실행');
    expect(captureText('lab-20261124')).toBe('실습망 2026-11-24 · 유휴(억제 규칙 전)');
    expect(captureText('lab-20261125')).toBe('실습망 2026-11-25 · 유휴(억제 규칙 전)');
    expect(LAB_CAPTURE_NOTES['lab-20261126']).toEqual({
      note: '오탐 억제 규칙 뒤 재실행',
      description:
        '오탐 억제 규칙(브로드캐스트만 있는 윈도우를 인시던트에서 빼는 규칙)을 배포한 뒤 공격을 다시 실행한 실습망입니다. ' +
        '02:15~04:45 UTC 유휴 구간은 인시던트 0건이고, 이어서 연결 확인(04:50~05:00)·타깃 정상 배경(05:05~05:20)·' +
        '비커닝(05:25~05:40)·분할 유출(05:45~06:00) 시험을 했습니다. 연결 확인과 정상 배경 윈도우도 인시던트가 됩니다(새 자산이라 생기는 한계).',
    });
    expect(LAB_CAPTURE_NOTES['lab-20261124']).toEqual({
      note: '유휴(억제 규칙 전)',
      description:
        '공격이 없는 날입니다. 오탐 억제 규칙을 배포하기 전이라 타깃 VM의 NetBIOS 브로드캐스트 한 건이 5분마다 인시던트가 되었습니다(인시던트 118건).',
    });
    expect(LAB_CAPTURE_NOTES['lab-20261125']).toEqual({
      note: '유휴(억제 규칙 전)',
      description:
        '공격이 없는 날입니다. 오탐 억제 규칙을 배포하기 전이라 타깃 VM의 NetBIOS 브로드캐스트 한 건이 5분마다 인시던트가 되었습니다(인시던트 35건).',
    });
    const info = captureInfo('lab-20261126');
    expect(info.known).toBe(true);
    expect(info.tooltip).toContain('오탐 억제 규칙(브로드캐스트만 있는 윈도우를 인시던트에서 빼는 규칙)을 배포한 뒤 공격을 다시 실행한');
    expect(info.tooltip).not.toContain('다시 수집한');
    expect(info.tooltip).toContain('캡처 ID: lab-20261126');
    // 사전 키는 여덟(옛 다섯 + 셋)
    expect(Object.keys(LAB_CAPTURE_NOTES).sort()).toEqual([
      'lab-20261118',
      'lab-20261119',
      'lab-20261122',
      'lab-20261123',
      'lab-20261124',
      'lab-20261125',
      'lab-20261126',
      'lab-20261201',
    ]);
  });

  it('실습망 덧붙임 5개와 표에 없는 새 lab-*', () => {
    expect(captureText('lab-20261119')).toBe('실습망 2026-11-19 · Kali 공격 + 정상 배경');
    expect(captureText('lab-20261118')).toBe('실습망 2026-11-18 · 시험');
    expect(captureText('lab-20261201')).toBe('실습망 2026-12-01 · 시험(가짜 패킷)');
    // T39: zeek_AD data-contract-v2 "실습망 캡처별 표시"(2026-11-23). T62: 2026-11-26 이름 변경(6종, 공유 탐색, 분할 유출)
    expect(captureText('lab-20261122')).toBe('실습망 2026-11-22 · Kali 공격 6종 + 타깃 VM');
    // T68(B9): "위 캡처"는 계약 표의 윗줄을 뜻해 목록에서 뜻이 없었다
    expect(captureText('lab-20261123')).toBe('실습망 2026-11-23 · 시험(11-22 시험 직후 유휴)');
    // T68(A19): 경로·설계 결정 번호·정답 ID·작업 기록 이름을 빼고 사실(공격 6종, 빠른 스캔의 자리, 호스트, 첫 스레드 묶음)은 그대로
    expect(LAB_CAPTURE_NOTES['lab-20261122'].description).toBe(
      '세그먼트 센서를 확장한 뒤 실행한 공격 시험 6종(느린 스캔, 비커닝, 분할 유출, SMB 공유 탐색, SSH 무차별 대입, DNS 터널)입니다' +
        '(빠른 스캔은 실습망 2026-11-19에 있습니다). 호스트는 Kali(공격자)와 그 별칭(정상 배경용 서버), 타깃 VM과 그 IP 별칭(공유 탐색용)이고, ' +
        'Slack 알림 묶음(스레드)이 처음 기록된 캡처입니다.',
    );
    expect(captureInfo('lab-20261119').tooltip).toContain('정상 배경 트래픽 35분(월요일 재생 + 합성 정상 클라이언트) 사이에 공격을 섞은 시험(실행 2)입니다.');
    expect(captureInfo('lab-20261123').tooltip).toContain('공격 실행 없음');
    expect(captureInfo('lab-20261123').tooltip).toContain('알림은 모두 실습망 2026-11-22 시험 알림의 스레드 답글입니다.');
    // 화면 번들은 조회자 마스킹을 거치지 않으므로 사전 문구에 IPv4를 두지 않는다.
    // T62: 계약의 마크다운 표기(링크·백틱·굵은 글씨)는 풀고, 문장 끝에 마침표를 붙이고, 옛 이름을 쓰지 않는다.
    for (const id of Object.keys(LAB_CAPTURE_NOTES)) {
      const { note, description } = LAB_CAPTURE_NOTES[id];
      expect(description).not.toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
      expect(description).not.toMatch(/`|\*\*|\]\(/);
      expect(description.endsWith('.')).toBe(true);
      expect(`${note} ${description}`).not.toMatch(/zeek_ad|합성 APT|측면 이동|느린 유출|7종/i);
      // T68(A19): 사용자용 글. 저장소 경로·설계 결정 번호·정답 ID·작업 기록 이름·내부 권고·옛 말과 캡처 ID를 두지 않고 합니다체로 끝난다
      expect(`${note} ${description}`).not.toMatch(/DD-\d|configs\/|정답|진행 기록|전달 글|권한다|조사 큐|사건|창을|창도|lab-\d/);
      expect(description).toMatch(/니다(\([^)]*\))?\.$/);
    }
    for (const id of ['cic17-mon', 'syn1-fri', 'lab-20270102']) {
      expect(captureInfo(id).tooltip).not.toMatch(/zeek_ad/i);
      expect(captureInfo(id).tooltip).not.toMatch(/APT|`|\*\*|\]\(/);
    }
    expect(captureInfo('lab-20261119').tooltip).toContain('탐지 파이프라인 VM이 격리 실습망에서 실제로 수집한 트래픽입니다. 날짜는 UTC이고 하루 단위로 처리합니다.');
    expect(captureInfo('lab-20261119').tooltip).toContain('정상 배경 트래픽 35분');
    expect(captureInfo('lab-20261201').tooltip).toContain('시험용 생성기로 만든 가짜 패킷입니다(날짜도 가짜).');
    const fresh = captureInfo('lab-20270102');
    expect(fresh.text).toBe('실습망 2027-01-02');
    expect(fresh.known).toBe(true);
    expect(fresh.tooltip).toContain('캡처 ID: lab-20270102');
  });

  it('규칙에 맞지 않는 ID는 원래 ID 그대로, 미등록 값', () => {
    for (const id of ['cic17-sat', 'syn2-mon', 'lab-2026111', 'lab-fusion-v2', 'cic17-*']) {
      const info = captureInfo(id);
      expect(info.text).toBe(id);
      expect(info.known).toBe(false);
      expect(info.tooltip).toContain('미등록 값');
    }
    expect(captureInfo(null).text).toBe('-');
  });
});

describe('짧은 수집원 이름(T24)', () => {
  it('세 계열과 규칙 밖', () => {
    expect(captureShortName('cic17-wed')).toBe('CIC 수');
    expect(captureShortName('cic17-mon')).toBe('CIC 월');
    expect(captureShortName('syn1-thu')).toBe('CIC+합성 목');
    expect(captureShortName('lab-20261119')).toBe('실습 11-19');
    expect(captureShortName('t24-custom')).toBe('t24-custom');
    expect(captureShortName('cic17-sat')).toBe('cic17-sat');
    expect(captureShortName(null)).toBe('-');
  });

  it('공개 캡처 11개가 서로 다른 짧은 이름이고, 허용 목록 안에서 겹치면 연도를 붙인다', () => {
    // T66: 공개 캡처에 lab-20261126을 더했다(10 → 11)
    const publicIds = ['cic17-tue', 'cic17-wed', 'cic17-thu', 'cic17-fri', 'syn1-tue', 'syn1-wed', 'syn1-thu', 'syn1-fri', 'lab-20261119', 'lab-20261122', 'lab-20261126'];
    const names = captureShortNames(publicIds);
    expect(new Set(publicIds.map((id) => names.get(id))).size).toBe(11);
    expect(names.get('lab-20261119')).toBe('실습 11-19');
    expect(names.get('lab-20261122')).toBe('실습 11-22');
    expect(names.get('lab-20261126')).toBe('실습 11-26');
    const clash = captureShortNames(['lab-20251119', 'lab-20261119', 'lab-20261120']);
    expect(clash.get('lab-20251119')).toBe('실습 2025-11-19');
    expect(clash.get('lab-20261119')).toBe('실습 2026-11-19');
    expect(clash.get('lab-20261120')).toBe('실습 11-20');
    expect(shortNameOf(clash, 'lab-20261119')).toBe('실습 2026-11-19');
    expect(shortNameOf(clash, 'cic17-wed')).toBe('CIC 수');
  });
});
