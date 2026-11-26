import { describe, expect, it } from 'vitest';
import { LAB_CAPTURE_NOTES, captureInfo, captureText, captureShortName, captureShortNames, shortNameOf } from '../utils/labels';

/** 수집 구간(캡처) 표시 이름(zeek_AD 데이터 계약 v2, Q65) */
describe('캡처 표시 이름', () => {
  it('cic17-<요일>은 "CIC-IDS2017 <요일>요일"이고 툴팁에 설명과 원래 ID가 있다', () => {
    const info = captureInfo('cic17-wed');
    expect(info.text).toBe('CIC-IDS2017 수요일');
    expect(info.known).toBe(true);
    expect(info.tooltip).toContain('공개 데이터셋 CIC-IDS2017의 원본 트래픽(평가용)');
    expect(info.tooltip).toContain('캡처 ID: cic17-wed');
  });

  it('syn1-<요일>은 "CIC <요일>요일 + 합성 패턴"이고 툴팁에 같은 요일이 들어간다', () => {
    const info = captureInfo('syn1-thu');
    expect(info.text).toBe('CIC 목요일 + 합성 패턴');
    // T62: 탐지 저장소 데이터 계약 v2 표의 툴팁을 1절 규칙(링크는 글자만, 출처 앞머리 "탐지 저장소", 끝 마침표)으로 옮긴 글
    expect(info.tooltip).toBe(
      'CIC 목요일 Zeek 로그 사본에 합성 패턴 5종(beacon, 느린 유출, DNS 터널, 측면 이동, 느린 정찰)을 하나씩 코드로 끼워 넣었다. ' +
        '네트워크로 보낸 트래픽이 아니다(탐지 저장소 설계 결정 DD-008).\n캡처 ID: syn1-thu',
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

  it('T66: 실습망 덧붙임 셋(lab-20261126 오탐 규칙 뒤 재실행, lab-20261124·25 유휴(규칙 전))은 인계의 글자 그대로다', () => {
    // 탐지 저장소 data-contract-v2 "실습망 캡처별 표시"(2026-11-23, 2026-11-26 갱신)를 T62 규칙으로 옮긴 글(handoff/T66.md 5절)
    expect(captureText('lab-20261126')).toBe('실습망 2026-11-26 · 오탐 규칙 뒤 재실행');
    expect(captureText('lab-20261124')).toBe('실습망 2026-11-24 · 유휴(규칙 전)');
    expect(captureText('lab-20261125')).toBe('실습망 2026-11-25 · 유휴(규칙 전)');
    expect(LAB_CAPTURE_NOTES['lab-20261126']).toEqual({
      note: '오탐 규칙 뒤 재실행',
      description:
        '브로드캐스트뿐인 창을 조사 큐에서 빼는 규칙(탐지 저장소 설계 결정 DD-021)을 배포한 뒤의 실습망. ' +
        '02:15~04:45 UTC는 유휴(브로드캐스트만, 사건 0건). 04:50~05:00 연결 확인, 05:05~05:20 타깃 정상 배경, ' +
        '05:25~05:40 비커닝, 05:45~06:00 분할 유출(정답 lab-ep-012·013). 연결 확인과 정상 배경 창도 사건이 된다(새 자산의 한계). ' +
        '탐지 저장소 실습망 공격 탐지 결과 "규칙 전과 뒤".',
    });
    expect(LAB_CAPTURE_NOTES['lab-20261124']).toEqual({
      note: '유휴(규칙 전)',
      description:
        '공격이 없는 날. 타깃 VM의 NetBIOS 브로드캐스트 한 건이 5분마다 사건이 됐다(규칙 전, 사건 118건). ' +
        '시연 화면에서는 숨기길 권한다(규칙 전의 오탐 사례는 lab-20261122의 사건으로 충분하다).',
    });
    expect(LAB_CAPTURE_NOTES['lab-20261125']).toEqual({
      note: '유휴(규칙 전)',
      description:
        '공격이 없는 날. 타깃 VM의 NetBIOS 브로드캐스트 한 건이 5분마다 사건이 됐다(규칙 전, 사건 35건). ' +
        '시연 화면에서는 숨기길 권한다(규칙 전의 오탐 사례는 lab-20261122의 사건으로 충분하다).',
    });
    const info = captureInfo('lab-20261126');
    expect(info.known).toBe(true);
    expect(info.tooltip).toContain('탐지 저장소 설계 결정 DD-021');
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
    expect(captureText('lab-20261123')).toBe('실습망 2026-11-23 · 시험(위 캡처의 뒤 시간)');
    expect(LAB_CAPTURE_NOTES['lab-20261122'].description).toBe(
      '세그먼트 센서 확장(DD-020) 뒤의 공격 시험: 느린 스캔, 비커닝, 분할 유출, SMB 공유 탐색, SSH 무차별 대입, DNS 터널' +
        '(빠른 스캔은 lab-20261119에 있다. 정답은 탐지 저장소 configs/ground-truth/lab-attacks.v1.json, 단계 7 진행 기록 열두째 작업). ' +
        '호스트는 Kali(공격자)와 그 별칭(정상 배경용 서버), 타깃 VM과 그 IP 별칭(공유 탐색용)이다' +
        '(주소는 탐지 저장소 데이터 계약 v2 "실습망 캡처별 표시"). 스레드 묶음이 처음 기록된 캡처다.',
    );
    expect(captureInfo('lab-20261119').tooltip).toContain('시험 호스트 구분은 탐지 저장소 2026-11-19 전달 글 5절.');
    expect(captureInfo('lab-20261123').tooltip).toContain('공격 실행 기록은 없다');
    // 화면 번들은 조회자 마스킹을 거치지 않으므로 사전 문구에 IPv4를 두지 않는다.
    // T62: 계약의 마크다운 표기(링크·백틱·굵은 글씨)는 풀고, 문장 끝에 마침표를 붙이고, 옛 이름을 쓰지 않는다.
    for (const id of Object.keys(LAB_CAPTURE_NOTES)) {
      const { note, description } = LAB_CAPTURE_NOTES[id];
      expect(description).not.toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
      expect(description).not.toMatch(/`|\*\*|\]\(/);
      expect(description.endsWith('.')).toBe(true);
      expect(`${note} ${description}`).not.toMatch(/zeek_ad|합성 APT|측면 이동|느린 유출|7종/i);
    }
    for (const id of ['cic17-mon', 'syn1-fri', 'lab-20270102']) {
      expect(captureInfo(id).tooltip).not.toMatch(/zeek_ad/i);
      expect(captureInfo(id).tooltip).not.toMatch(/APT|`|\*\*|\]\(/);
    }
    expect(captureInfo('lab-20261119').tooltip).toContain('배포 VM이 격리 실습망에서 실제로 수집한 트래픽(날짜는 UTC)');
    expect(captureInfo('lab-20261119').tooltip).toContain('정상 배경 35분');
    expect(captureInfo('lab-20261201').tooltip).toContain('시험용 생성기로 만든 패킷');
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
