import { describe, expect, it } from 'vitest';
import { captureInfo, captureText, captureShortName, captureShortNames, shortNameOf } from '../utils/labels';

/** 수집 구간(캡처) 표시 이름(zeek_AD 데이터 계약 v2, Q65) */
describe('캡처 표시 이름', () => {
  it('cic17-<요일>은 "CIC-IDS2017 <요일>요일"이고 툴팁에 설명과 원래 ID가 있다', () => {
    const info = captureInfo('cic17-wed');
    expect(info.text).toBe('CIC-IDS2017 수요일');
    expect(info.known).toBe(true);
    expect(info.tooltip).toContain('공개 데이터셋 CIC-IDS2017의 원본 트래픽(평가용)');
    expect(info.tooltip).toContain('캡처 ID: cic17-wed');
  });

  it('syn1-<요일>은 "CIC <요일>요일 + 합성 APT"이고 툴팁에 같은 요일이 들어간다', () => {
    const info = captureInfo('syn1-thu');
    expect(info.text).toBe('CIC 목요일 + 합성 APT');
    expect(info.tooltip).toContain('CIC 목요일 Zeek 로그 사본에 합성 APT 패턴 5종');
    expect(info.tooltip).toContain('네트워크로 보낸 트래픽이 아니다');
    expect(info.tooltip).toContain('캡처 ID: syn1-thu');
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

  it('실습망 덧붙임 3개와 표에 없는 새 lab-*', () => {
    expect(captureText('lab-20261119')).toBe('실습망 2026-11-19 · Kali 공격 + 정상 배경');
    expect(captureText('lab-20261118')).toBe('실습망 2026-11-18 · 시험');
    expect(captureText('lab-20261201')).toBe('실습망 2026-12-01 · 시험(가짜 패킷)');
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
    expect(captureShortName('syn1-thu')).toBe('CIC+APT 목');
    expect(captureShortName('lab-20261119')).toBe('실습 11-19');
    expect(captureShortName('t24-custom')).toBe('t24-custom');
    expect(captureShortName('cic17-sat')).toBe('cic17-sat');
    expect(captureShortName(null)).toBe('-');
  });

  it('공개 캡처 9개가 서로 다른 짧은 이름이고, 허용 목록 안에서 겹치면 연도를 붙인다', () => {
    const publicIds = ['cic17-tue', 'cic17-wed', 'cic17-thu', 'cic17-fri', 'syn1-tue', 'syn1-wed', 'syn1-thu', 'syn1-fri', 'lab-20261119'];
    const names = captureShortNames(publicIds);
    expect(new Set(publicIds.map((id) => names.get(id))).size).toBe(9);
    expect(names.get('lab-20261119')).toBe('실습 11-19');
    const clash = captureShortNames(['lab-20251119', 'lab-20261119', 'lab-20261120']);
    expect(clash.get('lab-20251119')).toBe('실습 2025-11-19');
    expect(clash.get('lab-20261119')).toBe('실습 2026-11-19');
    expect(clash.get('lab-20261120')).toBe('실습 11-20');
    expect(shortNameOf(clash, 'lab-20261119')).toBe('실습 2026-11-19');
    expect(shortNameOf(clash, 'cic17-wed')).toBe('CIC 수');
  });
});
