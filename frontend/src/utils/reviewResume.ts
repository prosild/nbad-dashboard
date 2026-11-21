import { useEffect, useState } from 'react';

/**
 * 에스컬레이션 결정과 인시던트 상태의 관계(T21, zeek_AD 계약 `dashboard.decide_review`).
 * 결정은 기록만 되고, 파이프라인이 멈춘 흐름을 재개하면서 상태를 바꾼다: 승인 → 분석 중, 오탐 종결 → 종결(오탐).
 * 반영 상태 이름은 서버 라벨(resumeStatusLabel: 반영 중 / 반영됨 / 반영 실패(관리자 확인 필요))을 그대로 쓴다.
 * 반영 지연은 서버 라벨이 아니라 화면이 결정 시각으로 계산하는 보조 표시다. 시간 약속("30초", "곧")은 쓰지 않는다.
 */

/** 두 결정(에스컬레이션 결정·상태 변경)의 관계 안내. 조치 패널과 에스컬레이션 화면이 같이 쓴다. */
export const REVIEW_STATUS_RELATION =
  '에스컬레이션 결정은 파이프라인이 반영하면 인시던트 상태에 적용됩니다. 승인 → 분석 중, 오탐 종결 → 종결(오탐).';

/** 결정 뒤 이 시간이 지나도 반영 중이면 반영 지연으로 본다. */
export const RESUME_DELAY_MINUTES = 10;

/** 반영 지연 안내 */
export const RESUME_DELAYED_TEXT =
  '반영이 늦어지고 있습니다. 파이프라인 상태를 확인하거나 상태 변경으로 직접 처리하세요.';

/** 반영 실패 안내 */
export const RESUME_FAILED_TEXT = '자동 반영에 실패했습니다. 관리자에게 알리거나 상태 변경으로 직접 처리하세요.';

/** 오탐 종결이 반영 실패·지연일 때 상태 변경 폼 안내(판정 오탐 미리 채움) */
export const RESUME_MANUAL_CLOSE_TEXT =
  '오탐 종결 결정이 자동 반영되지 않았습니다. 상태 변경으로 직접 종결하세요. 판정을 오탐으로 미리 채웠습니다.';

/** 반영 중(지연 전)에 상태 변경 폼 위에 두는 안내. 폼은 막지 않는다. */
export const RESUME_PENDING_FORM_NOTE =
  '에스컬레이션 결정이 아직 반영 중입니다. 지금 상태를 직접 바꾸면 반영 때 그 단계는 건너뜁니다. 결정과 다른 판정으로 종결하면 둘이 어긋난 채 남습니다.';

/** 반영 지연 표시 이름(서버 라벨 옆 보조 표시) */
export const RESUME_DELAYED_LABEL = '반영 지연';

export type ResumePhase = 'none' | 'pending' | 'delayed' | 'resumed' | 'failed';

export interface ResumeInput {
  reviewAction: string | null | undefined;
  decidedAt: string | null | undefined;
  resumedAt: string | null | undefined;
  resumeFailed: boolean | null | undefined;
}

/**
 * 결정의 반영 단계. 서버 라벨과 같은 순서로 판단한다(실패 → 반영됨 → 반영 중).
 * 반영 중이면서 결정 시각에서 RESUME_DELAY_MINUTES분이 지났으면 delayed다(결정 시각이 없거나 읽을 수 없으면 pending).
 */
export function resumePhase(input: ResumeInput, nowMs: number): ResumePhase {
  if (!input.reviewAction || input.reviewAction.trim() === '') return 'none';
  if (input.resumeFailed === true) return 'failed';
  if (input.resumedAt) return 'resumed';
  const decided = input.decidedAt ? new Date(input.decidedAt).getTime() : Number.NaN;
  if (!Number.isNaN(decided) && nowMs - decided >= RESUME_DELAY_MINUTES * 60_000) return 'delayed';
  return 'pending';
}

/** 자동 반영이 안 된 단계(직접 처리 안내·오탐 미리 채움 대상) */
export function isResumeStuck(phase: ResumePhase): boolean {
  return phase === 'failed' || phase === 'delayed';
}

/** 반영 지연 판정용 현재 시각. 화면을 열어 둔 채 시간이 지나도 지연 표시가 나오도록 30초마다 갱신한다. */
export function useNowMs(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}
