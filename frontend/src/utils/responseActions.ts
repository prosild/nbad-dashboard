/**
 * T56 대응 조치 종류(서버 IncidentResponseActionService와 같은 값·순서). 표시 이름은 labels.ts의 responseAction 사전에 둔다.
 */
export const RESPONSE_ACTION_VALUES = [
  'block_ip',
  'isolate_host',
  'lock_account',
  'handover',
  'monitor',
  'none',
  'other',
] as const;

/** 메모가 필수인 종류(왜 조치가 없는지, 무엇을 했는지 적어야 뜻이 통한다) */
export const RESPONSE_ACTION_NOTE_REQUIRED: readonly string[] = ['none', 'other'];

/** 정탐 종결을 막을 때의 안내(서버의 409 RESPONSE_ACTION_REQUIRED 메시지와 같은 글) */
export const RESPONSE_ACTION_REQUIRED_TEXT =
  "정탐으로 종결하려면 대응 조치를 먼저 기록하세요. 조치가 없었다면 '조치 없음'을 기록하세요.";
