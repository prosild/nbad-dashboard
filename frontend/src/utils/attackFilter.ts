import { lookupLabel } from './labels';

/**
 * 큐 `attack` 조건 값의 정규화(T45). 서버 AttackFilter와 같은 규칙이다:
 * 기법 ID(T + 숫자 4자리, 선택 `.` + 숫자 3자리, 대소문자 무시 → 대문자)를 먼저 보고,
 * 아니면 전술 슬러그(소문자, 공백·밑줄 묶음 → 하이픈 하나, `[a-z0-9]+(-[a-z0-9]+)*`, 길이 2~64)로 읽는다.
 */
const TECHNIQUE = /^[Tt][0-9]{4}(\.[0-9]{3})?$/;
const SEPARATORS = /[ \t\n\v\f\r_]+/g;
const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/** 기법 ID면 대문자 꼴, 아니면 null */
export function attackTechniqueId(raw: string): string | null {
  const value = raw.trim();
  return TECHNIQUE.test(value) ? value.toUpperCase() : null;
}

/** 전술 슬러그 꼴, 만들 수 없으면 null */
export function attackTacticSlug(raw: string): string | null {
  const slug = raw.trim().toLowerCase().replace(SEPARATORS, '-');
  return slug.length >= 2 && slug.length <= 64 && SLUG.test(slug) ? slug : null;
}

/**
 * 칩에 보일 글. 기법 ID 꼴이면 `ATT&CK 기법`과 대문자 ID, 아니면 `ATT&CK 전술`과 표시 이름.
 * 표시 이름은 정규화한 슬러그로 사전(labels.ts attackTactic)을 찾고, 없거나 형식이 틀리면 받은 값 그대로다
 * (형식이 틀린 값은 서버가 400으로 답하고 칩은 남아 지울 수 있다).
 */
export function attackFilterLabel(raw: string): { kind: 'technique' | 'tactic'; label: string; value: string } {
  const technique = attackTechniqueId(raw);
  if (technique) return { kind: 'technique', label: 'ATT&CK 기법', value: technique };
  const slug = attackTacticSlug(raw);
  const found = slug ? lookupLabel('attackTactic', slug) : null;
  return { kind: 'tactic', label: 'ATT&CK 전술', value: found?.known ? found.text : raw };
}
