/**
 * Slack 알림 기록(`payloadJson`)을 화면에 보일 글로 푼다(T38).
 *
 * zeek_AD가 기록한 글을 고치거나 요약하지 않는다. 하는 일은 셋뿐이다.
 * - 링크·채널·사용자 토큰과 맨 URL을 지운다(링크 글만 남긴다).
 * - mrkdwn 굵게·기울임 기호를 푼다(낱말 경계의 짝만).
 * - `&gt;`·`&lt;`·`&amp;` 엔티티를 글자로 푼다.
 * 결과는 React 텍스트 노드로만 그린다. 원본 JSON 키, 채널, URL은 결과에 들어가지 않는다.
 */

export interface SlackSegment {
  text: string;
  bold?: boolean;
  italic?: boolean;
}

/** 한 줄 = 조각 목록 */
export type SlackLine = SlackSegment[];

export type SlackBlockView =
  | { kind: 'header'; lines: SlackLine[] }
  | { kind: 'section'; lines: SlackLine[] }
  | { kind: 'fields'; fields: { name: SlackLine[]; value: SlackLine[] }[] }
  | { kind: 'context'; lines: SlackLine[] }
  | { kind: 'buttons'; names: string[] };

export interface SlackMessageView {
  /** 알림 본문(`text`). 없거나 글이 아니면 null */
  body: SlackLine[] | null;
  /** 알림 전문(`blocks`). 그릴 글이 하나도 없으면(버튼 이름만 있어도) null */
  blocks: SlackBlockView[] | null;
}

// 1. Slack 토큰
const LINK_TOKEN = /<(?:https?:\/\/|mailto:)[^>|]*(?:\|([^>]*))?>/gi;
const MENTION_TOKEN = /<[#@!][^>]*>/g;
// 2. 맨 URL(공백·줄 끝 전까지. 엔티티 `&gt;`·`&lt;` 앞에서 멈춘다)
const BARE_URL = /https?:\/\/(?:(?!&gt;|&lt;)\S)+/gi;
// URL을 지운 뒤 `이름:` 꼴만 남은 줄
const LABEL_ONLY = /^[^:\s][^:]{0,30}:$/;

// 3. 굵게·기울임: 여는 기호 앞은 줄 처음·공백·여는 괄호, 닫는 기호 뒤는 줄 끝·공백·문장 부호
const OPEN_BEFORE = String.raw`(^|[\s(\[{"'“‘])`;
const CLOSE_AFTER = String.raw`(?=$|[\s.,!?;:)\]}"'”’…·])`;
const BOLD = new RegExp(`${OPEN_BEFORE}\\*(\\S(?:[^*\\n]*?\\S)?)\\*${CLOSE_AFTER}`, 'g');
const ITALIC = new RegExp(`${OPEN_BEFORE}_(\\S(?:[^_\\n]*?\\S)?)_${CLOSE_AFTER}`, 'g');

function decodeEntities(s: string): string {
  // 4. 마지막에 푼다. `&amp;`를 맨 뒤에 풀어 `&amp;gt;`가 `>`로 두 번 풀리지 않게 한다.
  return s.replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
}

function splitStyle(text: string, re: RegExp, style: 'bold' | 'italic', base: SlackSegment): SlackSegment[] {
  const out: SlackSegment[] = [];
  let last = 0;
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const start = m.index + m[1].length;
    if (start > last) out.push({ ...base, text: text.slice(last, start) });
    out.push({ ...base, [style]: true, text: m[2] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ ...base, text: text.slice(last) });
  return out;
}

/** 한 줄의 굵게·기울임을 풀고 엔티티를 글자로 바꾼다. */
function styleLine(line: string): SlackLine {
  const segs = splitStyle(line, BOLD, 'bold', { text: '' }).flatMap((seg) =>
    splitStyle(seg.text, ITALIC, 'italic', { text: '', ...(seg.bold ? { bold: true } : {}) }),
  );
  return segs.map((seg) => ({ ...seg, text: decodeEntities(seg.text) })).filter((seg) => seg.text !== '');
}

/** mrkdwn·plain_text 글 하나를 그릴 줄 목록으로 푼다. 그릴 글이 없으면 빈 배열. */
export function slackTextLines(raw: string): SlackLine[] {
  const lines: SlackLine[] = [];
  for (const original of raw.split(/\r?\n/)) {
    let line = original
      .replace(LINK_TOKEN, (_all, label: string | undefined) => label ?? '')
      .replace(MENTION_TOKEN, '')
      .replace(BARE_URL, '');
    if (line !== original) {
      line = line.replace(/[ \t]{2,}/g, ' ').trim();
      // 지운 뒤 빈 줄이나 `사건:` 같은 이름만 남은 줄은 그리지 않는다
      if (line === '' || LABEL_ONLY.test(line)) continue;
    }
    if (line.trim() === '') continue;
    const styled = styleLine(line);
    if (styled.length > 0) lines.push(styled);
  }
  return lines;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** `{ text: "…" }` 꼴 글 객체의 글 */
function textOf(obj: unknown): string | null {
  return isRecord(obj) && typeof obj.text === 'string' ? obj.text : null;
}

function plainText(lines: SlackLine[]): string {
  return lines.map((l) => l.map((s) => s.text).join('')).join(' ');
}

function blockView(block: unknown): SlackBlockView[] {
  if (!isRecord(block)) return [];
  const views: SlackBlockView[] = [];
  switch (block.type) {
    case 'header': {
      const t = textOf(block.text);
      const lines = t === null ? [] : slackTextLines(t);
      if (lines.length > 0) views.push({ kind: 'header', lines });
      break;
    }
    case 'section': {
      // accessory는 건너뛴다
      const t = textOf(block.text);
      const lines = t === null ? [] : slackTextLines(t);
      if (lines.length > 0) views.push({ kind: 'section', lines });
      if (Array.isArray(block.fields)) {
        const fields = block.fields
          .map((f) => {
            const ft = textOf(f);
            if (ft === null) return null;
            const fl = slackTextLines(ft);
            if (fl.length === 0) return null;
            return fl.length === 1 ? { name: [], value: fl } : { name: [fl[0]], value: fl.slice(1) };
          })
          .filter((f): f is { name: SlackLine[]; value: SlackLine[] } => f !== null);
        if (fields.length > 0) views.push({ kind: 'fields', fields });
      }
      break;
    }
    case 'context': {
      if (!Array.isArray(block.elements)) break;
      const lines = block.elements
        .filter((el) => isRecord(el) && (el.type === 'mrkdwn' || el.type === 'plain_text'))
        .flatMap((el) => {
          const t = textOf(el);
          return t === null ? [] : slackTextLines(t);
        });
      if (lines.length > 0) views.push({ kind: 'context', lines });
      break;
    }
    case 'actions': {
      if (!Array.isArray(block.elements)) break;
      // 버튼 이름만. URL은 읽지 않는다.
      const names = block.elements
        .filter((el) => isRecord(el) && el.type === 'button')
        .map((el) => {
          const t = textOf((el as Record<string, unknown>).text);
          return t === null ? '' : plainText(slackTextLines(t));
        })
        .filter((n) => n !== '');
      if (names.length > 0) views.push({ kind: 'buttons', names });
      break;
    }
    default:
      break;
  }
  return views;
}

/** `payloadJson`을 본문과 전문으로 푼다. 파싱에 실패하면 둘 다 null. */
export function parseSlackMessage(payloadJson: string | null | undefined): SlackMessageView {
  const empty: SlackMessageView = { body: null, blocks: null };
  if (typeof payloadJson !== 'string' || payloadJson === '') return empty;
  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    return empty;
  }
  if (!isRecord(payload)) return empty;

  const bodyLines = typeof payload.text === 'string' ? slackTextLines(payload.text) : [];
  const blocks = Array.isArray(payload.blocks) ? payload.blocks.flatMap(blockView) : [];
  const hasText = blocks.some((b) => b.kind !== 'buttons');
  return {
    body: bodyLines.length > 0 ? bodyLines : null,
    blocks: hasText ? blocks : null,
  };
}
