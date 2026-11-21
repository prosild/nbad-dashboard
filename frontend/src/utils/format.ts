/** 화면의 모든 날짜·시각은 방문자 브라우저 시간대와 상관없이 한국 표준시로 보여 준다. */
export const DISPLAY_TIME_ZONE = 'Asia/Seoul';
export const DISPLAY_TIME_ZONE_LABEL = 'KST';

const DATE_TIME_FORMATTER = new Intl.DateTimeFormat('en-CA', {
  timeZone: DISPLAY_TIME_ZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/** 날짜·시각 표준 형식: `YYYY-MM-DD HH:mm:ss` (한국 표준시). 값이 없으면 '-', 해석할 수 없으면 원래 값. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) {
    return '-';
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const parts: Record<string, string> = {};
  for (const part of DATE_TIME_FORMATTER.formatToParts(date)) {
    parts[part.type] = part.value;
  }
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

/** 시작~끝 구간: 같은 날이면 끝은 시각만 쓴다. 예: `2017-07-05 22:45:00 ~ 23:15:00` */
export function formatDateTimeRange(startIso: string | null | undefined, endIso: string | null | undefined): string {
  const start = formatDateTime(startIso);
  const end = formatDateTime(endIso);
  if (start === '-' && end === '-') {
    return '-';
  }
  if (start.length === 19 && end.length === 19 && start.slice(0, 10) === end.slice(0, 10)) {
    return `${start} ~ ${end.slice(11)}`;
  }
  return `${start} ~ ${end}`;
}

/** 기간(지속 시간) 표준 형식: `45분`, `1시간 5분`, `30초`, `1.4초`(1분 미만 소수). */
export function formatSeconds(totalSecondsInput: number | null | undefined): string {
  if (totalSecondsInput === null || totalSecondsInput === undefined || !Number.isFinite(totalSecondsInput) || totalSecondsInput < 0) {
    return '-';
  }
  if (totalSecondsInput < 60) {
    const rounded = Math.round(totalSecondsInput * 10) / 10;
    return Number.isInteger(rounded) ? `${rounded}초` : `${rounded.toFixed(1)}초`;
  }
  const totalSeconds = Math.round(totalSecondsInput);
  const totalMinutes = Math.floor(totalSeconds / 60);
  const remSeconds = totalSeconds % 60;
  const hours = Math.floor(totalMinutes / 60);
  const remMinutes = totalMinutes % 60;

  if (hours > 0) {
    return remMinutes > 0 ? `${hours}시간 ${remMinutes}분` : `${hours}시간`;
  }
  return remSeconds > 0 ? `${totalMinutes}분 ${remSeconds}초` : `${totalMinutes}분`;
}

export function formatDuration(startIso: string | null | undefined, endIso: string | null | undefined): string {
  if (!startIso || !endIso) {
    return '-';
  }
  const start = new Date(startIso).getTime();
  const end = new Date(endIso).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return '-';
  }
  return formatSeconds(Math.round((end - start) / 1000));
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) {
    return '-';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIdx]}`;
}

/** 숫자 표준 형식: 천 단위 구분. */
export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '-';
  }
  return new Intl.NumberFormat('ko-KR').format(value);
}

export function formatPercent(ratio: number | null | undefined, decimals = 1): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) {
    return '-';
  }
  return `${(ratio * 100).toFixed(decimals)}%`;
}

/**
 * 세션(주요 세션 표) 지속 시간(초 단위 값): 1ms 미만은 "1ms 미만", 1초 미만은 정수 ms,
 * 1분 미만은 소수 한 자리 초, 그 이상은 "m분 s초"(T19 L6).
 */
export function formatSessionDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '-';
  }
  if (seconds < 0.001) {
    return '1ms 미만';
  }
  if (seconds < 1) {
    return `${Math.floor(seconds * 1000)}ms`;
  }
  if (seconds < 60) {
    return `${(Math.floor(seconds * 10) / 10).toFixed(1)}초`;
  }
  const total = Math.floor(seconds);
  return `${Math.floor(total / 60)}분 ${total % 60}초`;
}

/**
 * 상대 시각(T23 탐지 시각): 기준 시각(서버가 준 anchor)에서 얼마 전인지. 브라우저 시각은 쓰지 않는다.
 * 1분 미만 "방금", 1시간 미만 "N분 전", 1일 미만 "N시간 전", 그 밖 "N일 전". 기준보다 늦으면 "방금".
 */
export function formatRelativeTo(iso: string | null | undefined, referenceIso: string | null | undefined): string {
  if (!iso || !referenceIso) {
    return '-';
  }
  const t = new Date(iso).getTime();
  const ref = new Date(referenceIso).getTime();
  if (Number.isNaN(t) || Number.isNaN(ref)) {
    return '-';
  }
  const diffSec = Math.floor((ref - t) / 1000);
  if (diffSec < 60) {
    return '방금';
  }
  const minutes = Math.floor(diffSec / 60);
  if (minutes < 60) {
    return `${minutes}분 전`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}시간 전`;
  }
  return `${formatNumber(Math.floor(hours / 24))}일 전`;
}
