export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) {
    return '-';
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
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
  const totalSeconds = Math.round((end - start) / 1000);
  if (totalSeconds < 60) {
    return `${totalSeconds}초`;
  }
  const totalMinutes = Math.floor(totalSeconds / 60);
  const remSeconds = totalSeconds % 60;
  const hours = Math.floor(totalMinutes / 60);
  const remMinutes = totalMinutes % 60;

  if (hours > 0) {
    return remMinutes > 0 ? `${hours}시간 ${remMinutes}분` : `${hours}시간`;
  }
  return remSeconds > 0 ? `${totalMinutes}분 ${remSeconds}초` : `${totalMinutes}분`;
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

export function statusLabel(status: string | null | undefined): string {
  switch ((status ?? '').toLowerCase()) {
    case 'open':
      return '미해결 (open)';
    case 'investigating':
      return '확인 중 (investigating)';
    case 'closed':
      return '종료 (closed)';
    default:
      return status || '-';
  }
}

export function resolutionLabel(resolution: string | null | undefined): string {
  switch ((resolution ?? '').toLowerCase()) {
    case 'true_positive':
      return '실제 공격 (true_positive)';
    case 'false_positive':
      return '오탐 (false_positive)';
    case 'benign':
      return '정상 행위 (benign)';
    default:
      return resolution || '-';
  }
}

export function decisionChoiceLabel(choice: string | null | undefined): string {
  switch ((choice ?? '').toLowerCase()) {
    case 'send':
      return '전송 (send)';
    case 'hold':
      return '보류 (hold)';
    case 'analyst_review':
      return '분석가 검토 (analyst_review)';
    case 'need_more_evidence':
      return '추가 근거 필요 (need_more_evidence)';
    default:
      return choice || '-';
  }
}

export function roleLabel(role: string | null | undefined): string {
  switch ((role ?? '').toUpperCase()) {
    case 'ADMIN':
      return '관리자 (ADMIN)';
    case 'ANALYST':
      return '분석가 (ANALYST)';
    case 'VIEWER':
      return '조회자 (VIEWER)';
    default:
      return role || '-';
  }
}
