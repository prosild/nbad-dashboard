import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { DetailHeader } from '../components/incident/DetailHeader';
import { ReportSection, ReportVerificationProblems } from '../components/incident/ReportSection';
import { ToastProvider } from '../components/ToastContext';
import { SignalChips } from '../pages/IncidentQueuePage';
import type { IncidentDetailView, ReportView } from '../types/api';
import { templateReplacedText } from '../utils/factLabels';
import { REPORT_KIND_DESCRIPTION, VERIFICATION_DESCRIPTION } from '../utils/labels';
import { baseDetail, queueItem } from './detailFixture';
import { unified } from './fakeQueueServer';

/**
 * T43 템플릿 리포트 표시(설계자 답 1, 3절). zeek_AD 계약 v2: kind `llm` = LLM 리포트가 검증 통과,
 * `template` = 검증 실패·호출 실패로 규칙 템플릿으로 바꿈(검증 false면 kind는 template).
 * 화면에 보이는 리포트가 무엇인지 먼저 말하고, 검증 실패·호출 실패는 AI 리포트를 쓰지 못한 이유로 말한다.
 */

const TEMPLATE_TITLE = '템플릿 리포트: AI 리포트를 쓰지 못해 사실만 나열한 템플릿 리포트로 대체됐습니다';

function chips(kind: string | null, opts: { reportJobId?: number | null; verified?: boolean | null } = {}) {
  const item = unified(
    queueItem({
      zeekadReportJobId: opts.reportJobId === undefined ? 41 : opts.reportJobId,
      zeekadReportKind: kind,
      zeekadVerificationPassed: opts.verified === undefined ? null : opts.verified,
      hasReport: opts.reportJobId !== null,
    }),
  );
  return render(<SignalChips item={item} />);
}

describe('T43 목록 리포트 칩', () => {
  it('llm: 문서 아이콘, 이름·툴팁 "AI 작성 리포트"', () => {
    const { container } = chips('llm', { verified: true });
    const chip = screen.getByRole('img', { name: 'AI 작성 리포트 있음' });
    expect(chip).toHaveAttribute('title', 'AI 작성 리포트 · 리포트 작업 41');
    expect(chip).toHaveAttribute('data-report-kind', 'llm');
    expect(chip.querySelector('svg')?.getAttribute('class')).toContain('lucide-file-text');
    expect(container.querySelectorAll('[role="img"]')).toHaveLength(3);
  });

  it('template: 다른 아이콘·주의 색조로 그리고 이름·툴팁이 템플릿 대체를 말한다(빨강 없음)', () => {
    const { container } = chips('template', { verified: false });
    const chip = screen.getByRole('img', { name: TEMPLATE_TITLE });
    expect(chip).toHaveAttribute('title', `${TEMPLATE_TITLE} · 리포트 작업 41`);
    expect(chip).toHaveAttribute('data-report-kind', 'template');
    const icon = chip.querySelector('svg')?.getAttribute('class') ?? '';
    expect(icon).toContain('lucide-clipboard-list');
    expect(icon).not.toContain('lucide-file-text');
    expect(chip.className).toContain('text-amber-200');
    expect(chip.className).not.toMatch(/rose|red/);
    // 칩 자리 수 셋은 그대로
    expect(container.firstElementChild?.children).toHaveLength(3);
  });

  it('검증 칩 실패의 뜻: 템플릿으로 대체(사유는 단정하지 않음), 통과는 그대로', () => {
    chips('template', { verified: false });
    const fail = screen.getByRole('img', { name: VERIFICATION_DESCRIPTION.failedQueue });
    expect(fail).toHaveAttribute('title', 'AI 리포트를 쓰지 못함: 검증 실패 또는 호출 실패로 템플릿 리포트로 대체됐습니다. 사유는 상세에서 봅니다');
    expect(VERIFICATION_DESCRIPTION.failedQueue).not.toContain('맞지 않는 내용');
  });

  it('검증 칩 통과는 그대로', () => {
    chips('llm', { verified: true });
    expect(screen.getByRole('img', { name: VERIFICATION_DESCRIPTION.passed })).toBeInTheDocument();
  });

  it('사전에 없는 값: 지금 모양(문서 아이콘)이고 원문이 툴팁에 있다', () => {
    chips('hybrid', { verified: null });
    const chip = screen.getByRole('img', { name: 'AI 분석 리포트 있음: hybrid' });
    expect(chip.getAttribute('title')).toContain('hybrid 리포트 · 리포트 작업 41');
    expect(chip.getAttribute('title')).toContain('미등록 값: hybrid');
    expect(chip.querySelector('svg')?.getAttribute('class')).toContain('lucide-file-text');
    expect(chip).not.toHaveAttribute('data-report-kind');
  });

  it('리포트 없음은 그대로', () => {
    chips(null, { reportJobId: null });
    expect(screen.getByRole('img', { name: '리포트 없음' })).toHaveAttribute('title', '리포트 없음');
  });
});

/* ───────────────────────── 상세 ───────────────────────── */

function report(over: Partial<ReportView>): ReportView {
  return { ...baseDetail().report, ...over };
}

function detailWith(over: Partial<ReportView>): IncidentDetailView {
  const d = baseDetail();
  return { ...d, report: { ...d.report, ...over } };
}

function renderHeader(over: Partial<ReportView>) {
  render(
    <MemoryRouter>
      <ToastProvider>
        <DetailHeader detail={detailWith(over)} />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('T43 상세 머리줄 "AI 리포트" 칸', () => {
  it('템플릿이면 "검증 실패" 대신 "템플릿 대체"(주의 색조), 툴팁·읽기 글에 대체 사실과 사유', () => {
    renderHeader({ reportKind: 'template', verificationPassed: false, verificationReason: 'call: ClientError' });
    const badge = screen.getByText('템플릿 대체');
    const img = badge.closest('[role="img"]') as HTMLElement;
    expect(img).toHaveAttribute('title', 'AI 리포트를 쓰지 못해 템플릿 리포트로 대체됐습니다. 사유: LLM 호출 실패: ClientError');
    expect(img.getAttribute('aria-label')).toBe('템플릿 대체: AI 리포트를 쓰지 못해 템플릿 리포트로 대체됐습니다. 사유: LLM 호출 실패: ClientError');
    expect(screen.queryByText('검증 실패')).toBeNull();
  });

  it('템플릿·사유 verification도 사유를 한국어로', () => {
    renderHeader({ reportKind: 'template', verificationPassed: false, verificationReason: 'verification' });
    expect(screen.getByText('템플릿 대체').closest('[role="img"]')).toHaveAttribute(
      'title',
      'AI 리포트를 쓰지 못해 템플릿 리포트로 대체됐습니다. 사유: 리포트 내용이 근거와 맞지 않음(숫자·가명·ATT&CK ID)',
    );
  });

  it('AI 작성·검증 통과는 그대로("검증 통과"만)', () => {
    renderHeader({ reportKind: 'llm', verificationPassed: true });
    expect(screen.getByText('검증 통과')).toBeInTheDocument();
    expect(screen.queryByText('AI 작성')).toBeNull();
    expect(screen.queryByText('템플릿 대체')).toBeNull();
  });

  it('계약에 없는 조합은 지어내지 않고 kind 표지와 검증 표지를 함께 보인다', () => {
    const cases: [Partial<ReportView>, string, string | null][] = [
      [{ reportKind: 'llm', verificationPassed: false }, 'AI 작성', '검증 실패'],
      [{ reportKind: 'template', verificationPassed: true }, '템플릿 리포트', '검증 통과'],
      [{ reportKind: 'template', verificationPassed: null }, '템플릿 리포트', null],
    ];
    for (const [over, kind, verification] of cases) {
      const { unmount } = render(
        <MemoryRouter>
          <ToastProvider>
            <DetailHeader detail={detailWith(over)} />
          </ToastProvider>
        </MemoryRouter>,
      );
      expect(screen.getByText(kind)).toBeInTheDocument();
      if (verification) expect(screen.getByText(verification)).toBeInTheDocument();
      expect(screen.queryByText('템플릿 대체')).toBeNull();
      unmount();
    }
  });
});

describe('T43 AI 리포트 탭', () => {
  it('사유 verification: 맨 위 표지 "템플릿 리포트" 하나와 무엇이 보이는지 한 줄', () => {
    render(<ReportSection report={report({ reportKind: 'template', verificationPassed: false, verificationReason: 'verification' })} />);
    expect(screen.getByText('템플릿 리포트')).toBeInTheDocument();
    expect(screen.queryByText('검증 실패')).toBeNull();
    expect(screen.queryByText('AI 작성')).toBeNull();
    expect(screen.getByTestId('template-report-note')).toHaveTextContent(
      'AI가 쓴 리포트가 검증(글 속 숫자·가명·ATT&CK ID를 근거 사실과 대조)에서 걸려 쓰지 않았습니다. 아래는 사실만 나열한 템플릿 리포트입니다.',
    );
  });

  it('사유 call: …: 호출 실패로 쓰지 못함', () => {
    render(<ReportSection report={report({ reportKind: 'template', verificationPassed: false, verificationReason: 'call: ClientError' })} />);
    expect(screen.getByTestId('template-report-note')).toHaveTextContent(
      'AI 호출이 실패해(LLM 호출 실패: ClientError) AI 리포트를 쓰지 못했습니다. 아래는 사실만 나열한 템플릿 리포트입니다.',
    );
  });

  it('사유가 그 밖·없음이면 대체됐다는 것까지만', () => {
    for (const reason of ['brand_new', null]) {
      const { unmount } = render(<ReportSection report={report({ reportKind: 'template', verificationPassed: false, verificationReason: reason })} />);
      expect(screen.getByTestId('template-report-note')).toHaveTextContent(
        'AI 리포트를 쓰지 못해 템플릿 리포트로 대체됐습니다. 아래는 사실만 나열한 템플릿 리포트입니다.',
      );
      unmount();
    }
    expect(templateReplacedText('call')).toBe('AI 호출이 실패해(LLM 호출 실패) AI 리포트를 쓰지 못했습니다. 아래는 사실만 나열한 템플릿 리포트입니다.');
  });

  it('주황 상자 제목: 쓰지 않은 AI 리포트의 이유, 문제 항목이 그 글의 것임을 적는다(항목 문장은 그대로)', () => {
    render(
      <ReportVerificationProblems
        report={report({
          reportKind: 'template',
          verificationPassed: false,
          verificationReason: 'verification',
          verificationProblemItems: [{ kind: 'attack_id_not_in_candidates', value: 'T1046' }],
        })}
      />,
    );
    expect(screen.getByText(/AI 리포트를 쓰지 않은 이유:/)).toHaveTextContent('AI 리포트를 쓰지 않은 이유: 리포트 내용이 근거와 맞지 않음(숫자·가명·ATT&CK ID)');
    expect(screen.getByText('아래 항목은 쓰지 않은 AI 리포트 글의 것입니다. 화면의 템플릿 리포트 내용이 아닙니다.')).toBeInTheDocument();
    expect(screen.getByText(/리포트가 인용한 ATT&CK ID 가운데 후보 목록에 없는 ID: "T1046"/)).toBeInTheDocument();
    expect(screen.queryByText(/검증 실패 사유/)).toBeNull();
  });

  it('계약에 없는 조합(llm + 검증 실패)은 상자 제목을 지금처럼 "검증 실패 사유"로 둔다', () => {
    render(<ReportVerificationProblems report={report({ reportKind: 'llm', verificationPassed: false, verificationReason: 'verification' })} />);
    expect(screen.getByText(/검증 실패 사유:/)).toBeInTheDocument();
    expect(screen.queryByText(/쓰지 않은 이유/)).toBeNull();
  });

  it('AI 작성·검증 통과는 그대로("AI 작성" + "검증 통과", 한 줄 안내 없음)', () => {
    render(<ReportSection report={report({ reportKind: 'llm', verificationPassed: true })} />);
    const top = screen.getByText('AI 작성').closest('div') as HTMLElement;
    expect(within(top.parentElement as HTMLElement).getByText('검증 통과')).toBeInTheDocument();
    expect(screen.queryByTestId('template-report-note')).toBeNull();
    expect(screen.queryByText('템플릿 리포트')).toBeNull();
  });

  it('"AI 작성 오류" 상자는 그대로', () => {
    render(<ReportSection report={report({ reportKind: 'template', verificationPassed: false, verificationReason: 'call', llmError: 'ClientError' })} />);
    expect(screen.getByText('AI 작성 오류:')).toBeInTheDocument();
  });

  it('REPORT_KIND_DESCRIPTION 낱말', () => {
    expect(REPORT_KIND_DESCRIPTION.template).toBe(TEMPLATE_TITLE);
  });
});
