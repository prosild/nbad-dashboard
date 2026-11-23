import { useId, useMemo, useState } from 'react';
import { Radio } from 'lucide-react';
import type { SlackDeliveryView, SlackThreadGroup } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { lookupSlackMessageVersion } from '../../utils/labels';
import { parseSlackMessage, type SlackBlockView, type SlackLine } from '../../utils/slackText';
import { CodeLabel, LookupText, SocBadge } from '../StatusBadge';

/**
 * zeek_AD가 스레드 두 열(`zeekad_thread_parent`·`zeekad_reply_broadcast`)을 기록하기 시작한 시각.
 * 출처: zeek_AD 데이터 계약 v2 `slack_deliveries` 절 "스레드 두 열을 읽는 법"(2026-11-23 회신).
 * migration 016이 배포 VM에 2026-11-19T06:19:54Z에 적용됐다. `created_at`이 이보다 이른 행의 부모 없음은
 * "머리 알림"이 아니라 "스레드 정보 없음"이다.
 */
const SLACK_THREAD_RECORD_START = Date.parse('2026-11-19T06:20:00Z');

const NO_THREAD_RECORD_TITLE =
  '스레드 기록 도입(2026-11-19) 전의 알림입니다. 첫 알림의 스레드 답글인지 기록에 없습니다.';

/** 기준 시각 전 기록이면 true. `createdAt`이 없거나 읽을 수 없으면 기준 뒤로 다룬다. */
function beforeThreadRecords(createdAt: string | null): boolean {
  if (!createdAt) return false;
  const t = Date.parse(createdAt);
  return Number.isFinite(t) && t < SLACK_THREAD_RECORD_START;
}

function Line({ line }: { line: SlackLine }) {
  return (
    <>
      {line.map((seg, i) => {
        if (seg.bold && seg.italic) {
          return (
            <strong key={i} className="font-semibold italic text-slate-200">
              {seg.text}
            </strong>
          );
        }
        if (seg.bold) {
          return (
            <strong key={i} className="font-semibold text-slate-200">
              {seg.text}
            </strong>
          );
        }
        if (seg.italic) {
          return (
            <em key={i} className="italic">
              {seg.text}
            </em>
          );
        }
        return <span key={i}>{seg.text}</span>;
      })}
    </>
  );
}

function Lines({ lines, className = '' }: { lines: SlackLine[]; className?: string }) {
  return (
    <>
      {lines.map((line, i) => (
        <p key={i} className={className}>
          <Line line={line} />
        </p>
      ))}
    </>
  );
}

function BlockView({ block }: { block: SlackBlockView }) {
  switch (block.kind) {
    case 'header':
      return (
        <div className="text-[13px] font-semibold text-slate-100">
          <Lines lines={block.lines} />
        </div>
      );
    case 'section':
      return (
        <div className="space-y-0.5 text-slate-300">
          <Lines lines={block.lines} />
        </div>
      );
    case 'fields':
      return (
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-2">
          {block.fields.map((f, i) => (
            <div key={i} className="min-w-0">
              {f.name.length > 0 && (
                <dt className="text-[11px] text-slate-400">
                  {f.name.map((l, j) => (
                    <span key={j}>{l.map((s) => s.text).join('')}</span>
                  ))}
                </dt>
              )}
              <dd className="text-slate-300">
                <Lines lines={f.value} />
              </dd>
            </div>
          ))}
        </dl>
      );
    case 'context':
      return (
        <div className="space-y-0.5 text-[11px] text-slate-400">
          <Lines lines={block.lines} />
        </div>
      );
    case 'buttons':
      return (
        <div className="text-[11px] text-slate-400">
          {block.names.map((n, i) => (
            <span key={i} className="mr-3">
              버튼: {n}
            </span>
          ))}
        </div>
      );
  }
}

/**
 * Slack 발송 한 건: 역할·종류·판, 시각, 알림 본문, 접힌 전문, 전송 결과.
 * 원본 JSON 글, 채널, URL, `slackTs`, `threadParent`는 화면(툴팁·속성 포함)에 두지 않는다(2026-11-21 `T19`, 2026-11-23 `T38` 결정).
 */
function SlackDeliveryCard({
  item,
  isReply,
  noThreadRecord,
}: {
  item: SlackDeliveryView;
  isReply: boolean;
  noThreadRecord: boolean;
}) {
  const message = useMemo(() => parseSlackMessage(item.payloadJson), [item.payloadJson]);
  const version = item.messageKind === 'incident' ? lookupSlackMessageVersion(item.messageVersion) : null;
  const [open, setOpen] = useState(false);
  const fullId = useId();

  return (
    <div
      className={`min-w-0 rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 text-xs ${
        isReply ? 'ml-5 border-l-2 border-l-slate-600 sm:ml-8' : ''
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {noThreadRecord ? (
            <SocBadge tone="muted" title={NO_THREAD_RECORD_TITLE}>
              스레드 기록 없음
              <span className="sr-only">: {NO_THREAD_RECORD_TITLE}</span>
            </SocBadge>
          ) : (
            <SocBadge tone={isReply ? 'neutral' : 'notice'}>{item.threadRoleLabel || '알림'}</SocBadge>
          )}
          {item.messageKind && (
            <SocBadge tone="muted">
              <CodeLabel dict="slackMessageKind" value={item.messageKind} />
            </SocBadge>
          )}
          {version && (
            <SocBadge tone="neutral">
              <LookupText label={version} />
            </SocBadge>
          )}
          {item.replyBroadcast && (
            <SocBadge tone="muted">
              <Radio className="h-3 w-3" aria-hidden="true" />
              채널에도 표시
            </SocBadge>
          )}
          {item.dryRunOrRecorded && <SocBadge tone="muted">Dry-run</SocBadge>}
        </div>
        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
          {formatDateTime(item.deliveredAt ?? item.createdAt)}
        </span>
      </div>

      {message.body && (
        <div className="mt-2 break-words text-[13px] leading-relaxed text-slate-200 [overflow-wrap:anywhere]">
          <Lines lines={message.body} />
        </div>
      )}

      {message.blocks && (
        <div className="mt-2">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={fullId}
            onClick={() => setOpen((v) => !v)}
            className="text-[11px] text-cyan-300 hover:text-cyan-200 hover:underline"
          >
            {open ? '알림 전문 접기' : '알림 전문 보기'}
          </button>
          {open && (
            <div
              id={fullId}
              className="mt-2 space-y-2 break-words rounded border border-slate-800 bg-slate-950/40 p-2.5 leading-relaxed [overflow-wrap:anywhere]"
            >
              {message.blocks.map((block, i) => (
                <BlockView key={i} block={block} />
              ))}
            </div>
          )}
        </div>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
        <span>
          전송 결과 <CodeLabel dict="slackDeliveryStatus" value={item.deliveryStatus} className="text-slate-300" />
        </span>
        {!item.dryRunOrRecorded && item.deliveryMode && (
          <span>
            전송 방식 <CodeLabel dict="slackDeliveryMode" value={item.deliveryMode} className="text-slate-300" />
          </span>
        )}
      </div>

      {item.error && (
        <div className="mt-2 rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-amber-200">
          오류: {item.error}
        </div>
      )}
    </div>
  );
}

const hasParent = (d: SlackDeliveryView) => d.threadParent !== null && d.threadParent !== '';

export function SlackThreadsSection({ threadGroups }: { threadGroups: SlackThreadGroup[] }) {
  if (threadGroups.length === 0) {
    return <p className="text-sm text-slate-400">이 인시던트로 보낸 Slack 알림이 없습니다.</p>;
  }
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-400">알림 묶음 {threadGroups.length}개</div>
      {threadGroups.map((group, gIdx) => (
        <div key={`${gIdx}-${group.deliveries.length}`} className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="font-semibold text-slate-200">알림 묶음</span>
            <span className="text-slate-400">메시지 {group.deliveries.length}건</span>
          </div>
          {group.deliveries.map((delivery, idx) => {
            const reply = hasParent(delivery);
            // 부모가 기록된 알림만 답글로 그린다. 순서·판으로 스레드 관계를 추정하지 않는다.
            // 기준 시각 전의 부모 없는 알림은 묶음의 첫 알림만 "최초 알림"이고, 둘째부터는 스레드 정보가 없다.
            const noThreadRecord = !reply && idx > 0 && beforeThreadRecords(delivery.createdAt);
            return <SlackDeliveryCard key={idx} item={delivery} isReply={reply} noThreadRecord={noThreadRecord} />;
          })}
        </div>
      ))}
    </div>
  );
}
