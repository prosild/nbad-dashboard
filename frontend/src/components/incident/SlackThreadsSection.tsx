import { useState } from 'react';
import { ChevronDown, ChevronUp, MessageSquare, Radio } from 'lucide-react';
import type { SlackDeliveryView, SlackThreadGroup } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { CodeLabel, SocBadge } from '../StatusBadge';

function SlackDeliveryCard({ item, isReply }: { item: SlackDeliveryView; isReply: boolean }) {
  const [showPayload, setShowPayload] = useState(false);
  const techInfo = [
    item.jobId !== null ? `보고서 실행 #${item.jobId}` : null,
    item.slackTs ? `Slack 메시지 시각값 ${item.slackTs}` : null,
    item.threadParent ? `이어진 사건 ${item.threadParent}` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <div
      className={`rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 text-xs ${
        isReply ? 'ml-5 border-l-2 border-l-slate-600 sm:ml-8' : ''
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <SocBadge tone={isReply ? 'neutral' : 'notice'}>{item.threadRoleLabel || '알림'}</SocBadge>
          {item.messageKind && (
            <SocBadge tone="muted">
              <CodeLabel dict="slackMessageKind" value={item.messageKind} />
            </SocBadge>
          )}
          {item.replyBroadcast && (
            <SocBadge tone="muted">
              <Radio className="h-3 w-3" aria-hidden="true" />
              채널에도 표시
            </SocBadge>
          )}
          {item.dryRunOrRecorded && <SocBadge tone="muted">시험 모드(실제 전송 안 함)</SocBadge>}
        </div>
        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400" title={techInfo || undefined}>
          {formatDateTime(item.deliveredAt ?? item.createdAt)}
        </span>
      </div>

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

      <div className="mt-2.5">
        <button
          type="button"
          onClick={() => setShowPayload((prev) => !prev)}
          className="inline-flex items-center gap-1 text-[11px] font-medium text-cyan-300 hover:text-cyan-200"
        >
          {showPayload ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          {showPayload ? '원본 메시지 닫기' : 'Slack 원본 메시지 보기'}
        </button>
        {showPayload && (
          <pre
            className="mt-2 max-h-64 overflow-auto rounded border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300"
            data-raw=""
          >
            {item.payloadJson}
          </pre>
        )}
      </div>
    </div>
  );
}

export function SlackThreadsSection({ threadGroups }: { threadGroups: SlackThreadGroup[] }) {
  return (
    <section className="soc-card space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <MessageSquare className="h-4 w-4 text-slate-400" />
          Slack 알림 이력
        </div>
        <span className="text-xs text-slate-400">알림 묶음 {threadGroups.length}개</span>
      </div>

      {threadGroups.length === 0 ? (
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
          이 사건으로 보낸 Slack 알림이 없습니다.
        </div>
      ) : (
        <div className="space-y-4">
          {threadGroups.map((group) => (
            <div key={group.threadKey} className="soc-panel space-y-2.5 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="font-semibold text-slate-200" title={`알림 묶음 기준 사건: ${group.threadKey}`}>
                  알림 묶음
                </div>
                <span className="text-slate-400">메시지 {group.deliveries.length}건</span>
              </div>
              <div className="space-y-2">
                {group.deliveries.map((delivery, idx) => (
                  <SlackDeliveryCard
                    key={`${delivery.jobId ?? 'x'}-${delivery.slackTs ?? idx}-${idx}`}
                    item={delivery}
                    isReply={delivery.threadParent !== null && delivery.threadParent !== ''}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
