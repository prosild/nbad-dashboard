import { useState } from 'react';
import { ChevronDown, ChevronUp, MessageSquare, Radio } from 'lucide-react';
import type { SlackDeliveryView, SlackThreadGroup } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { SocBadge } from '../StatusBadge';

function SlackDeliveryCard({
  item,
  isReply,
}: {
  item: SlackDeliveryView;
  isReply: boolean;
}) {
  const [showPayload, setShowPayload] = useState(false);

  return (
    <div
      className={`rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 text-xs ${
        isReply ? 'ml-5 border-l-2 border-l-cyan-500/50 sm:ml-8' : ''
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <SocBadge tone={isReply ? 'slate' : 'cyan'}>{item.threadRoleLabel || '알림'}</SocBadge>
          {item.messageKind && <SocBadge tone="slate">{item.messageKind}</SocBadge>}
          {item.replyBroadcast && (
            <SocBadge tone="purple">
              <Radio className="h-3 w-3" />
              채널 재알림
            </SocBadge>
          )}
          {item.dryRunOrRecorded && <SocBadge tone="amber">기록만(dry-run)</SocBadge>}
        </div>
        <span className="font-mono text-[11px] tabular-nums text-slate-400">
          {formatDateTime(item.deliveredAt ?? item.createdAt)} · 작업 #{item.jobId ?? '-'}
        </span>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px] text-slate-400">
        <span>상태: {item.deliveryStatus ?? '-'}</span>
        <span>모드: {item.deliveryMode ?? '-'}</span>
        {item.slackTs && <span>ts: {item.slackTs}</span>}
        {item.threadParent && <span>parent: {item.threadParent}</span>}
      </div>

      {item.error && (
        <div className="mt-2 rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1.5 text-rose-200">
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
          {showPayload ? '페이로드 닫기' : 'Slack 페이로드 펼치기'}
        </button>
        {showPayload && (
          <pre className="mt-2 max-h-64 overflow-auto rounded border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300">
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
          <MessageSquare className="h-4 w-4 text-cyan-400" />
          Slack 알림 스레드 (incident_id 단독 조회)
        </div>
        <span className="text-xs text-slate-400">스레드 묶음 {threadGroups.length}개</span>
      </div>

      {threadGroups.length === 0 ? (
        <div className="soc-panel px-4 py-6 text-center text-sm text-slate-400">
          Slack 전송 기록이 없습니다.
        </div>
      ) : (
        <div className="space-y-4">
          {threadGroups.map((group) => (
            <div key={group.threadKey} className="soc-panel space-y-2.5 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="font-mono font-semibold text-cyan-200">
                  스레드 키: {group.threadKey}
                </div>
                <span className="text-slate-400">메시지 {group.deliveries.length}건</span>
              </div>
              <div className="space-y-2">
                {group.deliveries.map((delivery, idx) => {
                  const isReply =
                    delivery.threadRoleLabel === '스레드 답글' ||
                    delivery.threadRoleLabel === '머리 사건 후속 답글';
                  return (
                    <SlackDeliveryCard
                      key={`${delivery.jobId ?? 'x'}-${delivery.slackTs ?? idx}-${idx}`}
                      item={delivery}
                      isReply={isReply}
                    />
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
