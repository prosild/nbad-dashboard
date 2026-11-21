import { Radio } from 'lucide-react';
import type { SlackDeliveryView, SlackThreadGroup } from '../../types/api';
import { formatDateTime } from '../../utils/format';
import { CodeLabel, SocBadge } from '../StatusBadge';

/** Slack 발송 한 건: 시각·종류·채널 재알림·전송 결과. 원본 페이로드와 ts·parent 값은 화면에 두지 않는다(2026-11-21 결정). */
function SlackDeliveryCard({ item, isReply }: { item: SlackDeliveryView; isReply: boolean }) {
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
          {item.dryRunOrRecorded && <SocBadge tone="muted">Dry-run</SocBadge>}
        </div>
        <span className="whitespace-nowrap text-[11px] tabular-nums text-slate-400">
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

    </div>
  );
}

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
          {group.deliveries.map((delivery, idx) => (
            <SlackDeliveryCard
              key={idx}
              item={delivery}
              isReply={delivery.threadParent !== null && delivery.threadParent !== ''}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
