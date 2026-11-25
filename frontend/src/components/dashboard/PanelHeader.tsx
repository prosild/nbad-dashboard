/** 현황판 패널 머리(T24): 아이콘·제목과 오른쪽의 짧은 기준 글. noteTitle은 기준 글의 툴팁이다(T45b). */
export function PanelHeader({
  icon: Icon,
  title,
  note,
  noteTitle,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  note?: string;
  noteTitle?: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
        <Icon className="h-4 w-4 text-slate-400" />
        {title}
      </h2>
      {note && (
        <span className="text-[11px] text-slate-400" title={noteTitle}>
          {note}
        </span>
      )}
    </div>
  );
}
