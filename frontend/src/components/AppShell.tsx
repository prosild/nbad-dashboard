import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Activity,
  ClipboardCheck,
  EyeOff,
  FileSearch,
  Lock,
  LogOut,
  Menu,
  Radar,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { roleLabel } from '../utils/format';
import { SocBadge } from './StatusBadge';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  matchPrefix: string;
  adminOnly?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/incidents', label: '이상탐지 조사 큐', icon: Radar, matchPrefix: '/incidents' },
  { to: '/reviews', label: '분석가 승인 대기', icon: ClipboardCheck, matchPrefix: '/reviews' },
  { to: '/operations', label: '운영 상태 · 결론 집계', icon: Activity, matchPrefix: '/operations' },
  { to: '/admin/users', label: '사용자 관리', icon: Users, matchPrefix: '/admin/users', adminOnly: true },
  { to: '/admin/audit-logs', label: '감사 로그', icon: FileSearch, matchPrefix: '/admin/audit-logs', adminOnly: true },
];

export function AppShell({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const visibleNav = NAV_ITEMS.filter((item) => !item.adminOnly || user?.role === 'ADMIN');

  const isActive = (item: NavItem) => {
    if (item.to === '/incidents' && location.pathname === '/') {
      return true;
    }
    return location.pathname === item.matchPrefix || location.pathname.startsWith(`${item.matchPrefix}/`);
  };

  const navContent = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-slate-800/90 px-5 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <div className="font-mono text-sm font-bold tracking-wide text-slate-100">zeek_AD SOC</div>
          <div className="text-[11px] text-slate-400">관제·조사 콘솔</div>
        </div>
      </div>

      <nav aria-label="주 메뉴" className="flex-1 space-y-1 px-3 py-4">
        {visibleNav.map((item) => {
          const Icon = item.icon;
          const active = isActive(item);
          return (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => setMobileOpen(false)}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                active
                  ? 'border border-cyan-500/35 bg-cyan-500/10 text-cyan-200 shadow-sm'
                  : 'border border-transparent text-slate-300 hover:bg-slate-800/70 hover:text-slate-100'
              }`}
            >
              <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-cyan-300' : 'text-slate-400'}`} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {user && (
        <div className="border-t border-slate-800/90 p-4 text-xs">
          <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-semibold text-slate-100">{user.displayName}</span>
              <SocBadge tone={user.role === 'ADMIN' ? 'purple' : user.role === 'ANALYST' ? 'cyan' : 'slate'}>
                {user.role}
              </SocBadge>
            </div>
            <div className="mt-1 font-mono text-[11px] text-slate-400">@{user.username}</div>
            <div className="mt-2 flex flex-wrap gap-1">
              {user.allowedCapturePatterns.map((pattern) => (
                <span
                  key={pattern}
                  className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
                >
                  {pattern}
                </span>
              ))}
            </div>
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700/80 bg-slate-800/60 px-3 py-2 text-xs font-medium text-slate-200 transition hover:border-rose-500/40 hover:bg-rose-500/10 hover:text-rose-200"
          >
            <LogOut className="h-3.5 w-3.5" />
            로그아웃
          </button>
        </div>
      )}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 lg:flex">
      <aside className="hidden w-64 shrink-0 border-r border-slate-800/90 bg-[#0a101d] lg:block">
        <div className="sticky top-0 h-screen overflow-y-auto">{navContent}</div>
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <button
            type="button"
            aria-label="메뉴 닫기"
            onClick={() => setMobileOpen(false)}
            className="fixed inset-0 bg-black/70"
          />
          <aside className="relative z-10 w-72 border-r border-slate-800 bg-[#0a101d]">
            <button
              type="button"
              aria-label="모바일 메뉴 닫기"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              <X className="h-5 w-5" />
            </button>
            {navContent}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#090f1d]/95 backdrop-blur">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
            <div className="flex items-center gap-3">
              <button
                type="button"
                aria-label="메뉴 열기"
                onClick={() => setMobileOpen(true)}
                className="rounded-lg border border-slate-700 bg-slate-800/70 p-2 text-slate-200 hover:bg-slate-700 lg:hidden"
              >
                <Menu className="h-4 w-4" />
              </button>
              <div>
                <h1 className="text-lg font-bold tracking-tight text-slate-100 sm:text-xl">{title}</h1>
                {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {user?.maskedView && (
                <SocBadge tone="amber">
                  <EyeOff className="h-3.5 w-3.5" />
                  VIEWER 마스킹 적용 중
                </SocBadge>
              )}
              {user && (
                <SocBadge tone="slate">
                  <Lock className="h-3 w-3 text-cyan-400" />
                  {roleLabel(user.role)}
                </SocBadge>
              )}
              {actions}
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6">{children}</main>
      </div>
    </div>
  );
}
