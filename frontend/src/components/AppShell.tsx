import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Activity,
  ClipboardCheck,
  Clock,
  EyeOff,
  History,
  FileSearch,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Radar,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime } from '../utils/format';
import { labelText } from '../utils/labels';
import { SocBadge, UserRoleBadge } from './StatusBadge';

export const PRODUCT_NAME = 'zeek_AD 보안 관제';

/**
 * T21: 고정 띠(stickyBar)가 있는 화면(인시던트 상세)은 넓은 화면(xl)에서 상단 바 줄을 접지 않는다.
 * 헤더 높이가 폭에 따라 달라지지 않아야 조치 패널의 고정 위치(xl:top)가 헤더에 가리지 않는다.
 */
const STICKY_ROW_NOWRAP = 'xl:flex-nowrap';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  matchPrefix: string;
  adminOnly?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', label: '현황판', icon: LayoutDashboard, matchPrefix: '/' },
  { to: '/incidents', label: '인시던트', icon: Radar, matchPrefix: '/incidents' },
  { to: '/reviews', label: '에스컬레이션', icon: ClipboardCheck, matchPrefix: '/reviews' },
  { to: '/operations', label: '운영 현황', icon: Activity, matchPrefix: '/operations' },
  { to: '/admin/users', label: '사용자 관리', icon: Users, matchPrefix: '/admin/users', adminOnly: true },
  { to: '/admin/audit-logs', label: '감사 로그', icon: FileSearch, matchPrefix: '/admin/audit-logs', adminOnly: true },
];

export function AppShell({
  title,
  subtitle,
  actions,
  stickyBar,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  /** 상단 바 아래에 붙어 스크롤해도 남는 띠(인시던트 상세의 요약 헤더 등) */
  stickyBar?: React.ReactNode;
  children: React.ReactNode;
}) {
  const { user, logout, timeContext } = useAuth();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const visibleNav = NAV_ITEMS.filter((item) => !item.adminOnly || user?.role === 'ADMIN');

  const isActive = (item: NavItem) => {
    // 현황판('/')은 정확히 '/'일 때만 활성이다(다른 모든 경로가 '/'로 시작하므로).
    if (item.matchPrefix === '/') {
      return location.pathname === '/';
    }
    return location.pathname === item.matchPrefix || location.pathname.startsWith(`${item.matchPrefix}/`);
  };

  const navContent = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-slate-800/90 px-5 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">
          <Shield className="h-5 w-5" />
        </div>
        <div className="text-sm font-bold tracking-tight text-slate-100">{PRODUCT_NAME}</div>
      </div>

      <nav aria-label="주 메뉴" className="flex-1 space-y-1 px-3 py-4">
        {visibleNav.map((item) => {
          const Icon = item.icon;
          const active = isActive(item);
          return (
            <Link
              key={item.to}
              to={item.to}
              aria-current={active ? 'page' : undefined}
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
              <UserRoleBadge role={user.role} />
            </div>
            <div className="mt-1 font-mono text-[11px] text-slate-400">@{user.username}</div>
            <div className="mt-2 text-[11px] text-slate-400">열람 허용 캡처</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {user.allowedCapturePatterns.map((pattern) => (
                <span
                  key={pattern}
                  title={pattern === '*' ? '모든 캡처' : undefined}
                  className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-400"
                >
                  {pattern === '*' ? '전체' : pattern}
                </span>
              ))}
            </div>
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700/80 bg-slate-800/60 px-3 py-2 text-xs font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-700/70 hover:text-slate-100"
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
        {timeContext?.snapshot && (
          <div
            role="status"
            data-snapshot-banner=""
            className="border-b border-slate-700 bg-slate-800/80 px-4 py-1.5 text-center text-xs text-slate-200 sm:px-6"
            title="데이터가 더 늘지 않는 고정 스냅샷입니다. 최근 기간(24시간 등)은 이 기준 시각에서 거꾸로 셉니다."
          >
            <History className="mr-1.5 inline h-3.5 w-3.5 align-[-2px] text-slate-400" aria-hidden="true" />
            고정 스냅샷 · 기준 시각 <span className="tabular-nums">{formatDateTime(timeContext.anchor)}</span>{' '}
            {DISPLAY_TIME_ZONE_LABEL}
          </div>
        )}
        <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#090f1d]/95 backdrop-blur">
          <div className={`mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 ${stickyBar ? STICKY_ROW_NOWRAP : ''}`}>
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

            <div className={`flex flex-wrap items-center gap-2 ${stickyBar ? STICKY_ROW_NOWRAP : ''}`}>
              <span
                className="inline-flex items-center gap-1 whitespace-nowrap text-xs text-slate-400"
                title="화면의 모든 날짜·시각은 한국 표준시(UTC+9)로 표시합니다."
              >
                <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                시각 기준 {DISPLAY_TIME_ZONE_LABEL}
              </span>
              {user?.maskedView ? (
                <SocBadge
                  tone="neutral"
                  title={`${labelText('userRole', user.role)} 계정입니다. 조회만 할 수 있고, IP 주소와 계정 이름 일부가 서버에서 가려져 보입니다.`}
                >
                  <EyeOff className="h-3.5 w-3.5" aria-hidden="true" />
                  마스킹 적용
                </SocBadge>
              ) : (
                user && (
                  <SocBadge tone="neutral" title="현재 계정의 권한">
                    <Lock className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    {labelText('userRole', user.role)}
                  </SocBadge>
                )
              )}
              {actions}
            </div>
          </div>
          {stickyBar && <div className="mx-auto max-w-[1600px] px-4 pb-2.5 sm:px-6">{stickyBar}</div>}
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6">{children}</main>
      </div>
    </div>
  );
}
