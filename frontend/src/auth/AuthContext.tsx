import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { registerApiCallbacks } from '../api/client';
import { authApi, timeApi } from '../api/endpoints';
import type { AuthUserDto, TimeContextResponse } from '../types/api';
import { fromState, returnPathFromState } from '../utils/returnTo';

interface AuthContextValue {
  user: AuthUserDto | null;
  loading: boolean;
  sessionExpired: boolean;
  clearSessionExpired: () => void;
  refreshMe: () => Promise<AuthUserDto | null>;
  setAuthenticatedUser: (user: AuthUserDto | null) => void;
  logout: () => Promise<void>;
  /** T23: 기준 시각·고정 스냅샷(로그인한 사용자 허용 캡처 기준). 불러오기 전·실패면 null */
  timeContext: TimeContextResponse | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUserDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [timeContext, setTimeContext] = useState<TimeContextResponse | null>(null);
  const navigate = useNavigate();

  // 로그인한 사용자가 바뀔 때만 한 번 묻는다(화면을 옮길 때마다 부르지 않는다). 실패하면 띠를 보이지 않는다.
  const username = user?.username ?? null;
  const totpPending = Boolean(user && user.totpRequired && !user.totpVerified);
  useEffect(() => {
    setTimeContext(null);
    if (!username || totpPending) return undefined;
    let cancelled = false;
    timeApi
      .context()
      .then((res) => {
        if (!cancelled) setTimeContext(res);
      })
      .catch(() => {
        if (!cancelled) setTimeContext(null);
      });
    return () => {
      cancelled = true;
    };
  }, [username, totpPending]);

  const refreshMe = useCallback(async () => {
    try {
      const res = await authApi.me();
      const nextUser = res.authenticated ? res.user : null;
      setUser(nextUser);
      return nextUser;
    } catch {
      setUser(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshMe();
  }, [refreshMe]);

  useEffect(() => {
    return registerApiCallbacks({
      // T27: 화면을 열어 둔 채 세션이 끝나 API 401·OTP 필요를 받으면 그 순간의 주소를 라우터 상태로 넘긴다
      onUnauthorized: (code) => {
        const expired = code === 'SESSION_EXPIRED';
        const state = fromState(window.location.pathname + window.location.search);
        setSessionExpired(expired);
        setUser(null);
        navigate(expired ? '/login?expired' : '/login', { replace: true, state });
      },
      onTotpRequired: (mode) => {
        const state = fromState(window.location.pathname + window.location.search);
        navigate(mode === 'setup' ? '/login/totp/setup' : '/login/totp', { replace: true, state });
      },
    });
  }, [navigate]);

  const clearSessionExpired = useCallback(() => {
    setSessionExpired(false);
  }, []);

  const setAuthenticatedUser = useCallback((nextUser: AuthUserDto | null) => {
    setUser(nextUser);
    if (nextUser) {
      setSessionExpired(false);
    }
    setLoading(false);
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setSessionExpired(false);
      setUser(null);
      navigate('/login?logout', { replace: true });
    }
  }, [navigate]);

  const value = useMemo(
    () => ({
      user,
      loading,
      sessionExpired,
      clearSessionExpired,
      refreshMe,
      setAuthenticatedUser,
      logout,
      timeContext,
    }),
    [user, loading, sessionExpired, clearSessionExpired, refreshMe, setAuthenticatedUser, logout, timeContext],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return ctx;
}

function AuthLoadingScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070b14] text-slate-300">
      <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-[#0d1424] px-6 py-4 shadow-xl">
        <ShieldCheck className="h-5 w-5 animate-pulse text-cyan-400" />
        <span className="text-sm">로그인 상태를 확인하는 중...</span>
      </div>
    </div>
  );
}

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading, sessionExpired } = useAuth();
  const location = useLocation();

  if (loading) {
    return <AuthLoadingScreen />;
  }
  if (!user) {
    return (
      <Navigate
        to={sessionExpired ? '/login?expired' : '/login'}
        state={{ from: location.pathname + location.search }}
        replace
      />
    );
  }
  if (user.totpRequired && !user.totpVerified) {
    return (
      <Navigate
        to={user.totpEnabled ? '/login/totp' : '/login/totp/setup'}
        state={fromState(location.pathname + location.search)}
        replace
      />
    );
  }
  return <>{children}</>;
}

export function RequireTotpRoute({
  mode,
  children,
}: {
  mode: 'setup' | 'verify';
  children: React.ReactNode;
}) {
  const { user, loading } = useAuth();
  const location = useLocation();
  // T27: OTP 화면 사이를 옮겨도 원래 주소를 잃지 않는다
  const from = returnPathFromState(location.state);
  const state = from ? { from } : undefined;

  if (loading) {
    return <AuthLoadingScreen />;
  }
  if (!user) {
    return <Navigate to="/login" state={state} replace />;
  }
  if (user.role !== 'ADMIN' || user.totpVerified) {
    return <Navigate to={from ?? '/'} replace />;
  }
  if (mode === 'setup' && user.totpEnabled) {
    return <Navigate to="/login/totp" state={state} replace />;
  }
  if (mode === 'verify' && !user.totpEnabled) {
    return <Navigate to="/login/totp/setup" state={state} replace />;
  }
  return <>{children}</>;
}

export function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user || user.role !== 'ADMIN') {
    return (
      <div className="soc-card p-8 text-center">
        <ShieldAlert className="mx-auto mb-3 h-10 w-10 text-amber-400" />
        <h2 className="text-lg font-semibold text-slate-100">접근 권한이 없습니다</h2>
        <p className="mt-1 text-sm text-slate-400">이 메뉴는 관리자만 쓸 수 있습니다.</p>
      </div>
    );
  }
  return <>{children}</>;
}
