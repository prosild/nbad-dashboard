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
import { authApi } from '../api/endpoints';
import type { AuthUserDto } from '../types/api';

interface AuthContextValue {
  user: AuthUserDto | null;
  loading: boolean;
  sessionExpired: boolean;
  clearSessionExpired: () => void;
  refreshMe: () => Promise<AuthUserDto | null>;
  setAuthenticatedUser: (user: AuthUserDto | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUserDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const navigate = useNavigate();

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
      onUnauthorized: (code) => {
        const expired = code === 'SESSION_EXPIRED';
        setSessionExpired(expired);
        setUser(null);
        navigate(expired ? '/login?expired' : '/login', { replace: true });
      },
      onTotpRequired: (mode) => {
        navigate(mode === 'setup' ? '/login/totp/setup' : '/login/totp', { replace: true });
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
    }),
    [user, loading, sessionExpired, clearSessionExpired, refreshMe, setAuthenticatedUser, logout],
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
    return <Navigate to={user.totpEnabled ? '/login/totp' : '/login/totp/setup'} replace />;
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

  if (loading) {
    return <AuthLoadingScreen />;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  if (user.role !== 'ADMIN' || user.totpVerified) {
    return <Navigate to="/" replace />;
  }
  if (mode === 'setup' && user.totpEnabled) {
    return <Navigate to="/login/totp" replace />;
  }
  if (mode === 'verify' && !user.totpEnabled) {
    return <Navigate to="/login/totp/setup" replace />;
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
