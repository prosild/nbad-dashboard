import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, Info, Lock, Shield } from 'lucide-react';
import { ApiError } from '../api/client';
import { authApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { PRODUCT_NAME } from '../components/AppShell';
import { returnPathFromState } from '../utils/returnTo';

/**
 * 로그인 화면 안내 문구(T21, 설정값 DASHBOARD_LOGIN_NOTICE). 값이 있을 때만 로그인 폼 위에 보인다.
 * 일반 텍스트로만 그린다(텍스트 노드, 줄바꿈은 CSS whitespace-pre-line). 불러오지 못하면 아무것도 보이지 않는다.
 */
function useLoginNotice(): string {
  const [notice, setNotice] = useState('');
  useEffect(() => {
    let alive = true;
    authApi
      .loginNotice()
      .then((res) => {
        if (alive) setNotice(typeof res?.notice === 'string' ? res.notice.trim() : '');
      })
      .catch(() => {
        if (alive) setNotice('');
      });
    return () => {
      alive = false;
    };
  }, []);
  return notice;
}

export function LoginPage() {
  const { user, sessionExpired, setAuthenticatedUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const loginNotice = useLoginNotice();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // T27: 원래 주소(라우터 상태, 앱 안 경로만)
  const stateFrom = returnPathFromState(location.state);
  const fromState = stateFrom ? { from: stateFrom } : undefined;

  if (user) {
    if (user.totpRequired && !user.totpVerified) {
      return <Navigate to={user.totpEnabled ? '/login/totp' : '/login/totp/setup'} state={fromState} replace />;
    }
    return <Navigate to={stateFrom ?? '/'} replace />;
  }

  const isExpired = searchParams.has('expired') || sessionExpired;
  const isLogout = searchParams.has('logout');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const res = await authApi.login(username.trim(), password);
      setAuthenticatedUser(res.user);
      const next = res.nextRoute || '/';
      if (next === '/' && stateFrom) {
        navigate(stateFrom, { replace: true });
      } else {
        // ADMIN은 OTP 화면으로 가고, 원래 주소를 그 화면에 넘긴다
        navigate(next, { replace: true, state: fromState });
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg('로그인 요청을 처리할 수 없습니다. 잠시 후 다시 시도하세요.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070b14] px-4 py-12">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 shadow-lg shadow-cyan-500/10">
            <Shield className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">{PRODUCT_NAME}</h1>
          <p className="mt-1.5 text-sm text-slate-400">네트워크 이상탐지 인시던트를 분석하고 판단하는 관제 화면</p>
        </div>

        <div className="soc-card p-6 sm:p-8">
          {loginNotice && (
            <p
              role="note"
              aria-label="안내"
              className="mb-5 flex items-start gap-2.5 rounded-lg border border-slate-700 bg-slate-900/60 px-3.5 py-2.5 text-xs leading-relaxed text-slate-300"
            >
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
              <span className="whitespace-pre-line">{loginNotice}</span>
            </p>
          )}

          {isExpired && (
            <div
              role="status"
              className="mb-5 flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-sm text-amber-200"
            >
              <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
              <span>세션이 만료되었습니다. 다시 로그인해 주세요.</span>
            </div>
          )}

          {isLogout && !isExpired && (
            <div
              role="status"
              className="mb-5 flex items-center gap-2.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2.5 text-sm text-emerald-200"
            >
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
              <span>안전하게 로그아웃되었습니다.</span>
            </div>
          )}

          {errorMsg && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-sm text-amber-200"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
            <div>
              <label htmlFor="login-username" className="mb-1.5 block text-xs font-semibold text-slate-300">
                아이디
              </label>
              <input
                id="login-username"
                name="username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="아이디 입력"
                className="soc-input"
              />
            </div>

            <div>
              <label htmlFor="login-password" className="mb-1.5 block text-xs font-semibold text-slate-300">
                비밀번호
              </label>
              <input
                id="login-password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="비밀번호 입력"
                className="soc-input"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="soc-btn-primary mt-2 w-full py-2.5"
            >
              <Lock className="h-4 w-4" />
              {submitting ? '인증 확인 중...' : '로그인'}
            </button>
          </form>

          <p className="mt-5 border-t border-slate-800/80 pt-4 text-center text-xs text-slate-500">
            로그인을 여러 번 실패하면 잠시 로그인이 제한될 수 있습니다. 관리자 계정은 2단계 인증을 거칩니다.
          </p>
        </div>
      </div>
    </div>
  );
}
