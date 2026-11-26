import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, Info, Lock, Shield } from 'lucide-react';
import { ApiError } from '../api/client';
import { authApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { PRODUCT_NAME } from '../components/AppShell';
import type { LoginNoticeLink } from '../types/api';
import { returnPathFromState } from '../utils/returnTo';

interface LoginNotice {
  notice: string;
  link: LoginNoticeLink | null;
}

const NO_NOTICE: LoginNotice = { notice: '', link: null };

/**
 * 로그인 화면 안내 문구(T21, 설정값 DASHBOARD_LOGIN_NOTICE). 값이 있을 때만 로그인 폼 위에 보인다.
 * 일반 텍스트로만 그린다(텍스트 노드, 줄바꿈은 CSS whitespace-pre-line). 불러오지 못하면 아무것도 보이지 않는다.
 * T50: 설정한 링크 하나가 있으면 안내 문구 아래에 새 창으로 여는 링크로 붙는다(라벨도 텍스트 노드).
 */
function useLoginNotice(): LoginNotice {
  const [state, setState] = useState<LoginNotice>(NO_NOTICE);
  useEffect(() => {
    let alive = true;
    authApi
      .loginNotice()
      .then((res) => {
        if (!alive) return;
        const notice = typeof res?.notice === 'string' ? res.notice.trim() : '';
        setState({ notice, link: notice ? safeNoticeLink(res?.link) : null });
      })
      .catch(() => {
        if (alive) setState(NO_NOTICE);
      });
    return () => {
      alive = false;
    };
  }, []);
  return state;
}

/**
 * T50 안내문 링크: 서버가 검사한 값(https 주소, 일반 텍스트 라벨)만 내려오지만 화면도 https 주소와 빈 라벨을 한 번 더 본다.
 * 안내문이 없으면 링크도 보이지 않는다.
 */
function safeNoticeLink(value: unknown): LoginNoticeLink | null {
  if (!value || typeof value !== 'object') return null;
  const { url, label } = value as { url?: unknown; label?: unknown };
  if (typeof url !== 'string' || typeof label !== 'string' || !label.trim()) return null;
  try {
    if (new URL(url).protocol !== 'https:') return null;
  } catch {
    return null;
  }
  return { url, label: label.trim() };
}

export function LoginPage() {
  const { user, sessionExpired, authError, clearAuthError, setAuthenticatedUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { notice: loginNotice, link: noticeLink } = useLoginNotice();

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
  // T60: TOTP 화면이 423(계정 잠김)을 받아 넘긴 서버 메시지. 다시 로그인을 시도하면 지워지고 그 응답의 메시지가 보인다
  const shownError = errorMsg ?? authError;
  const isLogout = searchParams.has('logout');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    clearAuthError();
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
              <span className="min-w-0">
                <span className="block whitespace-pre-line">{loginNotice}</span>
                {noticeLink && (
                  <a
                    href={noticeLink.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`${noticeLink.label} (새 창)`}
                    className="mt-1.5 inline-flex items-center gap-1 rounded font-medium text-cyan-300 underline underline-offset-2 hover:text-cyan-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/70"
                  >
                    {noticeLink.label}
                  </a>
                )}
              </span>
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

          {shownError && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-sm text-amber-200"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>{shownError}</span>
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
