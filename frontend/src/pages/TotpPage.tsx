import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, Check, Copy, KeyRound, LogOut, ShieldCheck } from 'lucide-react';
import { ApiError } from '../api/client';
import { authApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { QrCodeSvg } from '../components/QrCodeSvg';
import { useToast } from '../components/ToastContext';
import type { TotpSetupResponse } from '../types/api';
import { returnPathFromState } from '../utils/returnTo';

export function TotpPage({ mode }: { mode: 'setup' | 'verify' }) {
  const { user, setAuthenticatedUser, logout, endSessionWithError } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  // T27: OTP를 마치면 원래 주소(라우터 상태, 앱 안 경로만)로 간다
  const returnTo = returnPathFromState(location.state);

  const [setupInfo, setSetupInfo] = useState<TotpSetupResponse | null>(null);
  const [loadingSetup, setLoadingSetup] = useState(mode === 'setup');
  const [code, setCode] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (mode !== 'setup') {
      setLoadingSetup(false);
      return;
    }
    let active = true;
    setLoadingSetup(true);
    setErrorMsg(null);
    authApi
      .getTotpSetup()
      .then((res) => {
        if (active) {
          setSetupInfo(res);
        }
      })
      .catch((err) => {
        if (active) {
          setErrorMsg(err instanceof ApiError ? err.message : 'TOTP 등록 정보를 불러오지 못했습니다.');
        }
      })
      .finally(() => {
        if (active) {
          setLoadingSetup(false);
        }
      });
    return () => {
      active = false;
    };
  }, [mode]);

  async function handleCopySecret() {
    if (!setupInfo?.secret) {
      return;
    }
    try {
      await navigator.clipboard.writeText(setupInfo.secret);
      setCopied(true);
      notify('수동 입력용 키를 클립보드에 복사했습니다.', 'success');
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      notify('클립보드 복사에 실패했습니다. 키를 직접 선택해 복사해 주세요.', 'error');
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const res =
        mode === 'setup'
          ? await authApi.completeTotpSetup(code.trim())
          : await authApi.verifyTotp(code.trim());
      setAuthenticatedUser(res.user);
      notify(res.message || 'TOTP 인증이 완료되었습니다.', 'success');
      navigate(returnTo ?? '/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 423) {
        // T60: 계정이 잠겼고 서버가 이 세션을 끝냈다. 로그인 화면으로 옮겨 서버 메시지를 그 화면의 오류 자리에 보인다
        endSessionWithError(err.message, returnTo);
        return;
      }
      setErrorMsg(err instanceof ApiError ? err.message : '인증 코드를 확인하지 못했습니다.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070b14] px-4 py-10">
      <div className="w-full max-w-lg">
        <div className="soc-card p-6 sm:p-8">
          <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-purple-500/40 bg-purple-500/15 text-purple-300">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">
                  {mode === 'setup' ? '관리자 TOTP 최초 등록' : '관리자 TOTP 2단계 인증'}
                </h1>
                <p className="text-xs text-slate-400">
                  계정 <span className="break-all font-mono text-slate-200">{user?.username}</span>
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => void logout()}
              className="soc-btn-secondary py-1.5 text-xs"
            >
              <LogOut className="h-3.5 w-3.5" />
              로그아웃
            </button>
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-sm text-amber-200"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          {mode === 'setup' && (
            <div className="mt-5 space-y-4">
              {loadingSetup ? (
                <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-6 text-center text-sm text-slate-400">
                  TOTP 등록 키 생성 중...
                </div>
              ) : setupInfo ? (
                <div className="rounded-xl border border-slate-800 bg-[#090f1d] p-4">
                  <p className="mb-3 text-xs leading-relaxed text-slate-300">
                    Google Authenticator, 1Password, Microsoft Authenticator 같은 TOTP 앱으로 아래 QR 코드를 스캔하거나 수동 입력용 키를 입력하세요.
                  </p>
                  <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
                    <div className="shrink-0">
                      <QrCodeSvg value={setupInfo.otpauthUri} size={176} label="관리자 TOTP QR 코드" />
                    </div>
                    <div className="min-w-0 flex-1 space-y-3 text-xs">
                      <div>
                        <div className="mb-1 font-semibold text-slate-400">발급자 · 계정</div>
                        <div className="font-mono text-slate-200">
                          {setupInfo.issuer} / {setupInfo.accountName}
                        </div>
                      </div>
                      <div>
                        <div className="mb-1 font-semibold text-slate-400">수동 입력용 키</div>
                        <div className="flex items-center gap-2">
                          <code className="block flex-1 break-all rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-cyan-300">
                            {setupInfo.secret}
                          </code>
                          <button
                            type="button"
                            onClick={() => void handleCopySecret()}
                            className="soc-btn-secondary shrink-0 px-2.5 py-1.5 text-xs"
                          >
                            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                            {copied ? '복사됨' : '복사'}
                          </button>
                        </div>
                      </div>
                      <div>
                        <div className="mb-1 font-semibold text-slate-400">QR 코드에 담긴 등록 주소</div>
                        <code className="block max-h-20 overflow-y-auto break-all rounded border border-slate-800 bg-slate-950 px-2.5 py-1.5 font-mono text-[11px] text-slate-400">
                          {setupInfo.otpauthUri}
                        </code>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}

          <form onSubmit={(e) => void handleSubmit(e)} className="mt-5 space-y-4">
            <div>
              <label
                htmlFor="totp-code"
                className="mb-1.5 block text-xs font-semibold text-slate-300"
              >
                6자리 TOTP 인증 코드
              </label>
              <input
                id="totp-code"
                name="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                pattern="\d{6}"
                required
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                className="soc-input text-center font-mono text-lg tracking-[0.4em]"
              />
            </div>

            <button
              type="submit"
              disabled={submitting || code.length !== 6 || (mode === 'setup' && !setupInfo)}
              className="soc-btn-primary w-full py-2.5"
            >
              <KeyRound className="h-4 w-4" />
              {submitting
                ? '검증 중...'
                : mode === 'setup'
                  ? 'TOTP 등록 완료 및 입장'
                  : '인증 확인'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
