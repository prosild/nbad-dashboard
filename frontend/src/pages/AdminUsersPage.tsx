import { useCallback, useEffect, useState } from 'react';
import {
  Edit3,
  KeyRound,
  LockOpen,
  Power,
  UserPlus,
  Users,
  X,
} from 'lucide-react';
import { ApiError, errorNotice, type ErrorNotice } from '../api/client';
import { adminApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { SocBadge, UserRoleBadge } from '../components/StatusBadge';
import { useToast } from '../components/ToastContext';
import type { AdminUserDto, AdminUsersListResponse, UserRole } from '../types/api';
import { formatDateTime } from '../utils/format';
import { labelText } from '../utils/labels';

function parsePatterns(input: string): string[] {
  return input
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function AdminUsersPage() {
  const { notify } = useToast();
  const [data, setData] = useState<AdminUsersListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<ErrorNotice | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('VIEWER');
  const [newPatterns, setNewPatterns] = useState('cic17-*');
  const [submitting, setSubmitting] = useState(false);

  const [editingUser, setEditingUser] = useState<AdminUserDto | null>(null);
  const [editDisplayName, setEditDisplayName] = useState('');
  const [editRole, setEditRole] = useState<UserRole>('VIEWER');
  const [editPatterns, setEditPatterns] = useState('');

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await adminApi.listUsers();
      setData(res);
    } catch (err) {
      setErrorMsg(errorNotice(err, '사용자 목록을 불러오지 못했습니다.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  function openEditModal(user: AdminUserDto) {
    setEditingUser(user);
    setEditDisplayName(user.displayName);
    setEditRole(user.role);
    setEditPatterns(user.capturePatterns.join('\n'));
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await adminApi.createUser({
        username: newUsername.trim(),
        displayName: newDisplayName.trim(),
        password: newPassword,
        role: newRole,
        capturePatterns: parsePatterns(newPatterns),
      });
      notify(res.message, 'success');
      setShowCreate(false);
      setNewUsername('');
      setNewDisplayName('');
      setNewPassword('');
      setNewRole('VIEWER');
      setNewPatterns('cic17-*');
      await loadUsers();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '사용자 생성에 실패했습니다.', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleUpdateUser(e: React.FormEvent) {
    e.preventDefault();
    if (!editingUser) return;
    setSubmitting(true);
    try {
      const res = await adminApi.updateUser(editingUser.id, {
        displayName: editDisplayName.trim(),
        role: editRole,
        capturePatterns: parsePatterns(editPatterns),
      });
      notify(res.message, 'success');
      setEditingUser(null);
      await loadUsers();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '사용자 수정에 실패했습니다.', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  async function runRowAction(action: () => Promise<{ message: string }>) {
    try {
      const res = await action();
      notify(res.message, 'success');
      await loadUsers();
    } catch (err) {
      notify(err instanceof ApiError ? err.message : '작업 처리에 실패했습니다.', 'error');
    }
  }

  return (
    <AppShell
      title="사용자 관리"
      subtitle="계정 권한, 열람 허용 캡처, 잠금 해제, 2단계 인증 초기화를 관리합니다"
      actions={
        <button
          type="button"
          onClick={() => setShowCreate((prev) => !prev)}
          className="soc-btn-primary py-1.5 text-xs"
        >
          <UserPlus className="h-3.5 w-3.5" />
          신규 사용자 생성
        </button>
      }
    >
      <div className="space-y-5">
        {showCreate && (
          <section className="soc-card p-5">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <UserPlus className="h-4 w-4 text-slate-400" />
                신규 사용자 계정 생성
              </div>
              <button
                type="button"
                aria-label="생성 폼 닫기"
                onClick={() => setShowCreate(false)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={(e) => void handleCreateUser(e)} className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="create-username" className="mb-1 block text-xs font-medium text-slate-300">
                  아이디
                </label>
                <input
                  id="create-username"
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="영문·숫자 3~64자"
                  className="soc-input font-mono text-xs"
                />
              </div>

              <div>
                <label htmlFor="create-displayName" className="mb-1 block text-xs font-medium text-slate-300">
                  표시 이름
                </label>
                <input
                  id="create-displayName"
                  type="text"
                  required
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  placeholder="예: 홍길동 분석가"
                  className="soc-input text-xs"
                />
              </div>

              <div>
                <label htmlFor="create-password" className="mb-1 block text-xs font-medium text-slate-300">
                  초기 비밀번호
                </label>
                <input
                  id="create-password"
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="비밀번호 입력"
                  className="soc-input text-xs"
                />
              </div>

              <div>
                <label htmlFor="create-role" className="mb-1 block text-xs font-medium text-slate-300">
                  역할
                </label>
                <select
                  id="create-role"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                  className="soc-select w-full text-xs"
                >
                  {(data?.roles ?? ['VIEWER', 'ANALYST', 'ADMIN']).map((r) => (
                    <option key={r} value={r}>
                      {labelText('userRole', r)}
                    </option>
                  ))}
                </select>
              </div>

              <div className="md:col-span-2">
                <label htmlFor="create-patterns" className="mb-1 block text-xs font-medium text-slate-300">
                  열람 허용 캡처 (줄바꿈이나 쉼표로 구분, 예: cic17-*, syn1-*, 전체는 *)
                </label>
                <textarea
                  id="create-patterns"
                  rows={2}
                  required
                  value={newPatterns}
                  onChange={(e) => setNewPatterns(e.target.value)}
                  className="soc-input font-mono text-xs"
                />
              </div>

              <div className="flex justify-end gap-2 md:col-span-2">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="soc-btn-secondary text-xs"
                >
                  취소
                </button>
                <button type="submit" disabled={submitting} className="soc-btn-primary text-xs">
                  {submitting ? '생성 중...' : '사용자 생성'}
                </button>
              </div>
            </form>
          </section>
        )}

        {editingUser && (
          <section className="soc-card border-cyan-500/40 p-5">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-cyan-200">
                <Edit3 className="h-4 w-4 text-slate-400" />
                사용자 정보·권한 수정: <span className="font-mono">{editingUser.username}</span>
              </div>
              <button
                type="button"
                aria-label="수정 폼 닫기"
                onClick={() => setEditingUser(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={(e) => void handleUpdateUser(e)} className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="edit-displayName" className="mb-1 block text-xs font-medium text-slate-300">
                  표시 이름
                </label>
                <input
                  id="edit-displayName"
                  type="text"
                  required
                  value={editDisplayName}
                  onChange={(e) => setEditDisplayName(e.target.value)}
                  className="soc-input text-xs"
                />
              </div>

              <div>
                <label htmlFor="edit-role" className="mb-1 block text-xs font-medium text-slate-300">
                  역할
                </label>
                <select
                  id="edit-role"
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value as UserRole)}
                  className="soc-select w-full text-xs"
                >
                  {(data?.roles ?? ['VIEWER', 'ANALYST', 'ADMIN']).map((r) => (
                    <option key={r} value={r}>
                      {labelText('userRole', r)}
                    </option>
                  ))}
                </select>
              </div>

              <div className="md:col-span-2">
                <label htmlFor="edit-patterns" className="mb-1 block text-xs font-medium text-slate-300">
                  열람 허용 캡처 (줄바꿈이나 쉼표로 구분)
                </label>
                <textarea
                  id="edit-patterns"
                  rows={2}
                  required
                  value={editPatterns}
                  onChange={(e) => setEditPatterns(e.target.value)}
                  className="soc-input font-mono text-xs"
                />
              </div>

              <div className="flex justify-end gap-2 md:col-span-2">
                <button
                  type="button"
                  onClick={() => setEditingUser(null)}
                  className="soc-btn-secondary text-xs"
                >
                  취소
                </button>
                <button type="submit" disabled={submitting} className="soc-btn-primary text-xs">
                  {submitting ? '저장 중...' : '변경 저장'}
                </button>
              </div>
            </form>
          </section>
        )}

        {errorMsg && <ErrorAlert message={errorMsg.message} rateLimited={errorMsg.rateLimited} onRetry={() => void loadUsers()} />}

        {loading && !data ? (
          <LoadingPanel label="사용자 목록을 불러오는 중..." />
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 text-xs text-slate-400">
              <div className="flex items-center gap-2 font-semibold text-slate-200">
                <Users className="h-4 w-4 text-slate-400" />
                등록 사용자 ({data?.users.length ?? 0}명)
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr>
                    <th className="soc-th">아이디 · 표시 이름</th>
                    <th className="soc-th">역할</th>
                    <th className="soc-th">열람 허용 캡처</th>
                    <th className="soc-th">계정 · 2단계 인증 상태</th>
                    <th className="soc-th">수정 시각</th>
                    <th className="soc-th text-right">관리</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.users ?? []).map((u) => (
                    <tr key={u.id} className="hover:bg-slate-800/35">
                      <td className="soc-td text-xs">
                        <div className="font-mono font-semibold text-slate-100">{u.username}</div>
                        <div className="mt-0.5 text-slate-400">{u.displayName}</div>
                      </td>
                      <td className="soc-td">
                        <UserRoleBadge role={u.role} />
                      </td>
                      <td className="soc-td">
                        <div className="flex flex-wrap gap-1">
                          {u.capturePatterns.map((p) => (
                            <SocBadge key={p} tone="neutral">
                              <span className="font-mono">{p}</span>
                            </SocBadge>
                          ))}
                        </div>
                      </td>
                      <td className="soc-td text-xs">
                        <div className="flex flex-wrap gap-1">
                          <SocBadge tone={u.enabled ? 'neutral' : 'muted'}>{u.enabled ? '활성' : '비활성'}</SocBadge>
                          {u.lockedUntil && (
                            <SocBadge tone="attention">
                              잠김 · <span className="tabular-nums">{formatDateTime(u.lockedUntil)}</span>까지
                            </SocBadge>
                          )}
                          {u.role === 'ADMIN' && (
                            <SocBadge tone={u.totpEnabled ? 'neutral' : 'attention'}>
                              {u.totpEnabled ? '2단계 인증 등록됨' : '2단계 인증 미등록'}
                            </SocBadge>
                          )}
                        </div>
                        {u.failedAttempts > 0 && (
                          <div className="mt-1 text-[11px] tabular-nums text-amber-300">
                            로그인 실패 {u.failedAttempts}회
                          </div>
                        )}
                      </td>
                      <td className="soc-td whitespace-nowrap text-xs tabular-nums text-slate-400">
                        {formatDateTime(u.updatedAt ?? u.createdAt)}
                      </td>
                      <td className="soc-td text-right">
                        <div className="flex flex-wrap justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => openEditModal(u)}
                            className="soc-btn-secondary px-2.5 py-1 text-xs"
                          >
                            <Edit3 className="h-3 w-3" />
                            수정
                          </button>
                          <button
                            type="button"
                            onClick={() => void runRowAction(() => adminApi.toggleEnabled(u.id))}
                            className="soc-btn-secondary px-2.5 py-1 text-xs"
                          >
                            <Power className="h-3 w-3" />
                            {u.enabled ? '비활성화' : '활성화'}
                          </button>
                          <button
                            type="button"
                            onClick={() => void runRowAction(() => adminApi.unlockUser(u.id))}
                            className="soc-btn-secondary px-2.5 py-1 text-xs"
                          >
                            <LockOpen className="h-3 w-3" />
                            잠금 해제
                          </button>
                          {u.role === 'ADMIN' && (
                            <button
                              type="button"
                              onClick={() => void runRowAction(() => adminApi.resetTotp(u.id))}
                              className="soc-btn-caution px-2.5 py-1 text-xs"
                            >
                              <KeyRound className="h-3 w-3" />
                              2단계 인증 초기화
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
