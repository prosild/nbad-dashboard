import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Crown, Edit3, Plus, Trash2, X } from 'lucide-react';
import { ApiError, errorNotice, type ErrorNotice } from '../api/client';
import { adminApi } from '../api/endpoints';
import { AppShell } from '../components/AppShell';
import { ErrorAlert, LoadingPanel } from '../components/ErrorBanner';
import { StaleNotice } from '../components/StaleNotice';
import { useToast } from '../components/ToastContext';
import type { CriticalAssetItem, CriticalAssetListResponse } from '../types/api';
import { formatDateTime } from '../utils/format';

/** 규칙 한 줄(화면 제목 아래가 아니라 본문 첫 줄. T48: 제목 아래 설명 문장을 두지 않는다) */
export const CRITICAL_ASSET_RULE =
  '등록한 주소가 호스트인 미종결 인시던트는 자동 분류 우선순위를 한 단계 올립니다(Low → Medium, Medium → High). 같은 우선순위 안에서는 먼저 보입니다.';

function errorText(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

/**
 * T52 중요 자산 관리(관리자만). 목록(주소·이름·설명·고친 사람·시각), 추가, 고치기(이름·설명만), 지우기(확인을 한 번 더 받는다).
 * 서버가 주소(IPv4 하나의 정확한 꼴)·길이·중복을 검사하고, 화면은 서버의 오류 문장을 폼 아래에 보인다.
 */
export function AdminCriticalAssetsPage() {
  const { notify } = useToast();
  const [data, setData] = useState<CriticalAssetListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<ErrorNotice | null>(null);
  const [loadedAt, setLoadedAt] = useState<string | null>(null);
  const seq = useRef(0);

  const [showCreate, setShowCreate] = useState(false);
  const [newHostIp, setNewHostIp] = useState('');
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [createError, setCreateError] = useState<string | null>(null);

  const [editing, setEditing] = useState<CriticalAssetItem | null>(null);
  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editError, setEditError] = useState<string | null>(null);

  const [confirmingId, setConfirmingId] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const res = await adminApi.listCriticalAssets();
      if (my !== seq.current) return;
      setData(res);
      setLoadedAt(new Date().toISOString());
      setFailure(null);
    } catch (err) {
      if (my !== seq.current) return;
      setFailure(errorNotice(err, '중요 자산 목록을 불러오지 못했습니다.'));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function closeCreate() {
    setShowCreate(false);
    setNewHostIp('');
    setNewName('');
    setNewDescription('');
    setCreateError(null);
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setCreateError(null);
    try {
      const description = newDescription.trim();
      const res = await adminApi.createCriticalAsset({
        hostIp: newHostIp.trim(),
        name: newName.trim(),
        description: description === '' ? null : description,
      });
      notify(res.message, 'success');
      closeCreate();
      await load();
    } catch (err) {
      setCreateError(errorText(err, '중요 자산을 등록하지 못했습니다.'));
    } finally {
      setSubmitting(false);
    }
  }

  function openEdit(item: CriticalAssetItem) {
    setConfirmingId(null);
    setEditing(item);
    setEditName(item.name);
    setEditDescription(item.description ?? '');
    setEditError(null);
  }

  async function handleUpdate(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    setSubmitting(true);
    setEditError(null);
    try {
      const description = editDescription.trim();
      const res = await adminApi.updateCriticalAsset(editing.id, {
        name: editName.trim(),
        description: description === '' ? null : description,
      });
      notify(res.message, 'success');
      setEditing(null);
      await load();
    } catch (err) {
      setEditError(errorText(err, '중요 자산을 고치지 못했습니다.'));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(item: CriticalAssetItem) {
    setSubmitting(true);
    try {
      const res = await adminApi.deleteCriticalAsset(item.id);
      notify(res.message, 'success');
      setConfirmingId(null);
      if (editing?.id === item.id) setEditing(null);
      await load();
    } catch (err) {
      notify(errorText(err, '중요 자산을 지우지 못했습니다.'), 'error');
    } finally {
      setSubmitting(false);
    }
  }

  const items = data?.items ?? [];

  return (
    <AppShell
      title="중요 자산"
      actions={
        <button type="button" onClick={() => (showCreate ? closeCreate() : setShowCreate(true))} className="soc-btn-primary py-1.5 text-xs">
          <Plus className="h-3.5 w-3.5" aria-hidden="true" />
          중요 자산 추가
        </button>
      }
    >
      <div className="space-y-5">
        <p className="flex items-start gap-1.5 text-xs text-slate-400">
          <Crown className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-300" aria-hidden="true" />
          <span>{CRITICAL_ASSET_RULE}</span>
        </p>

        {showCreate && (
          <section className="soc-card p-5">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <Plus className="h-4 w-4 text-slate-400" aria-hidden="true" />
                중요 자산 추가
              </h2>
              <button
                type="button"
                aria-label="추가 폼 닫기"
                onClick={closeCreate}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            <form
              aria-label="중요 자산 추가"
              onSubmit={(e) => void handleCreate(e)}
              className="grid grid-cols-1 gap-4 md:grid-cols-2"
            >
              <div>
                <label htmlFor="asset-hostIp" className="mb-1 block text-xs font-medium text-slate-300">
                  주소
                </label>
                <input
                  id="asset-hostIp"
                  type="text"
                  required
                  inputMode="decimal"
                  autoComplete="off"
                  value={newHostIp}
                  onChange={(e) => setNewHostIp(e.target.value)}
                  placeholder="IPv4 하나(예: 10.10.0.20)"
                  className="soc-input font-mono text-xs"
                />
              </div>
              <div>
                <label htmlFor="asset-name" className="mb-1 block text-xs font-medium text-slate-300">
                  이름
                </label>
                <input
                  id="asset-name"
                  type="text"
                  required
                  maxLength={100}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="예: 실습망 대상 서버"
                  className="soc-input text-xs"
                />
              </div>
              <div className="md:col-span-2">
                <label htmlFor="asset-description" className="mb-1 block text-xs font-medium text-slate-300">
                  설명
                </label>
                <input
                  id="asset-description"
                  type="text"
                  maxLength={300}
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="선택. 관리자 화면에만 보입니다"
                  className="soc-input text-xs"
                />
              </div>
              {createError && (
                <p role="alert" className="text-xs text-amber-200 md:col-span-2">
                  {createError}
                </p>
              )}
              <div className="flex justify-end gap-2 md:col-span-2">
                <button type="button" onClick={closeCreate} className="soc-btn-secondary text-xs">
                  취소
                </button>
                <button type="submit" disabled={submitting} className="soc-btn-primary text-xs">
                  등록
                </button>
              </div>
            </form>
          </section>
        )}

        {editing && (
          <section className="soc-card border-cyan-500/40 p-5">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-cyan-200">
                <Edit3 className="h-4 w-4 text-slate-400" aria-hidden="true" />
                중요 자산 고치기
              </h2>
              <button
                type="button"
                aria-label="고치기 폼 닫기"
                onClick={() => setEditing(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            <form
              aria-label="중요 자산 고치기"
              onSubmit={(e) => void handleUpdate(e)}
              className="grid grid-cols-1 gap-4 md:grid-cols-2"
            >
              <div className="md:col-span-2 text-xs text-slate-400">
                주소 <span className="font-mono font-semibold text-slate-100">{editing.hostIp}</span>
                <span className="ml-2 text-slate-500">(주소를 바꾸려면 지우고 새로 추가합니다)</span>
              </div>
              <div>
                <label htmlFor="asset-edit-name" className="mb-1 block text-xs font-medium text-slate-300">
                  이름
                </label>
                <input
                  id="asset-edit-name"
                  type="text"
                  required
                  maxLength={100}
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="soc-input text-xs"
                />
              </div>
              <div>
                <label htmlFor="asset-edit-description" className="mb-1 block text-xs font-medium text-slate-300">
                  설명
                </label>
                <input
                  id="asset-edit-description"
                  type="text"
                  maxLength={300}
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  className="soc-input text-xs"
                />
              </div>
              {editError && (
                <p role="alert" className="text-xs text-amber-200 md:col-span-2">
                  {editError}
                </p>
              )}
              <div className="flex justify-end gap-2 md:col-span-2">
                <button type="button" onClick={() => setEditing(null)} className="soc-btn-secondary text-xs">
                  취소
                </button>
                <button type="submit" disabled={submitting} className="soc-btn-primary text-xs">
                  저장
                </button>
              </div>
            </form>
          </section>
        )}

        {failure && data && (
          <StaleNotice notice={failure} loadedAt={loadedAt} loading={loading} onRetry={() => void load()} />
        )}
        {failure && !data && (
          <ErrorAlert message={failure.message} rateLimited={failure.rateLimited} onRetry={() => void load()} />
        )}

        {!data ? (
          loading ? <LoadingPanel label="중요 자산 목록을 불러오는 중..." /> : null
        ) : (
          <div className="soc-card overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 text-xs text-slate-400">
              <div className="flex items-center gap-2 font-semibold text-slate-200">
                <Crown className="h-4 w-4 text-slate-400" aria-hidden="true" />
                등록 {items.length}개 · 최대 {data.limit}개
              </div>
            </div>
            {items.length === 0 ? (
              <p className="px-4 py-6 text-center text-xs text-slate-400">등록한 중요 자산이 없습니다.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr>
                      <th className="soc-th">주소</th>
                      <th className="soc-th">이름</th>
                      <th className="soc-th">설명</th>
                      <th className="soc-th">고친 사람 · 시각</th>
                      <th className="soc-th text-right">관리</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.id} className="align-top hover:bg-slate-800/35">
                        <td className="soc-td whitespace-nowrap font-mono text-xs font-semibold text-slate-100">{item.hostIp}</td>
                        <td className="soc-td text-xs text-slate-100">{item.name}</td>
                        <td className="soc-td text-xs text-slate-300">
                          {item.description ?? <span className="text-slate-600">-</span>}
                        </td>
                        <td className="soc-td whitespace-nowrap text-xs tabular-nums text-slate-400">
                          {item.updatedBy} · {formatDateTime(item.updatedAt)}
                        </td>
                        <td className="soc-td text-right">
                          {confirmingId === item.id ? (
                            <div
                              role="group"
                              aria-label={`${item.hostIp} 지우기 확인`}
                              className="ml-auto max-w-xs space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-left text-xs text-amber-100"
                            >
                              <p className="flex items-start gap-1.5">
                                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" aria-hidden="true" />
                                <span>
                                  {item.hostIp}({item.name})을 지울까요? 되돌릴 수 없습니다. 이 주소의 인시던트는 원래 우선순위로
                                  돌아갑니다.
                                </span>
                              </p>
                              <div className="flex gap-1.5">
                                <button
                                  type="button"
                                  disabled={submitting}
                                  onClick={() => void handleDelete(item)}
                                  className="soc-btn-caution flex-1 px-2 py-1 text-xs"
                                >
                                  <Trash2 className="h-3 w-3" aria-hidden="true" />
                                  지우기 확정
                                </button>
                                <button
                                  type="button"
                                  disabled={submitting}
                                  onClick={() => setConfirmingId(null)}
                                  className="soc-btn-secondary flex-1 px-2 py-1 text-xs"
                                >
                                  취소
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="flex flex-wrap justify-end gap-1.5">
                              <button
                                type="button"
                                aria-label={`${item.hostIp} 고치기`}
                                onClick={() => openEdit(item)}
                                className="soc-btn-secondary px-2.5 py-1 text-xs"
                              >
                                <Edit3 className="h-3 w-3" aria-hidden="true" />
                                고치기
                              </button>
                              <button
                                type="button"
                                aria-label={`${item.hostIp} 지우기`}
                                onClick={() => setConfirmingId(item.id)}
                                className="soc-btn-caution px-2.5 py-1 text-xs"
                              >
                                <Trash2 className="h-3 w-3" aria-hidden="true" />
                                지우기
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}
