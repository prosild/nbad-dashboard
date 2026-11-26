import { BrowserRouter, Route, Routes } from 'react-router-dom';
import {
  AuthProvider,
  RequireAdmin,
  RequireAuth,
  RequireTotpRoute,
} from './auth/AuthContext';
import { ToastProvider } from './components/ToastContext';
import { AdminAuditLogsPage } from './pages/AdminAuditLogsPage';
import { AdminUsersPage } from './pages/AdminUsersPage';
import { DashboardPage } from './pages/DashboardPage';
import { HostsPage } from './pages/HostsPage';
import { IncidentDetailPage } from './pages/IncidentDetailPage';
import { IncidentQueuePage } from './pages/IncidentQueuePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OperationsPage } from './pages/OperationsPage';
import { ReviewsPage } from './pages/ReviewsPage';
import { TotpPage } from './pages/TotpPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/login/totp/setup"
        element={
          <RequireTotpRoute mode="setup">
            <TotpPage mode="setup" />
          </RequireTotpRoute>
        }
      />
      <Route
        path="/login/totp"
        element={
          <RequireTotpRoute mode="verify">
            <TotpPage mode="verify" />
          </RequireTotpRoute>
        }
      />
      <Route
        path="/"
        element={
          <RequireAuth>
            <DashboardPage />
          </RequireAuth>
        }
      />
      <Route
        path="/incidents"
        element={
          <RequireAuth>
            <IncidentQueuePage />
          </RequireAuth>
        }
      />
      {/* T27 인시던트 번호 고정 주소. 숫자가 아니면 화면이 잘못된 경로 안내를 보인다 */}
      <Route
        path="/incidents/:incidentNo"
        element={
          <RequireAuth>
            <IncidentDetailPage />
          </RequireAuth>
        }
      />
      <Route
        path="/incidents/:jobId/rank/:queueRank"
        element={
          <RequireAuth>
            <IncidentDetailPage />
          </RequireAuth>
        }
      />
      {/* T46 호스트 위험도(모든 역할) */}
      <Route
        path="/hosts"
        element={
          <RequireAuth>
            <HostsPage />
          </RequireAuth>
        }
      />
      <Route
        path="/reviews"
        element={
          <RequireAuth>
            <ReviewsPage />
          </RequireAuth>
        }
      />
      <Route
        path="/operations"
        element={
          <RequireAuth>
            <OperationsPage />
          </RequireAuth>
        }
      />
      <Route
        path="/admin/users"
        element={
          <RequireAuth>
            <RequireAdmin>
              <AdminUsersPage />
            </RequireAdmin>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/audit-logs"
        element={
          <RequireAuth>
            <RequireAdmin>
              <AdminAuditLogsPage />
            </RequireAdmin>
          </RequireAuth>
        }
      />
      {/* T50 없는 주소: 현황판으로 돌려보내지 않고 NotFound 화면을 보인다. 로그인 전이면 다른 보호 경로와 같게 로그인으로 간다 */}
      <Route
        path="*"
        element={
          <RequireAuth>
            <NotFoundPage />
          </RequireAuth>
        }
      />
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  );
}

export default App;
