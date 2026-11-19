import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import {
  AuthProvider,
  RequireAdmin,
  RequireAuth,
  RequireTotpRoute,
} from './auth/AuthContext';
import { ToastProvider } from './components/ToastContext';
import { AdminAuditLogsPage } from './pages/AdminAuditLogsPage';
import { AdminUsersPage } from './pages/AdminUsersPage';
import { IncidentDetailPage } from './pages/IncidentDetailPage';
import { IncidentQueuePage } from './pages/IncidentQueuePage';
import { LoginPage } from './pages/LoginPage';
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
            <IncidentQueuePage />
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
      <Route
        path="/incidents/:jobId/rank/:queueRank"
        element={
          <RequireAuth>
            <IncidentDetailPage />
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
      <Route path="*" element={<Navigate to="/" replace />} />
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
