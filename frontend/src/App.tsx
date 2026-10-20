import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { GuestOnly, ProtectedRoute, RequirePermission } from "./components/guards";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { AlertsPage } from "./pages/AlertsPage";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { UsersPage } from "./pages/UsersPage";
import { AuditPage } from "./pages/AuditPage";
import { NotFoundPage } from "./pages/NotFoundPage";

export function App() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <GuestOnly>
            <LoginPage />
          </GuestOnly>
        }
      />
      <Route
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route
          index
          element={
            <RequirePermission code="dashboard:read">
              <DashboardPage />
            </RequirePermission>
          }
        />
        <Route
          path="alerts"
          element={
            <RequirePermission code="alerts:read">
              <AlertsPage />
            </RequirePermission>
          }
        />
        <Route
          path="alerts/:id"
          element={
            <RequirePermission code="alerts:read">
              <AlertDetailPage />
            </RequirePermission>
          }
        />
        <Route
          path="incidents"
          element={
            <RequirePermission code="incidents:read">
              <IncidentsPage />
            </RequirePermission>
          }
        />
        <Route
          path="reports"
          element={
            <RequirePermission code="reports:read">
              <ReportsPage />
            </RequirePermission>
          }
        />
        <Route
          path="users"
          element={
            <RequirePermission code="users:read">
              <UsersPage />
            </RequirePermission>
          }
        />
        <Route
          path="audit"
          element={
            <RequirePermission code="audit:read">
              <AuditPage />
            </RequirePermission>
          }
        />
        <Route path="404" element={<NotFoundPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/404" replace />} />
    </Routes>
  );
}
