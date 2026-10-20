import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { Card, Spinner } from "./ui";

function FullScreenLoader() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-ink-950">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
        <Spinner className="text-cyan-300" />
      </div>
      <p className="text-xs font-medium uppercase tracking-[0.2em] text-slate-500">Iniciando SOC-Lite</p>
    </div>
  );
}

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <FullScreenLoader />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

export function GuestOnly({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <FullScreenLoader />;
  if (user) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export function RequirePermission({ code, children }: { code: string; children: ReactNode }) {
  const { hasPermission } = useAuth();
  if (!hasPermission(code)) {
    return (
      <Card className="mx-auto mt-10 max-w-lg p-8 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-rose-400/20 bg-rose-400/10">
          <ShieldAlert className="text-rose-300" />
        </div>
        <h2 className="text-lg font-semibold text-white">Acceso restringido</h2>
        <p className="mt-2 text-sm text-slate-400">
          Su rol no tiene el permiso <span className="font-mono text-xs text-cyan-300">{code}</span>. Solicite
          acceso al administrador del SOC.
        </p>
      </Card>
    );
  }
  return <>{children}</>;
}
