import { useEffect, useMemo, useState, type FormEvent } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  ChevronDown,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Search,
  Settings,
  ShieldCheck,
  Siren,
  Moon,
  Sun,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { cn, initials, ROLE_LABEL } from "../lib/utils";
import { Badge } from "./ui";

const NAVIGATION = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, permission: "dashboard:read", end: true },
  { to: "/alerts", label: "Alertas", icon: Siren, permission: "alerts:read" },
  { to: "/incidents", label: "Incidentes", icon: AlertTriangle, permission: "incidents:read" },
  { to: "/reports", label: "Reportes", icon: FileText, permission: "reports:read" },
  { to: "/users", label: "Usuarios y roles", icon: Users, permission: "users:read" },
  { to: "/audit", label: "Auditoría", icon: Activity, permission: "audit:read" },
];

const PAGE_TITLES: Record<string, string> = {
  "/": "Panel de control",
  "/alerts": "Gestión de alertas",
  "/incidents": "Incidentes",
  "/reports": "Reportes",
  "/users": "Usuarios y roles",
  "/audit": "Bitácora de auditoría",
};

function Logo() {
  return (
    <div className="flex items-center gap-3">
      <div className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10">
        <ShieldCheck className="text-cyan-300" size={22} />
        <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-slate-950 bg-emerald-400" />
      </div>
      <div>
        <p className="text-sm font-bold tracking-[0.18em] text-white">SOC-LITE</p>
        <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">Security Operations</p>
      </div>
    </div>
  );
}

export function AppShell() {
  const { user, logout, hasPermission } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    setMobileOpen(false);
    setMenuOpen(false);
  }, [location.pathname]);

  const navigation = useMemo(
    () => NAVIGATION.filter((item) => hasPermission(item.permission)),
    [hasPermission],
  );

  const title = useMemo(() => {
    if (location.pathname.startsWith("/alerts/")) return "Detalle de alerta";
    if (location.pathname.startsWith("/incidents/")) return "Detalle de incidente";
    return PAGE_TITLES[location.pathname] || "SOC-Lite";
  }, [location.pathname]);

  const onSearch = (event: FormEvent) => {
    event.preventDefault();
    if (!search.trim()) return;
    navigate(`/alerts?q=${encodeURIComponent(search.trim())}`);
    setSearch("");
  };

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex h-[76px] items-center justify-between border-b border-white/[0.06] px-5">
        <Logo />
        <button
          type="button"
          className="rounded-lg p-1.5 text-slate-400 hover:bg-white/5 hover:text-white lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-label="Cerrar menú"
        >
          <X size={18} />
        </button>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5">
        <p className="mb-2 px-3 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600">Operaciones</p>
        {navigation.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition",
                isActive
                  ? "bg-cyan-400/10 text-cyan-200"
                  : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-100",
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive ? (
                  <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-cyan-400" />
                ) : null}
                <item.icon size={18} className={isActive ? "text-cyan-300" : "text-slate-500 group-hover:text-slate-300"} />
                <span>{item.label}</span>
                {item.to === "/alerts" ? (
                  <span className="ml-auto rounded-md bg-white/[0.06] px-1.5 py-0.5 text-[10px] font-semibold text-slate-400">
                    live
                  </span>
                ) : null}
              </>
            )}
          </NavLink>
        ))}

        <p className="mb-2 mt-7 px-3 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600">Sistema</p>
        <div className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-500">
          <Settings size={18} />
          <span>Configuración</span>
          <Badge tone="neutral" className="ml-auto text-[9px]">
            Próximamente
          </Badge>
        </div>
      </nav>

      <div className="border-t border-white/[0.06] p-4">
        <div className="rounded-xl border border-emerald-400/15 bg-emerald-400/[0.04] p-3">
          <div className="flex items-center gap-2 text-[11px] font-semibold text-emerald-300">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
            Motor de triaje operativo
          </div>
          <p className="mt-1.5 text-[10px] leading-relaxed text-slate-500">
            LangChain + Ollama local · modo híbrido con fallback
          </p>
        </div>
        <div className="mt-3 flex items-center justify-between px-1 text-[10px] text-slate-600">
          <span>v1.0.0</span>
          <span>ISO 27001 · NIST CSF</span>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-ink-950 text-slate-200">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-40 top-0 h-[460px] w-[460px] rounded-full bg-cyan-500/[0.05] blur-[120px]" />
        <div className="absolute -right-32 bottom-0 h-[420px] w-[420px] rounded-full bg-violet-500/[0.04] blur-[120px]" />
      </div>

      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[260px] border-r border-white/[0.06] bg-ink-900/80 backdrop-blur-xl lg:block">
        {sidebar}
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            className="modal-backdrop absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
            aria-label="Cerrar menú"
          />
          <aside className="relative h-full w-[280px] border-r border-white/10 bg-ink-900">{sidebar}</aside>
        </div>
      ) : null}

      <div className="relative lg:pl-[260px]">
        <header className="sticky top-0 z-30 flex h-[76px] items-center gap-3 border-b border-white/[0.06] bg-ink-950/75 px-4 backdrop-blur-xl sm:px-6">
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            className="rounded-lg border border-white/10 p-2 text-slate-300 hover:bg-white/5 lg:hidden"
            aria-label="Abrir menú"
          >
            <Menu size={18} />
          </button>

          <div className="hidden min-w-0 sm:block">
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">Centro de operaciones</p>
            <h2 className="truncate text-sm font-semibold text-white">{title}</h2>
          </div>

          <form onSubmit={onSearch} className="ml-auto hidden w-full max-w-xs items-center gap-2 md:flex">
            <div className="relative w-full">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={15} />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Buscar alerta, IP o host…"
                className="h-9 w-full rounded-lg border border-white/[0.08] bg-white/[0.03] pl-9 pr-3 text-xs text-white placeholder:text-slate-500 focus:border-cyan-400/40 focus:outline-none focus:ring-2 focus:ring-cyan-400/10"
              />
            </div>
          </form>

          <div className="ml-auto flex items-center gap-2 md:ml-0">
            <button
              type="button"
              onClick={toggleTheme}
              className="rounded-lg border border-white/[0.08] bg-white/[0.03] p-2 text-slate-400 transition hover:border-cyan-400/30 hover:text-cyan-300"
              aria-label={theme === "dark" ? "Activar modo claro" : "Activar modo oscuro"}
              title={theme === "dark" ? "Modo claro" : "Modo oscuro"}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <button
              type="button"
              onClick={() => navigate("/alerts?status=pending")}
              className="relative rounded-lg border border-white/[0.08] bg-white/[0.03] p-2 text-slate-400 transition hover:border-cyan-400/30 hover:text-cyan-300"
              aria-label="Alertas pendientes"
            >
              <Bell size={17} />
              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rose-400" />
            </button>

            <div className="relative">
              <button
                type="button"
                onClick={() => setMenuOpen((value) => !value)}
                className="flex items-center gap-2.5 rounded-xl border border-white/[0.08] bg-white/[0.03] py-1.5 pl-1.5 pr-2.5 text-left transition hover:border-white/20"
              >
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400/30 to-violet-400/30 text-xs font-bold text-cyan-100">
                  {initials(user?.full_name || "SL")}
                </span>
                <span className="hidden sm:block">
                  <span className="block text-xs font-semibold text-white">{user?.full_name}</span>
                  <span className="block text-[10px] text-slate-500">
                    {ROLE_LABEL[user?.role.name || ""] || user?.role.name}
                  </span>
                </span>
                <ChevronDown size={14} className="text-slate-500" />
              </button>
              {menuOpen ? (
                <div className="absolute right-0 top-12 w-60 overflow-hidden rounded-xl border border-white/10 bg-slate-900 shadow-2xl">
                  <div className="border-b border-white/10 px-4 py-3">
                    <p className="text-xs font-semibold text-white">{user?.full_name}</p>
                    <p className="mt-0.5 truncate text-[11px] text-slate-400">{user?.email}</p>
                    <p className="mt-1 text-[10px] text-slate-500">{user?.job_title || user?.department}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void logout()}
                    className="flex w-full items-center gap-2 px-4 py-3 text-left text-xs text-rose-300 transition hover:bg-rose-400/10"
                  >
                    <LogOut size={15} />
                    Cerrar sesión
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>

        <footer className="mx-auto flex w-full max-w-[1500px] flex-wrap items-center justify-between gap-2 px-4 pb-6 text-[10px] text-slate-600 sm:px-6 lg:px-8">
          <span>SOC-Lite · Plataforma de triaje y respuesta · Datos demo</span>
          <span className="flex items-center gap-1.5">
            <BarChart3 size={12} />
            PostgreSQL · FastAPI · LangChain
          </span>
        </footer>
      </div>
    </div>
  );
}
