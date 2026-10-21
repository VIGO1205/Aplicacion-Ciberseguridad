import { useEffect, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  Moon,
  ShieldCheck,
  Sparkles,
  Sun,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { apiErrorMessage, metaApi } from "../lib/api";
import type { DemoAccount } from "../types";
import { Badge, Button, Input } from "../components/ui";

const FALLBACK_ACCOUNTS: DemoAccount[] = [
  { email: "admin@soclite.local", password: "Admin2026!", name: "Valeria Ríos", role: "admin" },
  { email: "analista@soclite.local", password: "Analista2026!", name: "Camila Torres", role: "analyst" },
  { email: "auditor@soclite.local", password: "Auditor2026!", name: "Martín Quispe", role: "auditor" },
];

const ROLE_LABEL: Record<string, string> = {
  admin: "Administrador",
  supervisor: "Supervisor",
  analyst: "Analista SOC",
  auditor: "Auditor",
  viewer: "Consulta",
};

export function LoginPage() {
  const { login } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from || "/";

  const [email, setEmail] = useState("admin@soclite.local");
  const [password, setPassword] = useState("Admin2026!");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [accounts, setAccounts] = useState<DemoAccount[]>(FALLBACK_ACCOUNTS);

  useEffect(() => {
    metaApi
      .demoAccounts()
      .then((data) => {
        if (data.length) setAccounts(data);
      })
      .catch(() => undefined);
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email.trim(), password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-ink-950">
      <button
        type="button"
        onClick={toggleTheme}
        className="absolute right-5 top-5 z-10 flex items-center gap-2 rounded-lg border border-white/10 bg-slate-900/80 px-3 py-2 text-xs font-medium text-slate-300 transition hover:text-cyan-300"
        aria-label={theme === "dark" ? "Activar modo claro" : "Activar modo oscuro"}
      >
        {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        {theme === "dark" ? "Modo claro" : "Modo oscuro"}
      </button>
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-40 top-[-10%] h-[560px] w-[560px] rounded-full bg-cyan-500/[0.07] blur-[130px]" />
        <div className="absolute -right-40 bottom-[-15%] h-[600px] w-[600px] rounded-full bg-violet-500/[0.06] blur-[140px]" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(34,211,238,0.06),transparent_35%),radial-gradient(circle_at_80%_90%,rgba(139,92,246,0.06),transparent_40%)]" />
      </div>

      <div className="relative mx-auto grid min-h-screen w-full max-w-[1380px] items-center gap-12 px-6 py-10 lg:grid-cols-[1.05fr_0.95fr] lg:px-12">
        <section className="hidden lg:block">
          <div className="flex items-center gap-3">
            <div className="relative flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
              <ShieldCheck className="text-cyan-300" size={26} />
              <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-slate-950 bg-emerald-400" />
            </div>
            <div>
              <p className="text-sm font-bold tracking-[0.22em] text-white">SOC-LITE</p>
              <p className="text-[10px] uppercase tracking-[0.22em] text-slate-500">Security Operations Center</p>
            </div>
          </div>

          <h1 className="mt-14 max-w-xl text-4xl font-bold leading-[1.1] tracking-tight text-white xl:text-5xl">
            Menos ruido.
            <br />
            <span className="bg-gradient-to-r from-cyan-300 via-sky-300 to-violet-300 bg-clip-text text-transparent">
              Más decisiones.
            </span>
          </h1>
          <p className="mt-5 max-w-lg text-sm leading-relaxed text-slate-400">
            Triaje automático de alertas SOC con enriquecimiento contextual, razonamiento LLM local y
            trazabilidad completa. Diseñado para PYMEs y organismos públicos que necesitan operar 24/7 sin
            un SOAR corporativo.
          </p>

          <div className="mt-10 grid max-w-xl grid-cols-2 gap-3">
            {[
              { icon: Sparkles, title: "Triaje con LLM", text: "Clasificación, resumen y acciones recomendadas." },
              { icon: Fingerprint, title: "RBAC + auditoría", text: "Roles, permisos y bitácora por módulo." },
              { icon: LockKeyhole, title: "Datos en tu red", text: "Ollama local; sin exfiltración por defecto." },
              { icon: ShieldCheck, title: "ISO 27001 / NIST", text: "A.8.15, A.5.24 y DE.AE cubiertos." },
            ].map((item) => (
              <div key={item.title} className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
                <item.icon className="text-cyan-300" size={18} />
                <p className="mt-3 text-xs font-semibold text-white">{item.title}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-500">{item.text}</p>
              </div>
            ))}
          </div>

          <div className="mt-10 flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
            <Badge tone="cyan">NIST CSF 2.0</Badge>
            <Badge tone="violet">ISO 27001:2022</Badge>
            <Badge tone="neutral">PostgreSQL</Badge>
            <Badge tone="neutral">FastAPI + React</Badge>
          </div>
        </section>

        <section className="mx-auto w-full max-w-[460px]">
          <div className="mb-7 flex items-center gap-3 lg:hidden">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
              <ShieldCheck className="text-cyan-300" size={24} />
            </div>
            <div>
              <p className="text-sm font-bold tracking-[0.2em] text-white">SOC-LITE</p>
              <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Security Operations</p>
            </div>
          </div>

          <div className="rounded-3xl border border-white/[0.08] bg-slate-900/65 p-6 shadow-2xl backdrop-blur-xl sm:p-8">
            <div className="mb-7">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/[0.06] px-3 py-1 text-[10px] font-semibold text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                Entorno de demostración
              </div>
              <h2 className="text-2xl font-bold tracking-tight text-white">Acceso al SOC</h2>
              <p className="mt-1.5 text-sm text-slate-400">Autentíquese con sus credenciales corporativas.</p>
            </div>

            <form onSubmit={submit} className="space-y-4">
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-[38px] text-slate-500" size={16} />
                <Input
                  label="Correo electrónico"
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="pl-9"
                  placeholder="analista@soclite.local"
                />
              </div>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute left-3 top-[38px] text-slate-500" size={16} />
                <Input
                  label="Contraseña"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="pl-9 pr-10"
                  placeholder="••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute right-3 top-[33px] rounded p-1 text-slate-500 transition hover:text-slate-300"
                  aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              {error ? (
                <div className="rounded-lg border border-rose-400/20 bg-rose-400/10 px-3 py-2 text-xs text-rose-300">
                  {error}
                </div>
              ) : null}

              <Button type="submit" loading={loading} className="h-11 w-full justify-center">
                Iniciar sesión
                <ArrowRight size={16} />
              </Button>
            </form>

            <div className="mt-7">
              <div className="mb-3 flex items-center gap-3">
                <span className="h-px flex-1 bg-white/[0.07]" />
                <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">
                  Cuentas demo
                </span>
                <span className="h-px flex-1 bg-white/[0.07]" />
              </div>
              <div className="space-y-1.5">
                {accounts.slice(0, 4).map((account) => (
                  <button
                    key={account.email}
                    type="button"
                    onClick={() => {
                      setEmail(account.email);
                      setPassword(account.password);
                      setError("");
                    }}
                    className="flex w-full items-center justify-between gap-3 rounded-lg border border-transparent px-2.5 py-2 text-left transition hover:border-white/[0.08] hover:bg-white/[0.03]"
                  >
                    <span className="flex items-center gap-2.5">
                      <span className="flex h-7 w-7 items-center justify-center rounded-md bg-white/[0.06] text-[10px] font-bold text-slate-300">
                        {account.name
                          .split(" ")
                          .map((part) => part[0])
                          .slice(0, 2)
                          .join("")}
                      </span>
                      <span>
                        <span className="block text-[11px] font-medium text-slate-200">{account.name}</span>
                        <span className="block text-[10px] text-slate-500">{account.email}</span>
                      </span>
                    </span>
                    <Badge tone={account.role === "admin" ? "violet" : "neutral"} className="text-[9px]">
                      {ROLE_LABEL[account.role] || account.role}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <p className="mt-5 text-center text-[10px] leading-relaxed text-slate-600">
            Al acceder, sus entradas y salidas por módulo quedan registradas en la bitácora de auditoría.
          </p>
        </section>
      </div>
    </div>
  );
}
