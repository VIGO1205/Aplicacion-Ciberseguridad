import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  FileDown,
  Filter,
  Fingerprint,
  RefreshCw,
  Search,
  ShieldCheck,
  Users,
} from "lucide-react";
import { apiErrorMessage, auditApi } from "../lib/api";
import { useModuleAudit } from "../hooks/useModuleAudit";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingBlock,
  PageHeader,
  Pagination,
  Select,
} from "../components/ui";
import type { AuditLog } from "../types";
import { formatDateTime } from "../lib/utils";

const PAGE_SIZE = 20;

const EVENT_LABEL: Record<string, string> = {
  LOGIN: "Inicio de sesión",
  LOGOUT: "Cierre de sesión",
  LOGIN_FAILED: "Login fallido",
  TOKEN_REFRESH: "Renovación de token",
  MODULE_ENTER: "Entrada a módulo",
  MODULE_EXIT: "Salida de módulo",
  API_ACCESS: "Acceso a API",
  CREATE: "Creación",
  UPDATE: "Actualización",
  CLOSE: "Cierre",
  EXPORT: "Exportación",
  DOWNLOAD: "Descarga",
  TRIAGE: "Triaje",
  INGEST: "Ingesta",
  PASSWORD_CHANGE: "Cambio de contraseña",
};

const MODULE_LABEL: Record<string, string> = {
  auth: "Autenticación",
  dashboard: "Dashboard",
  alerts: "Alertas",
  incidents: "Incidentes",
  reports: "Reportes",
  users: "Usuarios",
  roles: "Roles",
  audit: "Auditoría",
  ingest: "Ingesta",
  settings: "Configuración",
};

function eventTone(event: string) {
  if (event.includes("FAILED") || event === "TRIAGE_ERROR") return "danger" as const;
  if (event === "LOGIN" || event === "LOGOUT" || event.startsWith("MODULE")) return "cyan" as const;
  if (event === "CREATE" || event === "INGEST") return "ok" as const;
  if (event === "UPDATE" || event === "CLOSE") return "warn" as const;
  if (event === "EXPORT" || event === "DOWNLOAD") return "violet" as const;
  return "neutral" as const;
}

export function AuditPage() {
  useModuleAudit("audit");
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [module, setModule] = useState("");
  const [eventType, setEventType] = useState("");
  const [direction, setDirection] = useState("");

  const filters = useMemo(
    () => ({
      page,
      page_size: PAGE_SIZE,
      q: search || undefined,
      module: module || undefined,
      event_type: eventType || undefined,
      direction: direction || undefined,
    }),
    [page, search, module, eventType, direction],
  );

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["audit", filters],
    queryFn: () => auditApi.list(filters),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });

  const { data: stats } = useQuery({
    queryKey: ["audit-stats"],
    queryFn: () => auditApi.stats(7),
    refetchInterval: 60_000,
  });

  const { data: options } = useQuery({
    queryKey: ["audit-options"],
    queryFn: auditApi.options,
  });

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Cumplimiento"
        title="Bitácora de auditoría"
        subtitle="Registro inmutable de entradas y salidas por módulo, acciones, usuario, fecha y hora."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void refetch()} loading={isFetching}>
              <RefreshCw size={14} /> Actualizar
            </Button>
            <Link to="/reports">
              <Button size="sm">
                <FileDown size={14} /> Reporte de auditoría
              </Button>
            </Link>
          </>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {
            label: "Eventos (7 días)",
            value: stats?.total_events ?? "—",
            icon: Activity,
            tone: "text-cyan-300",
          },
          {
            label: "Usuarios activos",
            value: stats?.active_users ?? "—",
            icon: Users,
            tone: "text-violet-300",
          },
          {
            label: "Entradas",
            value: stats?.by_direction.find((item) => item.name === "IN")?.value ?? 0,
            icon: ArrowDownLeft,
            tone: "text-emerald-300",
          },
          {
            label: "Salidas",
            value: stats?.by_direction.find((item) => item.name === "OUT")?.value ?? 0,
            icon: ArrowUpRight,
            tone: "text-amber-300",
          },
        ].map((item) => (
          <Card key={item.label} className="flex items-center gap-3 p-4">
            <item.icon size={18} className={item.tone} />
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
              <p className="mt-0.5 text-xl font-bold text-white">{item.value}</p>
            </div>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div>
          <Card className="mb-5 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative min-w-[220px] flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={15} />
                <input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                    setPage(1);
                  }}
                  placeholder="Buscar acción, descripción, IP o entidad…"
                  className="h-10 w-full rounded-lg border border-white/10 bg-slate-950/60 pl-9 pr-3 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10"
                />
              </div>
              <Select
                value={module}
                onChange={(event) => {
                  setModule(event.target.value);
                  setPage(1);
                }}
                className="w-40"
                aria-label="Módulo"
              >
                <option value="">Módulo</option>
                {(options?.modules || []).map((item) => (
                  <option key={item} value={item}>
                    {MODULE_LABEL[item] || item}
                  </option>
                ))}
              </Select>
              <Select
                value={eventType}
                onChange={(event) => {
                  setEventType(event.target.value);
                  setPage(1);
                }}
                className="w-44"
                aria-label="Tipo de evento"
              >
                <option value="">Tipo de evento</option>
                {(options?.event_types || []).map((item) => (
                  <option key={item} value={item}>
                    {EVENT_LABEL[item] || item}
                  </option>
                ))}
              </Select>
              <Select
                value={direction}
                onChange={(event) => {
                  setDirection(event.target.value);
                  setPage(1);
                }}
                className="w-32"
                aria-label="Dirección"
              >
                <option value="">Dirección</option>
                <option value="IN">Entrada</option>
                <option value="OUT">Salida</option>
              </Select>
            </div>
          </Card>

          <div className="table-shell">
            <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3 text-xs">
              <span className="text-slate-400">
                <span className="font-semibold text-slate-200">{data?.total ?? "—"}</span> eventos registrados
              </span>
              <Badge tone="ok" dot>
                Inmutable · solo lectura
              </Badge>
            </div>
            {isLoading ? <LoadingBlock label="Consultando bitácora…" /> : null}
            {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}
            {!isLoading && !error && data ? (
              data.items.length ? (
                <>
                  <div className="overflow-x-auto">
                    <table className="table-base">
                      <thead>
                        <tr>
                          <th>Fecha / hora</th>
                          <th>Usuario</th>
                          <th>Módulo</th>
                          <th>Evento</th>
                          <th className="hidden lg:table-cell">Acción</th>
                          <th>Dir.</th>
                          <th className="hidden xl:table-cell">IP</th>
                          <th className="hidden xl:table-cell">HTTP</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.items.map((log) => (
                          <AuditRow key={log.id} log={log} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Pagination
                    page={data.page}
                    pages={data.pages}
                    total={data.total}
                    pageSize={data.page_size}
                    onChange={setPage}
                  />
                </>
              ) : (
                <EmptyState
                  icon={<Filter size={20} />}
                  title="Sin eventos con esos filtros"
                  description="La bitácora registra automáticamente accesos, triajes, cambios y exportaciones."
                />
              )
            ) : null}
          </div>
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader title="Actividad por módulo" subtitle="Últimos 7 días" />
            <div className="space-y-3 px-5 py-4">
              {(stats?.by_module || []).slice(0, 8).map((item) => {
                const max = Math.max(1, ...(stats?.by_module.map((entry) => entry.value) || [1]));
                return (
                  <div key={item.name}>
                    <div className="mb-1 flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">{MODULE_LABEL[item.name] || item.name}</span>
                      <span className="font-semibold text-slate-200">{item.value}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                      <div className="h-full rounded-full bg-cyan-400/80" style={{ width: `${Math.max(4, (item.value / max) * 100)}%` }} />
                    </div>
                  </div>
                );
              })}
              {!stats?.by_module.length ? <p className="py-4 text-center text-xs text-slate-500">Sin actividad.</p> : null}
            </div>
          </Card>

          <Card>
            <CardHeader title="Tipos de evento" />
            <div className="flex flex-wrap gap-2 px-5 py-4">
              {(stats?.by_event || []).map((item) => (
                <span
                  key={item.name}
                  className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[10px] text-slate-300"
                >
                  {EVENT_LABEL[item.name] || item.name}
                  <span className="font-semibold text-cyan-300">{item.value}</span>
                </span>
              ))}
              {!stats?.by_event.length ? <p className="text-xs text-slate-500">Sin eventos.</p> : null}
            </div>
          </Card>

          <Card className="border-emerald-400/15 bg-emerald-400/[0.03]">
            <div className="p-5">
              <ShieldCheck className="text-emerald-300" size={20} />
              <p className="mt-3 text-xs font-semibold text-emerald-100">Trazabilidad para auditoría</p>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                La bitácora registra usuario, rol, módulo, acción, dirección, IP, agente, resultado HTTP y
                request ID. Conserva los registros según la política de retención.
              </p>
              <div className="mt-3 flex items-center gap-1.5 text-[10px] text-slate-500">
                <Fingerprint size={12} /> Hash de correlación por request
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function AuditRow({ log }: { log: AuditLog }) {
  return (
    <tr>
      <td className="whitespace-nowrap text-[11px] text-slate-400">{formatDateTime(log.created_at)}</td>
      <td>
        <p className="text-xs font-medium text-slate-200">{log.actor_email}</p>
        <p className="text-[10px] capitalize text-slate-500">{log.actor_role || "sistema"}</p>
      </td>
      <td>
        <Badge tone="neutral" className="text-[9px]">
          {MODULE_LABEL[log.module] || log.module}
        </Badge>
      </td>
      <td>
        <Badge tone={eventTone(log.event_type)} className="text-[9px]">
          {EVENT_LABEL[log.event_type] || log.event_type}
        </Badge>
      </td>
      <td className="hidden max-w-[280px] lg:table-cell">
        <p className="truncate text-[11px] text-slate-300" title={log.action}>
          {log.action}
        </p>
        {log.entity_id ? <p className="truncate font-mono text-[9px] text-slate-600">{log.entity_id}</p> : null}
      </td>
      <td>
        {log.direction === "IN" ? (
          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-300">
            <ArrowDownLeft size={12} /> IN
          </span>
        ) : log.direction === "OUT" ? (
          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-amber-300">
            <ArrowUpRight size={12} /> OUT
          </span>
        ) : (
          <span className="text-slate-700">—</span>
        )}
      </td>
      <td className="hidden font-mono text-[10px] text-slate-500 xl:table-cell">{log.ip_address || "—"}</td>
      <td className="hidden xl:table-cell">
        <span
          className={`font-mono text-[10px] ${
            !log.status_code
              ? "text-slate-600"
              : log.status_code >= 400
                ? "text-rose-400"
                : "text-emerald-400"
          }`}
        >
          {log.status_code || "—"}
        </span>
      </td>
    </tr>
  );
}
