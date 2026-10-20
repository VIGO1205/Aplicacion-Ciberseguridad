import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Eye,
  RefreshCw,
  Search,
  ShieldCheck,
  Users,
} from "lucide-react";
import { apiErrorMessage, incidentsApi } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useModuleAudit } from "../hooks/useModuleAudit";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  Input,
  LoadingBlock,
  Modal,
  PageHeader,
  Pagination,
  Select,
  SeverityBadge,
  Textarea,
} from "../components/ui";
import type { Incident, IncidentStatus, Severity } from "../types";
import {
  INCIDENT_STATUS_LABEL,
  SEVERITY_LABEL,
  formatDateTime,
  slaState,
  timeAgo,
} from "../lib/utils";

const PAGE_SIZE = 15;

export function IncidentsPage() {
  useModuleAudit("incidents");
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const [selected, setSelected] = useState<Incident | null>(null);
  const [saving, setSaving] = useState(false);
  const [note, setNote] = useState("");

  const page = Math.max(1, Number(params.get("page") || "1"));
  const filters = useMemo(
    () => ({
      q: params.get("q") || undefined,
      status: params.get("status") || undefined,
      severity: params.get("severity") || undefined,
      page,
      page_size: PAGE_SIZE,
    }),
    [params, page],
  );

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["incidents", filters],
    queryFn: () => incidentsApi.list(filters),
    placeholderData: keepPreviousData,
  });

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next, { replace: true });
  };

  const openDetail = (incident: Incident) => {
    setSelected(incident);
    setNote("");
  };

  const updateStatus = async (status: IncidentStatus) => {
    if (!selected) return;
    if (status === "closed" && !window.confirm(`¿Cerrar el incidente ${selected.code}?`)) return;
    setSaving(true);
    try {
      const updated = await incidentsApi.update(selected.id, {
        status,
        description: selected.description,
        containment_actions: note || selected.containment_actions,
      });
      setSelected(updated);
      toast(`Incidente ${updated.code} actualizado a ${INCIDENT_STATUS_LABEL[status]}`, "success");
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setSaving(false);
    }
  };

  const closeIncident = async () => {
    if (!selected) return;
    setSaving(true);
    try {
      const updated = await incidentsApi.close(selected.id);
      setSelected(updated);
      toast(`Incidente ${updated.code} cerrado`, "success");
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Respuesta"
        title="Incidentes"
        subtitle="Casos escalados desde alertas, con responsable, acciones de contención y seguimiento de SLA."
        actions={
          <Button variant="outline" size="sm" onClick={() => void refetch()} loading={isFetching}>
            <RefreshCw size={14} /> Actualizar
          </Button>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: "Total", value: data?.total ?? "—", icon: AlertTriangle, tone: "text-cyan-300" },
          {
            label: "Abiertos · pág.",
            value: data?.items.filter((item) => ["open", "investigating", "contained"].includes(item.status)).length ?? "—",
            icon: Clock3,
            tone: "text-amber-300",
          },
          {
            label: "Contenidos · pág.",
            value: data?.items.filter((item) => item.status === "contained").length ?? "—",
            icon: ShieldCheck,
            tone: "text-emerald-300",
          },
          {
            label: "Cerrados · pág.",
            value: data?.items.filter((item) => ["resolved", "closed"].includes(item.status)).length ?? "—",
            icon: CheckCircle2,
            tone: "text-slate-300",
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

      <Card className="mb-5 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              updateParam("q", search.trim());
            }}
            className="relative min-w-[220px] flex-1"
          >
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={15} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Buscar por código, título o descripción…"
              className="h-10 w-full rounded-lg border border-white/10 bg-slate-950/60 pl-9 pr-3 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10"
            />
          </form>
          <Select
            value={params.get("status") || ""}
            onChange={(event) => updateParam("status", event.target.value)}
            className="w-40"
            aria-label="Estado"
          >
            <option value="">Estado</option>
            {(Object.keys(INCIDENT_STATUS_LABEL) as IncidentStatus[]).map((status) => (
              <option key={status} value={status}>
                {INCIDENT_STATUS_LABEL[status]}
              </option>
            ))}
          </Select>
          <Select
            value={params.get("severity") || ""}
            onChange={(event) => updateParam("severity", event.target.value)}
            className="w-36"
            aria-label="Severidad"
          >
            <option value="">Severidad</option>
            {(Object.keys(SEVERITY_LABEL) as Severity[]).map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABEL[severity]}
              </option>
            ))}
          </Select>
        </div>
      </Card>

      <div className="table-shell">
        {isLoading ? <LoadingBlock label="Cargando incidentes…" /> : null}
        {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}
        {!isLoading && !error && data ? (
          data.items.length ? (
            <>
              <div className="overflow-x-auto">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th>Código</th>
                      <th>Incidente</th>
                      <th>Severidad</th>
                      <th>Estado</th>
                      <th className="hidden md:table-cell">Responsable</th>
                      <th className="hidden lg:table-cell">SLA</th>
                      <th className="hidden xl:table-cell">Apertura</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((incident) => {
                      const sla = slaState(incident.sla_due_at, incident.closed_at);
                      return (
                        <tr key={incident.id} className="cursor-pointer" onClick={() => openDetail(incident)}>
                          <td className="whitespace-nowrap font-mono text-[11px] text-cyan-300">{incident.code}</td>
                          <td className="max-w-[380px]">
                            <p className="truncate text-[13px] font-medium text-slate-100">{incident.title}</p>
                            <p className="mt-0.5 text-[10px] text-slate-500">
                              {incident.ticket_external_id ? `Ticket ${incident.ticket_external_id}` : "Sin ticket externo"}
                            </p>
                          </td>
                          <td>
                            <SeverityBadge severity={incident.severity} />
                          </td>
                          <td>
                            <IncidentStatusBadge status={incident.status} />
                          </td>
                          <td className="hidden text-xs text-slate-400 md:table-cell">
                            {incident.owner?.full_name || "Sin asignar"}
                          </td>
                          <td className="hidden lg:table-cell">
                            <Badge tone={sla.tone === "danger" ? "danger" : sla.tone === "warn" ? "warn" : "ok"}>
                              {sla.label}
                            </Badge>
                          </td>
                          <td className="hidden text-[11px] text-slate-500 xl:table-cell">
                            {formatDateTime(incident.opened_at)}
                          </td>
                          <td>
                            <ChevronRight size={15} className="text-slate-600" />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pagination
                page={data.page}
                pages={data.pages}
                total={data.total}
                pageSize={data.page_size}
                onChange={(nextPage) => updateParam("page", String(nextPage))}
              />
            </>
          ) : (
            <EmptyState
              icon={<AlertTriangle size={20} />}
              title="Sin incidentes registrados"
              description="Escale una alerta desde su detalle para abrir un incidente con SLA y responsable."
            />
          )
        ) : null}
      </div>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.code || "Incidente"}
        description={selected?.title}
        width="max-w-2xl"
        footer={
          selected && hasPermission("incidents:update") ? (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void updateStatus("investigating")}
                loading={saving}
              >
                Investigar
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void updateStatus("contained")}
                loading={saving}
              >
                Contenido
              </Button>
              {!["resolved", "closed"].includes(selected.status) ? (
                <Button variant="danger" size="sm" onClick={() => void closeIncident()} loading={saving}>
                  Cerrar incidente
                </Button>
              ) : null}
            </>
          ) : null
        }
      >
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <IncidentStatusBadge status={selected.status} />
              {selected.ticket_external_id ? <Badge tone="neutral">{selected.ticket_external_id}</Badge> : null}
            </div>
            <p className="text-sm leading-relaxed text-slate-300">{selected.description}</p>
            <div className="grid grid-cols-2 gap-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-xs">
              <div>
                <p className="text-slate-500">Responsable</p>
                <p className="mt-1 flex items-center gap-1.5 text-slate-200">
                  <Users size={12} /> {selected.owner?.full_name || "Sin asignar"}
                </p>
              </div>
              <div>
                <p className="text-slate-500">Apertura</p>
                <p className="mt-1 text-slate-200">{formatDateTime(selected.opened_at)}</p>
              </div>
              <div>
                <p className="text-slate-500">SLA</p>
                <p className="mt-1 text-slate-200">{formatDateTime(selected.sla_due_at)}</p>
              </div>
              <div>
                <p className="text-slate-500">Cierre</p>
                <p className="mt-1 text-slate-200">{selected.closed_at ? formatDateTime(selected.closed_at) : "—"}</p>
              </div>
            </div>
            <div>
              <p className="mb-1.5 text-xs font-medium text-slate-300">Acciones de contención</p>
              <p className="rounded-lg bg-slate-950/50 p-3 text-xs leading-relaxed text-slate-400">
                {selected.containment_actions || "Sin acciones documentadas."}
              </p>
            </div>
            {hasPermission("incidents:update") ? (
              <Textarea
                label="Nota de seguimiento (se guarda en las acciones de contención)"
                rows={3}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="Ej. Host aislado; se preservó imagen forense…"
              />
            ) : null}
            <p className="text-[10px] text-slate-500">
              Abierto {timeAgo(selected.opened_at)} · Actualizado {timeAgo(selected.created_at)}
            </p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
