import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Filter, Plus, RefreshCw, Search, SlidersHorizontal, X } from "lucide-react";
import { alertsApi, apiErrorMessage } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useModuleAudit } from "../hooks/useModuleAudit";
import { AlertsTable } from "../components/AlertsTable";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  PageHeader,
  Pagination,
  Select,
  Textarea,
} from "../components/ui";
import type { Severity } from "../types";
import { SEVERITY_LABEL } from "../lib/utils";

const PAGE_SIZE = 20;

const initialForm = {
  title: "",
  description: "",
  severity: "medium" as Severity,
  source: "manual",
  source_ip: "",
  hostname: "",
  rule_id: "",
  rule_level: 6,
};

export function AlertsPage() {
  useModuleAudit("alerts");
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState(initialForm);
  const [saving, setSaving] = useState(false);

  const page = Math.max(1, Number(params.get("page") || "1"));
  const filters = useMemo(
    () => ({
      q: params.get("q") || undefined,
      status: params.get("status") || undefined,
      severity: params.get("severity") || undefined,
      source: params.get("source") || undefined,
      verdict: params.get("verdict") || undefined,
      open_only: params.get("open_only") || undefined,
      page,
      page_size: PAGE_SIZE,
    }),
    [params, page],
  );

  useEffect(() => {
    setSearch(params.get("q") || "");
  }, [params]);

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => alertsApi.list(filters),
    placeholderData: keepPreviousData,
  });

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next, { replace: true });
  };

  const clearFilters = () => {
    setParams(new URLSearchParams(), { replace: true });
    setSearch("");
  };

  const activeFilters = ["q", "status", "severity", "source", "verdict", "open_only"].filter((key) =>
    params.get(key),
  ).length;

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    updateParam("q", search.trim());
  };

  const createAlert = async () => {
    if (!form.title.trim()) {
      toast("El título de la alerta es obligatorio", "error");
      return;
    }
    setSaving(true);
    try {
      const alert = await alertsApi.create({
        ...form,
        source_ip: form.source_ip || null,
        hostname: form.hostname || null,
        rule_id: form.rule_id || null,
        rule_level: Number(form.rule_level),
      });
      toast("Alerta creada. Puede ejecutar el triaje automático.", "success");
      setModalOpen(false);
      setForm(initialForm);
      navigate(`/alerts/${alert.id}`);
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Detección y triaje"
        title="Gestión de alertas"
        subtitle="Cola unificada de Wazuh, OPNsense y eventos manuales, priorizada por riesgo y enriquecimiento."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void refetch()} loading={isFetching}>
              <RefreshCw size={14} />
              Actualizar
            </Button>
            {hasPermission("alerts:create") ? (
              <Button size="sm" onClick={() => setModalOpen(true)}>
                <Plus size={15} />
                Nueva alerta
              </Button>
            ) : null}
          </>
        }
      />

      <Card className="mb-5 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <form onSubmit={submitSearch} className="relative min-w-[220px] flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={15} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Buscar por título, IP, host, regla o ID externo…"
              className="h-10 w-full rounded-lg border border-white/10 bg-slate-950/60 pl-9 pr-9 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10"
            />
            {search ? (
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  updateParam("q", "");
                }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                aria-label="Limpiar búsqueda"
              >
                <X size={14} />
              </button>
            ) : null}
          </form>

          <div className="flex items-center gap-2">
            <SlidersHorizontal size={15} className="text-slate-500" />
            <span className="text-[11px] font-medium text-slate-500">Filtros</span>
          </div>

          <Select
            value={params.get("severity") || ""}
            onChange={(event) => updateParam("severity", event.target.value)}
            className="h-10 w-36"
            aria-label="Severidad"
          >
            <option value="">Severidad</option>
            {(Object.keys(SEVERITY_LABEL) as Severity[]).map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABEL[severity]}
              </option>
            ))}
          </Select>

          <Select
            value={params.get("status") || ""}
            onChange={(event) => updateParam("status", event.target.value)}
            className="h-10 w-36"
            aria-label="Estado"
          >
            <option value="">Estado</option>
            <option value="pending">Pendiente</option>
            <option value="triaging">En triaje</option>
            <option value="triaged">Triada</option>
            <option value="escalated">Escalada</option>
            <option value="false_positive">Falso positivo</option>
            <option value="closed">Cerrada</option>
          </Select>

          <Select
            value={params.get("source") || ""}
            onChange={(event) => updateParam("source", event.target.value)}
            className="h-10 w-32"
            aria-label="Fuente"
          >
            <option value="">Fuente</option>
            <option value="wazuh">Wazuh</option>
            <option value="opnsense">OPNsense</option>
            <option value="manual">Manual</option>
            <option value="generic">Genérica</option>
          </Select>

          <Button
            variant={params.get("open_only") ? "subtle" : "outline"}
            size="sm"
            onClick={() => updateParam("open_only", params.get("open_only") ? "" : "true")}
          >
            <Filter size={14} />
            Solo abiertas
          </Button>

          {activeFilters ? (
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              <X size={14} />
              Limpiar ({activeFilters})
            </Button>
          ) : null}
        </div>
      </Card>

      <div className="table-shell">
        <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="font-semibold text-slate-200">{data?.total ?? "—"}</span>
            alertas encontradas
          </div>
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-slate-600">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Ordenadas por fecha de recepción
          </div>
        </div>

        {isLoading ? <LoadingBlock label="Cargando alertas…" /> : null}
        {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}
        {!isLoading && !error && data ? (
          data.items.length ? (
            <>
              <AlertsTable alerts={data.items} />
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
              icon={<Filter size={20} />}
              title="No hay alertas con esos filtros"
              description="Limpie los filtros o ingrese una alerta de prueba desde la integración de n8n."
              action={
                activeFilters ? (
                  <Button variant="outline" size="sm" onClick={clearFilters}>
                    Limpiar filtros
                  </Button>
                ) : null
              }
            />
          )
        ) : null}
      </div>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Nueva alerta manual"
        description="Útil para pruebas, casos reportados por usuarios o ingestas puntuales."
        width="max-w-2xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={() => void createAlert()} loading={saving}>
              Crear alerta
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Input
              label="Título *"
              value={form.title}
              onChange={(event) => setForm({ ...form, title: event.target.value })}
              placeholder="Ej. Fuerza bruta SSH detectada"
            />
          </div>
          <div className="sm:col-span-2">
            <Textarea
              label="Descripción"
              rows={3}
              value={form.description}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
              placeholder="Contexto, evidencia y logs relevantes…"
            />
          </div>
          <Select
            label="Severidad"
            value={form.severity}
            onChange={(event) => setForm({ ...form, severity: event.target.value as Severity })}
          >
            {(Object.keys(SEVERITY_LABEL) as Severity[]).map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABEL[severity]}
              </option>
            ))}
          </Select>
          <Select
            label="Fuente"
            value={form.source}
            onChange={(event) => setForm({ ...form, source: event.target.value })}
          >
            <option value="manual">Manual</option>
            <option value="wazuh">Wazuh</option>
            <option value="opnsense">OPNsense</option>
            <option value="generic">Genérica</option>
          </Select>
          <Input
            label="IP de origen"
            value={form.source_ip}
            onChange={(event) => setForm({ ...form, source_ip: event.target.value })}
            placeholder="203.0.113.45"
          />
          <Input
            label="Host / activo"
            value={form.hostname}
            onChange={(event) => setForm({ ...form, hostname: event.target.value })}
            placeholder="srv-web01"
          />
          <Input
            label="ID de regla"
            value={form.rule_id}
            onChange={(event) => setForm({ ...form, rule_id: event.target.value })}
            placeholder="5710"
          />
          <Input
            label="Nivel de regla (0-15)"
            type="number"
            min={0}
            max={15}
            value={form.rule_level}
            onChange={(event) => setForm({ ...form, rule_level: Number(event.target.value) })}
          />
        </div>
      </Modal>
    </div>
  );
}
