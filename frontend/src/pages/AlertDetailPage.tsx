import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  Boxes,
  CheckCircle2,
  ChevronDown,
  Clipboard,
  Clock,
  Cpu,
  ExternalLink,
  FileJson,
  Fingerprint,
  Globe2,
  History,
  Network,
  Play,
  Server,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Siren,
  UserRound,
} from "lucide-react";
import { alertsApi, apiErrorMessage } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useModuleAudit } from "../hooks/useModuleAudit";
import {
  AlertStatusBadge,
  Badge,
  Button,
  Card,
  CardHeader,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  RiskMeter,
  SeverityBadge,
  Textarea,
  VerdictBadge,
} from "../components/ui";
import {
  formatDateTime,
  SEVERITY_LABEL,
  timeAgo,
  VERDICT_LABEL,
  cn,
} from "../lib/utils";
import type { TriageAction } from "../types";

export function AlertDetailPage() {
  useModuleAudit("alerts");
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const [triaging, setTriaging] = useState(false);
  const [actionLoading, setActionLoading] = useState("");
  const [showRaw, setShowRaw] = useState(false);
  const [showReasoning, setShowReasoning] = useState(false);
  const [escalateOpen, setEscalateOpen] = useState(false);
  const [escalateForm, setEscalateForm] = useState({ title: "", description: "" });
  const [fpOpen, setFpOpen] = useState(false);
  const [fpReason, setFpReason] = useState("");

  const { data: alert, isLoading, error, refetch } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id),
    enabled: Boolean(id),
  });

  const { data: timeline } = useQuery({
    queryKey: ["alert-timeline", id],
    queryFn: () => alertsApi.timeline(id),
    enabled: Boolean(id),
  });

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["alert", id] });
    await queryClient.invalidateQueries({ queryKey: ["alert-timeline", id] });
    await queryClient.invalidateQueries({ queryKey: ["alerts"] });
  };

  const runTriage = async () => {
    setTriaging(true);
    try {
      await alertsApi.triage(id, true);
      toast("Triaje ejecutado y guardado en la bitácora", "success");
      await refresh();
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setTriaging(false);
    }
  };

  const markFalsePositive = async () => {
    if (!fpReason.trim()) {
      toast("Indique el motivo de descarte", "error");
      return;
    }
    setActionLoading("fp");
    try {
      await alertsApi.changeStatus(id, "false_positive", fpReason);
      toast("Alerta marcada como falso positivo", "success");
      setFpOpen(false);
      await refresh();
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setActionLoading("");
    }
  };

  const escalate = async () => {
    setActionLoading("escalate");
    try {
      const incident = await alertsApi.escalate(id, {
        title: escalateForm.title || undefined,
        description: escalateForm.description || undefined,
      });
      toast(`Incidente ${incident.code} creado`, "success");
      setEscalateOpen(false);
      await refresh();
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setActionLoading("");
    }
  };

  const copyPayload = async () => {
    if (!alert) return;
    await navigator.clipboard.writeText(JSON.stringify(alert.raw_payload, null, 2));
    toast("Payload copiado al portapapeles", "success");
  };

  if (isLoading) return <LoadingBlock label="Cargando detalle de la alerta…" />;
  if (error || !alert) return <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} />;

  const triage = alert.triage_result;

  return (
    <div className="animate-fade-up">
      <button
        type="button"
        onClick={() => navigate("/alerts")}
        className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 transition hover:text-cyan-300"
      >
        <ArrowLeft size={14} />
        Volver a alertas
      </button>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <AlertStatusBadge status={alert.status} />
            {triage ? <VerdictBadge verdict={triage.verdict} /> : null}
            {alert.incident ? <Badge tone="violet">{alert.incident.code}</Badge> : null}
          </div>
          <h1 className="max-w-4xl text-2xl font-bold tracking-tight text-white">{alert.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <Clock size={12} /> {formatDateTime(alert.received_at)} · {timeAgo(alert.received_at)}
            </span>
            <span className="flex items-center gap-1.5">
              <Siren size={12} /> {alert.source}
            </span>
            <span className="flex items-center gap-1.5">
              <Fingerprint size={12} /> {alert.rule_id || "sin regla"} · nivel {alert.rule_level}
            </span>
            <span className="font-mono text-slate-600">{alert.id.slice(0, 8)}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {hasPermission("alerts:triage") ? (
            <Button variant="subtle" size="sm" onClick={() => void runTriage()} loading={triaging}>
              <Play size={14} />
              {triage ? "Re-triar" : "Ejecutar triaje"}
            </Button>
          ) : null}
          {hasPermission("incidents:create") && !alert.incident ? (
            <Button
              size="sm"
              onClick={() => {
                setEscalateForm({ title: alert.title, description: alert.description });
                setEscalateOpen(true);
              }}
            >
              <ShieldX size={14} />
              Escalar a incidente
            </Button>
          ) : null}
          {hasPermission("alerts:close") && !["false_positive", "closed"].includes(alert.status) ? (
            <Button variant="outline" size="sm" onClick={() => setFpOpen(true)}>
              <CheckCircle2 size={14} />
              Falso positivo
            </Button>
          ) : null}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.7fr)_minmax(300px,1fr)]">
        <div className="space-y-5">
          <Card>
            <CardHeader
              title="Contexto de la alerta"
              subtitle={`${alert.source} · ${alert.agent_name || alert.hostname || "activo no identificado"}`}
            />
            <div className="px-5 py-4">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
                {alert.description || "Sin descripción adicional."}
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                {(alert.mitre_techniques || []).map((technique) => (
                  <Badge key={technique} tone="violet">
                    {technique}
                  </Badge>
                ))}
                {(alert.tags || []).map((tag) => (
                  <Badge key={tag} tone="neutral">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          </Card>

          {triage ? (
            <>
              <Card className="overflow-hidden">
                <div className="border-b border-white/[0.06] bg-gradient-to-r from-cyan-400/[0.06] via-transparent to-violet-400/[0.04] px-5 py-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-2">
                        <Sparkles className="text-cyan-300" size={18} />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-white">Resultado del triaje automático</p>
                        <p className="mt-0.5 text-[11px] text-slate-400">
                          {triage.engine} · {triage.model_name || "sin modelo"} · {triage.latency_ms} ms
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <VerdictBadge verdict={triage.verdict} />
                      <Badge tone="neutral">conf. {(triage.confidence * 100).toFixed(0)}%</Badge>
                    </div>
                  </div>
                </div>
                <div className="px-5 py-4">
                  <div className="mb-4 rounded-xl border border-white/[0.06] bg-slate-950/40 p-4">
                    <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">
                      <span>Riesgo calculado</span>
                      <span className={cn("text-base", triage.risk_score >= 70 ? "text-rose-300" : "text-amber-300")}>
                        {triage.risk_score}/100
                      </span>
                    </div>
                    <RiskMeter score={triage.risk_score} className="mt-2 h-2" />
                    <p className="mt-3 text-sm leading-relaxed text-slate-300">{triage.summary}</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowReasoning((value) => !value)}
                    className="flex w-full items-center justify-between rounded-lg border border-white/[0.06] px-3 py-2.5 text-left text-xs text-slate-400 transition hover:bg-white/[0.03]"
                  >
                    <span className="font-medium">Razonamiento y evidencia</span>
                    <ChevronDown size={15} className={cn("transition", showReasoning && "rotate-180")} />
                  </button>
                  {showReasoning ? (
                    <p className="mt-3 rounded-lg bg-slate-950/50 p-3 text-xs leading-relaxed text-slate-400">
                      {triage.reasoning || "Sin razonamiento adicional."}
                    </p>
                  ) : null}
                  {triage.false_positive_reason ? (
                    <div className="mt-3 rounded-lg border border-amber-400/20 bg-amber-400/[0.05] px-3 py-2 text-xs text-amber-200">
                      Motivo de falso positivo: {triage.false_positive_reason}
                    </div>
                  ) : null}
                </div>
              </Card>

              <Card>
                <CardHeader
                  title="Acciones recomendadas"
                  subtitle={`${triage.recommended_actions.length} pasos priorizados por el motor de triaje`}
                />
                <div className="divide-y divide-white/[0.05]">
                  {(triage.recommended_actions as TriageAction[]).map((action, index) => (
                    <div key={`${action.priority}-${index}`} className="flex gap-4 px-5 py-3.5">
                      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-cyan-400/20 bg-cyan-400/10 text-[11px] font-bold text-cyan-300">
                        {action.priority}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm leading-snug text-slate-200">{action.action}</p>
                        <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
                          <span className="flex items-center gap-1">
                            <UserRound size={11} /> {action.owner}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock size={11} /> SLA {action.sla_minutes} min
                          </span>
                          <Badge tone="neutral" className="text-[9px]">
                            {action.type}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </>
          ) : (
            <Card className="border-dashed p-8 text-center">
              <Sparkles className="mx-auto mb-3 text-cyan-300" size={24} />
              <p className="text-sm font-semibold text-white">Esta alerta aún no tiene triaje</p>
              <p className="mx-auto mt-1 max-w-md text-xs text-slate-400">
                Ejecute el motor de triaje para obtener veredicto, riesgo, resumen y acciones recomendadas.
              </p>
              {hasPermission("alerts:triage") ? (
                <Button className="mt-4" onClick={() => void runTriage()} loading={triaging}>
                  <Play size={14} /> Ejecutar triaje
                </Button>
              ) : null}
            </Card>
          )}

          <Card>
            <CardHeader
              title="Enriquecimiento externo"
              subtitle="Reputación de indicadores y contexto de red"
              action={
                <Badge tone="neutral">{alert.enrichment_data.length} fuentes</Badge>
              }
            />
            <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2">
              {alert.enrichment_data.length ? (
                alert.enrichment_data.map((item) => (
                  <div key={item.id} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                        <Globe2 size={13} className="text-cyan-300" />
                        {item.provider}
                      </span>
                      <Badge tone={item.status === "ok" ? "ok" : "warn"}>{item.status}</Badge>
                    </div>
                    <p className="mt-2 font-mono text-[11px] text-slate-400">{item.indicator}</p>
                    <p className="mt-2 text-xs leading-relaxed text-slate-300">{item.summary}</p>
                    {item.risk_score !== null ? (
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-[10px] text-slate-500">Riesgo</span>
                        <RiskMeter score={item.risk_score} className="flex-1" />
                        <span className="text-[10px] font-semibold text-slate-300">{Math.round(item.risk_score)}</span>
                      </div>
                    ) : null}
                  </div>
                ))
              ) : (
                <p className="col-span-full py-4 text-center text-xs text-slate-500">
                  Sin enriquecimiento externo. Configure VirusTotal, AbuseIPDB o GeoIP en el microservicio.
                </p>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Payload original"
              subtitle="Evento tal como llegó desde la fuente"
              action={
                <div className="flex gap-1">
                  <Button variant="ghost" size="sm" onClick={() => void copyPayload()}>
                    <Clipboard size={13} /> Copiar
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setShowRaw((value) => !value)}>
                    <ChevronDown size={14} className={cn("transition", showRaw && "rotate-180")} />
                  </Button>
                </div>
              }
            />
            {showRaw ? (
              <pre className="max-h-[420px] overflow-auto bg-slate-950/70 p-4 font-mono text-[11px] leading-relaxed text-slate-400">
                {JSON.stringify(alert.raw_payload, null, 2)}
              </pre>
            ) : (
              <div className="flex items-center gap-2 px-5 py-4 text-[11px] text-slate-500">
                <FileJson size={14} /> {Object.keys(alert.raw_payload).length} campos · pulse para expandir
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader title="Ficha del evento" />
            <div className="space-y-3.5 px-5 py-4 text-xs">
              <MetaRow label="ID externo" value={alert.external_id || "—"} mono />
              <MetaRow label="Fuente" value={alert.source} />
              <MetaRow label="Regla" value={`${alert.rule_id || "—"} (nivel ${alert.rule_level})`} />
              <MetaRow label="Recibida" value={formatDateTime(alert.received_at)} />
              <MetaRow label="Primera vez" value={formatDateTime(alert.first_seen_at)} />
              <MetaRow label="Última vez" value={formatDateTime(alert.last_seen_at)} />
              <MetaRow label="Asignada a" value={alert.assigned_to?.full_name || "Sin asignar"} />
              {alert.osticket_link ? (
                <>
                  <MetaRow label="Ticket osTicket" value={`#${alert.osticket_link.ticket_number}`} mono />
                  <MetaRow label="Estado del ticket" value={alert.osticket_link.status_name} />
                </>
              ) : null}
              <MetaRow label="IP origen" value={alert.source_ip || "—"} mono />
              <MetaRow label="IP destino" value={alert.destination_ip || "—"} mono />
              <MetaRow label="Usuario" value={alert.username || "—"} mono />
            </div>
          </Card>

          <Card>
            <CardHeader title="Activo afectado" subtitle="Contexto de criticidad" />
            <div className="px-5 py-4">
              {alert.asset ? (
                <>
                  <div className="flex items-center gap-3">
                    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5">
                      <Server className="text-cyan-300" size={18} />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-white">{alert.asset.hostname}</p>
                      <p className="font-mono text-[10px] text-slate-500">{alert.asset.ip_address || "sin IP"}</p>
                    </div>
                    <Badge
                      tone={
                        alert.asset.criticality === "critical"
                          ? "critical"
                          : alert.asset.criticality === "high"
                            ? "high"
                            : alert.asset.criticality === "medium"
                              ? "medium"
                              : "low"
                      }
                      className="ml-auto"
                    >
                      {SEVERITY_LABEL[alert.asset.criticality]}
                    </Badge>
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-3 text-[11px]">
                    <div>
                      <p className="text-slate-500">Entorno</p>
                      <p className="mt-0.5 text-slate-200">{alert.asset.environment}</p>
                    </div>
                    <div>
                      <p className="text-slate-500">Responsable</p>
                      <p className="mt-0.5 text-slate-200">{alert.asset.owner}</p>
                    </div>
                    <div className="col-span-2">
                      <p className="text-slate-500">Sistema operativo</p>
                      <p className="mt-0.5 text-slate-200">{alert.asset.operating_system || "—"}</p>
                    </div>
                  </div>
                </>
              ) : (
                <div className="flex items-start gap-2 text-xs text-slate-400">
                  <Boxes size={15} className="mt-0.5 text-slate-500" />
                  Activo no inventariado. Se recomienda incorporarlo al CMDB para mejorar el contexto del triaje.
                </div>
              )}
            </div>
          </Card>

          {alert.incident ? (
            <Card className="border-violet-400/20">
              <CardHeader title="Incidente asociado" action={<Badge tone="violet">{alert.incident.code}</Badge>} />
              <div className="px-5 py-4">
                <p className="text-sm font-semibold text-white">{alert.incident.title}</p>
                <div className="mt-3 flex items-center gap-2">
                  <Badge tone="warn">{alert.incident.status}</Badge>
                  <span className="text-[10px] text-slate-500">SLA {formatDateTime(alert.incident.sla_due_at)}</span>
                </div>
                <Button variant="outline" size="sm" className="mt-4 w-full" onClick={() => navigate("/incidents")}>
                  <ExternalLink size={13} /> Ver bandeja de incidentes
                </Button>
              </div>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Timeline de auditoría" subtitle="Trazabilidad de la alerta" action={<History size={15} className="text-slate-500" />} />
            <div className="px-5 py-4">
              {timeline && timeline.length ? (
                <div className="space-y-4">
                  {timeline.slice(-8).map((event) => (
                    <div key={event.id} className="relative pl-4">
                      <span className="absolute left-0 top-1.5 h-1.5 w-1.5 rounded-full bg-cyan-400" />
                      <span className="absolute left-[2px] top-3.5 h-[calc(100%+4px)] w-px bg-white/[0.07] last:hidden" />
                      <p className="text-[11px] font-medium text-slate-200">{event.action}</p>
                      <p className="mt-0.5 text-[10px] text-slate-500">
                        {event.actor_email} · {formatDateTime(event.created_at)}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500">Sin eventos registrados para esta alerta.</p>
              )}
            </div>
          </Card>
        </div>
      </div>

      <Modal
        open={escalateOpen}
        onClose={() => setEscalateOpen(false)}
        title="Escalar a incidente"
        description="Se creará un incidente con SLA calculado según la severidad de la alerta."
        footer={
          <>
            <Button variant="ghost" onClick={() => setEscalateOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={() => void escalate()} loading={actionLoading === "escalate"}>
              <ShieldX size={14} /> Crear incidente
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Input
            label="Título del incidente"
            value={escalateForm.title}
            onChange={(event) => setEscalateForm({ ...escalateForm, title: event.target.value })}
          />
          <Textarea
            label="Descripción y acciones de contención"
            rows={4}
            value={escalateForm.description}
            onChange={(event) => setEscalateForm({ ...escalateForm, description: event.target.value })}
          />
          <div className="flex items-center gap-2 rounded-lg border border-cyan-400/15 bg-cyan-400/[0.04] px-3 py-2 text-[11px] text-cyan-200">
            <ShieldCheck size={14} /> El escalamiento queda registrado en la bitácora con su usuario.
          </div>
        </div>
      </Modal>

      <Modal
        open={fpOpen}
        onClose={() => setFpOpen(false)}
        title="Marcar como falso positivo"
        description="Documente el motivo para mejorar las reglas y la métrica de ruido."
        footer={
          <>
            <Button variant="ghost" onClick={() => setFpOpen(false)}>
              Cancelar
            </Button>
            <Button variant="outline" onClick={() => void markFalsePositive()} loading={actionLoading === "fp"}>
              Confirmar descarte
            </Button>
          </>
        }
      >
        <Textarea
          label="Motivo del descarte"
          rows={4}
          value={fpReason}
          onChange={(event) => setFpReason(event.target.value)}
          placeholder="Ej. Actividad de escaneo autorizada por el equipo de infraestructura…"
        />
      </Modal>
    </div>
  );
}

function MetaRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="shrink-0 text-slate-500">{label}</span>
      <span className={cn("break-all text-right text-slate-200", mono && "font-mono text-[10px]")}>{value}</span>
    </div>
  );
}
