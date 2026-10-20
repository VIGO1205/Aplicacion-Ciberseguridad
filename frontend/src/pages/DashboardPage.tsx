import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  BellRing,
  CheckCircle2,
  Clock3,
  Gauge,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Timer,
  TrendingDown,
} from "lucide-react";
import { dashboardApi, apiErrorMessage } from "../lib/api";
import { useModuleAudit } from "../hooks/useModuleAudit";
import { BarList, DonutChart, KpiCard, AreaTrend } from "../components/charts";
import { AlertsTable } from "../components/AlertsTable";
import { Button, Card, CardHeader, ErrorState, LoadingBlock, Badge, PageHeader } from "../components/ui";
import { ALERT_STATUS_LABEL, SEVERITY_LABEL, formatNumber } from "../lib/utils";

const PERIODS = [7, 14, 30, 90];

export function DashboardPage() {
  useModuleAudit("dashboard");
  const navigate = useNavigate();
  const [days, setDays] = useState(14);
  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["dashboard", days],
    queryFn: () => dashboardApi.overview(days),
    refetchInterval: 60_000,
  });

  const kpis = data?.kpis;

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Vista general"
        title="Panel de control"
        subtitle="Postura operativa del SOC, eficiencia del triaje y evolución de alertas en el periodo."
        actions={
          <>
            <div className="flex items-center rounded-lg border border-white/[0.08] bg-white/[0.03] p-0.5">
              {PERIODS.map((period) => (
                <button
                  key={period}
                  type="button"
                  onClick={() => setDays(period)}
                  className={`rounded-md px-2.5 py-1.5 text-[11px] font-semibold transition ${
                    days === period ? "bg-cyan-400/15 text-cyan-200" : "text-slate-500 hover:text-slate-200"
                  }`}
                >
                  {period}d
                </button>
              ))}
            </div>
            <Button variant="outline" size="sm" onClick={() => void refetch()} loading={isFetching}>
              <RefreshCw size={14} />
              Actualizar
            </Button>
            <Button size="sm" onClick={() => navigate("/reports")}>
              <Sparkles size={14} />
              Generar reporte
            </Button>
          </>
        }
      />

      {isLoading ? <LoadingBlock label="Calculando indicadores del SOC…" /> : null}
      {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}

      {data && kpis ? (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <KpiCard
              label="Alertas recibidas"
              value={formatNumber(kpis.total_alerts)}
              hint={`Periodo de ${data.period_days} días · ${kpis.total_incidents} incidentes`}
              icon={<BellRing size={20} />}
              tone="cyan"
            />
            <KpiCard
              label="Alertas abiertas"
              value={formatNumber(kpis.open_alerts)}
              hint={`${kpis.critical_open} críticas · ${kpis.high_open} altas requieren atención`}
              icon={<ShieldAlert size={20} />}
              tone={kpis.critical_open ? "rose" : "amber"}
            />
            <KpiCard
              label="MTTT · tiempo a triaje"
              value={`${formatNumber(kpis.mttt_minutes, 1)} min`}
              hint={kpis.mttt_minutes <= 30 ? "Dentro de la meta operativa (< 30 min)" : "Sobre la meta de 30 min"}
              icon={<Timer size={20} />}
              tone={kpis.mttt_minutes <= 30 ? "emerald" : "amber"}
            />
            <KpiCard
              label="Tasa de falsos positivos"
              value={`${formatNumber(kpis.false_positive_rate, 1)}%`}
              hint={kpis.false_positive_rate <= 40 ? "Ruido bajo control" : "Revisar reglas y umbrales"}
              icon={<TrendingDown size={20} />}
              tone={kpis.false_positive_rate <= 40 ? "emerald" : "rose"}
            />
          </div>

          <Card className="p-4 sm:p-5">
            <div className="grid grid-cols-2 divide-x divide-white/[0.06] lg:grid-cols-4">
              {[
                {
                  label: "Cumplimiento SLA",
                  value: `${kpis.sla_compliance}%`,
                  icon: CheckCircle2,
                  tone: "text-emerald-300",
                },
                {
                  label: "Automatización",
                  value: `${kpis.automation_rate}%`,
                  icon: Sparkles,
                  tone: "text-cyan-300",
                },
                {
                  label: "Cobertura de triaje",
                  value: `${kpis.triage_coverage}%`,
                  icon: Gauge,
                  tone: "text-violet-300",
                },
                {
                  label: "MTTR",
                  value: `${kpis.mttr_hours} h`,
                  icon: Clock3,
                  tone: "text-amber-300",
                },
              ].map((item, index) => (
                <div key={item.label} className={index > 0 ? "pl-4 sm:pl-6" : "pr-4 sm:pr-6"}>
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
                    <item.icon size={12} className={item.tone} />
                    {item.label}
                  </div>
                  <p className="mt-1.5 text-xl font-bold text-white">{item.value}</p>
                </div>
              ))}
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader
                title="Evolución de alertas"
                subtitle={`Volumen diario · últimos ${data.period_days} días`}
                action={
                  <Badge tone="cyan" dot>
                    {isFetching ? "Actualizando" : "En vivo"}
                  </Badge>
                }
              />
              <div className="px-3 pb-3 pt-5">
                <AreaTrend data={data.alerts_by_day} />
              </div>
            </Card>

            <Card>
              <CardHeader title="Distribución por severidad" subtitle="Clasificación de origen" />
              <div className="px-5 py-5">
                <DonutChart
                  data={data.by_severity.map((item) => ({
                    ...item,
                    name: SEVERITY_LABEL[item.name as keyof typeof SEVERITY_LABEL] || item.name,
                  }))}
                />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            <Card>
              <CardHeader title="Top IPs de origen" subtitle="Mayor volumen de alertas" />
              <div className="px-5 py-4">
                <BarList data={data.top_source_ips} color="#22d3ee" />
              </div>
            </Card>
            <Card>
              <CardHeader title="Técnicas MITRE ATT&CK" subtitle="Observadas en alertas y triajes" />
              <div className="px-5 py-4">
                <BarList
                  data={data.top_mitre.map((item) => ({
                    name: item.name,
                    value: item.value,
                  }))}
                  color="#a78bfa"
                />
              </div>
            </Card>
            <Card>
              <CardHeader title="Incidentes por estado" subtitle="Carga de respuesta actual" />
              <div className="px-5 py-4">
                <BarList
                  data={data.incidents_by_status.map((item) => ({
                    ...item,
                    name:
                      {
                        open: "Abiertos",
                        investigating: "Investigación",
                        contained: "Contenidos",
                        resolved: "Resueltos",
                        closed: "Cerrados",
                      }[item.name] || item.name,
                  }))}
                  color="#fb923c"
                />
                <Button variant="ghost" size="sm" className="mt-3 w-full" onClick={() => navigate("/incidents")}>
                  Ver incidentes <ArrowRight size={13} />
                </Button>
              </div>
            </Card>
          </div>

          <Card className="overflow-hidden">
            <CardHeader
              title="Alertas recientes"
              subtitle="Últimos eventos recibidos por el SOC"
              action={
                <Button variant="ghost" size="sm" onClick={() => navigate("/alerts")}>
                  Ver todas <ArrowRight size={13} />
                </Button>
              }
            />
            <AlertsTable alerts={data.recent_alerts} compact />
          </Card>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="flex items-start gap-3 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.04] p-4">
              <ShieldCheck className="mt-0.5 shrink-0 text-emerald-300" size={18} />
              <div>
                <p className="text-xs font-semibold text-emerald-200">Trazabilidad activa</p>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                  Cada consulta, triaje y exportación queda registrada con usuario, fecha, hora y acción.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-4">
              <Activity className="mt-0.5 shrink-0 text-cyan-300" size={18} />
              <div>
                <p className="text-xs font-semibold text-cyan-200">Motor de triaje híbrido</p>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                  LangChain con herramientas de reputación y LLM local; fallback heurístico si Ollama no está
                  disponible.
                </p>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
