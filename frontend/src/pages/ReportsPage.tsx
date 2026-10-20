import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDownToLine,
  BarChart3,
  Check,
  FileSpreadsheet,
  FileText,
  FileType2,
  History,
  Loader2,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { apiErrorMessage, reportsApi } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
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
} from "../components/ui";
import type { Report, ReportFormat, ReportType } from "../types";
import { formatBytes, formatDateTime } from "../lib/utils";

const REPORT_TYPES: {
  type: ReportType;
  title: string;
  description: string;
  icon: typeof BarChart3;
  accent: string;
  bullets: string[];
}[] = [
  {
    type: "operational",
    title: "Operacional",
    description: "Detalle de alertas, triajes, incidentes y acciones recomendadas del periodo.",
    icon: FileText,
    accent: "cyan",
    bullets: ["Alertas y severidad", "Resúmenes de triaje", "Incidentes y cierre"],
  },
  {
    type: "management",
    title: "Gestión",
    description: "KPIs ejecutivos, tendencia, SLA, carga operativa y recomendaciones para la dirección.",
    icon: BarChart3,
    accent: "violet",
    bullets: ["MTTT / MTTR / SLA", "Tendencia y fuentes", "Conclusiones y riesgos"],
  },
  {
    type: "audit",
    title: "Auditoría",
    description: "Evidencia de trazabilidad: usuarios, módulos, entradas/salidas y exportaciones.",
    icon: ShieldCheck,
    accent: "amber",
    bullets: ["Entradas y salidas", "Acciones por módulo", "Evidencia ISO 27001"],
  },
];

const FORMATS: { format: ReportFormat; label: string; icon: typeof FileText; hint: string }[] = [
  { format: "pdf", label: "PDF", icon: FileText, hint: "Ejecutivo / impresión" },
  { format: "docx", label: "Word", icon: FileType2, hint: "Editable" },
  { format: "xlsx", label: "Excel", icon: FileSpreadsheet, hint: "Datos y anexos" },
];

const TYPE_LABEL: Record<ReportType, string> = {
  operational: "Operacional",
  management: "Gestión",
  audit: "Auditoría",
};

const FORMAT_TONE: Record<ReportFormat, string> = {
  pdf: "text-rose-300 border-rose-400/20 bg-rose-400/10",
  docx: "text-sky-300 border-sky-400/20 bg-sky-400/10",
  xlsx: "text-emerald-300 border-emerald-400/20 bg-emerald-400/10",
};

export function ReportsPage() {
  useModuleAudit("reports");
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [type, setType] = useState<ReportType>("operational");
  const [format, setFormat] = useState<ReportFormat>("pdf");
  const [days, setDays] = useState(30);
  const [generating, setGenerating] = useState(false);
  const [page, setPage] = useState(1);

  const availableTypes = useMemo(
    () => REPORT_TYPES.filter((item) => item.type !== "audit" || hasPermission("audit:read")),
    [hasPermission],
  );

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["reports", page],
    queryFn: () => reportsApi.list({ page, page_size: 8 }),
  });

  const generate = async () => {
    setGenerating(true);
    try {
      const report = await reportsApi.create({ report_type: type, format, days });
      toast(`Reporte ${report.file_name} generado`, "success");
      setPage(1);
      await queryClient.invalidateQueries({ queryKey: ["reports"] });
      await reportsApi.download(report);
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    } finally {
      setGenerating(false);
    }
  };

  const download = async (report: Report) => {
    try {
      await reportsApi.download(report);
      toast("Descarga iniciada y registrada en auditoría", "success");
    } catch (err) {
      toast(apiErrorMessage(err), "error");
    }
  };

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Gestión y cumplimiento"
        title="Reportes"
        subtitle="Genere evidencia operacional y ejecutiva en PDF, Word y Excel. Toda exportación queda auditada."
        actions={
          <Badge tone="neutral">
            <History size={12} /> {data?.total ?? 0} reportes generados
          </Badge>
        }
      />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(300px,1fr)]">
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {availableTypes.map((item) => {
              const active = type === item.type;
              return (
                <button
                  key={item.type}
                  type="button"
                  onClick={() => setType(item.type)}
                  className={`group relative overflow-hidden rounded-2xl border p-4 text-left transition ${
                    active
                      ? "border-cyan-400/40 bg-cyan-400/[0.07] shadow-glow"
                      : "border-white/[0.07] bg-slate-900/55 hover:border-white/15 hover:bg-slate-900/80"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div
                      className={`rounded-xl border p-2 ${
                        active ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-300" : "border-white/10 bg-white/5 text-slate-400"
                      }`}
                    >
                      <item.icon size={19} />
                    </div>
                    {active ? (
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-400 text-slate-950">
                        <Check size={12} />
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-3 text-sm font-semibold text-white">{item.title}</p>
                  <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{item.description}</p>
                  <ul className="mt-3 space-y-1">
                    {item.bullets.map((bullet) => (
                      <li key={bullet} className="flex items-center gap-1.5 text-[10px] text-slate-500">
                        <span className="h-1 w-1 rounded-full bg-cyan-400/60" />
                        {bullet}
                      </li>
                    ))}
                  </ul>
                </button>
              );
            })}
          </div>

          <Card>
            <CardHeader title="Configurar exportación" subtitle="El archivo se genera en el servidor y se registra en reports" />
            <div className="space-y-5 px-5 py-5">
              <div>
                <p className="mb-2 text-xs font-medium text-slate-300">Formato</p>
                <div className="grid grid-cols-3 gap-2">
                  {FORMATS.map((item) => (
                    <button
                      key={item.format}
                      type="button"
                      onClick={() => setFormat(item.format)}
                      className={`flex items-center gap-2.5 rounded-xl border p-3 text-left transition ${
                        format === item.format
                          ? "border-cyan-400/40 bg-cyan-400/[0.07]"
                          : "border-white/[0.07] bg-white/[0.02] hover:border-white/15"
                      }`}
                    >
                      <item.icon size={18} className={format === item.format ? "text-cyan-300" : "text-slate-400"} />
                      <span>
                        <span className="block text-xs font-semibold text-white">{item.label}</span>
                        <span className="block text-[10px] text-slate-500">{item.hint}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-slate-300">Periodo</p>
                <div className="flex flex-wrap gap-2">
                  {[7, 14, 30, 90].map((value) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setDays(value)}
                      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition ${
                        days === value
                          ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-200"
                          : "border-white/[0.08] text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Últimos {value} días
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-slate-950/40 p-4">
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <Sparkles size={15} className="text-cyan-300" />
                  {TYPE_LABEL[type]} · {FORMATS.find((item) => item.format === format)?.label} · {days} días
                </div>
                <Button onClick={() => void generate()} loading={generating} disabled={!hasPermission("reports:export")}>
                  {generating ? <Loader2 size={15} className="animate-spin" /> : <ArrowDownToLine size={15} />}
                  Generar y descargar
                </Button>
              </div>
              {!hasPermission("reports:export") ? (
                <p className="text-[11px] text-amber-300">Su rol puede consultar reportes, pero no generarlos.</p>
              ) : null}
            </div>
          </Card>

          <Card className="overflow-hidden">
            <CardHeader
              title="Reportes recientes"
              subtitle="Historial de exportaciones y evidencia"
              action={
                <Button variant="ghost" size="sm" onClick={() => void refetch()}>
                  Actualizar
                </Button>
              }
            />
            {isLoading ? <LoadingBlock label="Cargando reportes…" /> : null}
            {error ? <ErrorState message={apiErrorMessage(error)} onRetry={() => void refetch()} /> : null}
            {!isLoading && !error && data ? (
              data.items.length ? (
                <>
                  <div className="divide-y divide-white/[0.05]">
                    {data.items.map((report) => (
                      <div key={report.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5 transition hover:bg-white/[0.02]">
                        <div className={`rounded-lg border p-2 ${FORMAT_TONE[report.format]}`}>
                          {report.format === "pdf" ? <FileText size={16} /> : report.format === "docx" ? <FileType2 size={16} /> : <FileSpreadsheet size={16} />}
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-xs font-semibold text-slate-100">{report.name}</p>
                          <p className="mt-0.5 text-[10px] text-slate-500">
                            {formatDateTime(report.created_at)} · {formatBytes(report.size_bytes)} ·{" "}
                            {report.generated_by?.full_name || "Sistema"}
                          </p>
                        </div>
                        <Badge tone={report.report_type === "audit" ? "warn" : report.report_type === "management" ? "violet" : "cyan"}>
                          {TYPE_LABEL[report.report_type]}
                        </Badge>
                        <Badge tone="neutral" className="uppercase">
                          {report.format}
                        </Badge>
                        <Button variant="ghost" size="icon" onClick={() => void download(report)} aria-label="Descargar reporte">
                          <ArrowDownToLine size={15} />
                        </Button>
                      </div>
                    ))}
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
                  icon={<FileText size={20} />}
                  title="Aún no hay reportes"
                  description="Configure el tipo, formato y periodo; el primer reporte aparecerá aquí."
                />
              )
            ) : null}
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader title="Qué incluye cada reporte" />
            <div className="space-y-4 px-5 py-4">
              {[
                { title: "Portada y resumen ejecutivo", text: "Periodo, responsable, KPIs y lectura gerencial." },
                { title: "Indicadores y gráficos", text: "Tendencia diaria, severidad, fuentes y MITRE ATT&CK." },
                { title: "Anexo de datos", text: "Alertas, triajes, incidentes y bitácora en Excel." },
                { title: "Recomendaciones", text: "Acciones priorizadas según SLA, FP y cobertura." },
              ].map((item) => (
                <div key={item.title} className="flex gap-2.5">
                  <span className="mt-1 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-cyan-400/15 text-cyan-300">
                    <Check size={10} />
                  </span>
                  <div>
                    <p className="text-xs font-medium text-slate-200">{item.title}</p>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{item.text}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card className="border-cyan-400/15 bg-cyan-400/[0.03]">
            <div className="p-5">
              <ShieldCheck className="text-cyan-300" size={20} />
              <p className="mt-3 text-xs font-semibold text-cyan-100">Evidencia y cumplimiento</p>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                Cada generación y descarga se registra con usuario, fecha, hora, formato y tamaño. Esto
                soporta los controles A.8.15 y A.5.24 de ISO 27001 y las funciones DETECT/RESPOND de NIST CSF.
              </p>
            </div>
          </Card>

          <Card>
            <CardHeader title="Buenas prácticas" />
            <ul className="space-y-2.5 px-5 py-4 text-[11px] leading-relaxed text-slate-400">
              <li>• Use PDF para comités y Excel para análisis operacional.</li>
              <li>• Genere el reporte de auditoría al cierre de cada mes.</li>
              <li>• Restrinja la descarga a roles con reports:read.</li>
              <li>• Conserve los archivos según la política de retención.</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
