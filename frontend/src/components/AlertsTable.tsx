import { useNavigate } from "react-router-dom";
import { ArrowUpRight, ShieldAlert } from "lucide-react";
import type { Alert } from "../types";
import { SeverityBadge, AlertStatusBadge, RiskMeter, EmptyState } from "./ui";
import { formatDateTime } from "../lib/utils";

export function AlertsTable({ alerts, compact = false }: { alerts: Alert[]; compact?: boolean }) {
  const navigate = useNavigate();

  if (!alerts.length) {
    return (
      <EmptyState
        icon={<ShieldAlert size={20} />}
        title="Sin alertas para mostrar"
        description="Ajuste los filtros o ingrese una nueva alerta desde la integración de Wazuh/OPNsense."
      />
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="table-base">
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Alerta</th>
            <th className="hidden md:table-cell">Origen</th>
            <th>Estado</th>
            <th className="hidden sm:table-cell">Riesgo</th>
            <th className="hidden lg:table-cell">Recibida</th>
            <th aria-label="Acciones" />
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              onClick={() => navigate(`/alerts/${alert.id}`)}
              className="cursor-pointer"
            >
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="max-w-[420px]">
                <p className="truncate text-[13px] font-medium text-slate-100">{alert.title}</p>
                <p className="mt-0.5 truncate text-[11px] text-slate-500">
                  {alert.source} · {alert.hostname || "sin host"} · {alert.source_ip || "sin IP"}
                  {!compact && alert.rule_id ? ` · regla ${alert.rule_id}` : ""}
                </p>
              </td>
              <td className="hidden md:table-cell">
                <span className="text-xs text-slate-400">{alert.source_ip || "—"}</span>
                <p className="text-[10px] text-slate-600">{alert.asset?.hostname || alert.agent_name || "—"}</p>
              </td>
              <td>
                <AlertStatusBadge status={alert.status} />
              </td>
              <td className="hidden w-28 sm:table-cell">
                <div className="flex items-center gap-2">
                  <span className="w-7 text-xs font-semibold text-slate-300">
                    {alert.triage_result?.risk_score ?? "—"}
                  </span>
                  {alert.triage_result ? <RiskMeter score={alert.triage_result.risk_score} className="w-14" /> : null}
                </div>
              </td>
              <td className="hidden whitespace-nowrap text-[11px] text-slate-500 lg:table-cell">
                {formatDateTime(alert.received_at)}
              </td>
              <td>
                <ArrowUpRight size={15} className="text-slate-600" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
