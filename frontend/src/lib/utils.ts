import { clsx, type ClassValue } from "clsx";
import { format, formatDistanceToNow, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import { twMerge } from "tailwind-merge";
import type { AlertStatus, IncidentStatus, Severity, Verdict } from "../types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function toDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  try {
    return parseISO(value);
  } catch {
    return null;
  }
}

export function formatDate(value: string | null | undefined, pattern = "dd MMM yyyy") {
  const date = toDate(value);
  return date ? format(date, pattern, { locale: es }) : "—";
}

export function formatDateTime(value: string | null | undefined) {
  return formatDate(value, "dd MMM · HH:mm");
}

export function timeAgo(value: string | null | undefined) {
  const date = toDate(value);
  if (!date) return "—";
  return formatDistanceToNow(date, { addSuffix: true, locale: es });
}

export function formatNumber(value: number, decimals = 0) {
  return new Intl.NumberFormat("es-PE", {
    maximumFractionDigits: decimals,
    minimumFractionDigits: decimals,
  }).format(value);
}

export function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Informativa",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  info: "#38bdf8",
};

export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  pending: "Pendiente",
  triaging: "En triaje",
  triaged: "Triada",
  escalated: "Escalada",
  false_positive: "Falso positivo",
  closed: "Cerrada",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: "Verdadero positivo",
  false_positive: "Falso positivo",
  suspicious: "Sospechoso",
  benign: "Benigno",
};

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  open: "Abierto",
  investigating: "Investigación",
  contained: "Contenido",
  resolved: "Resuelto",
  closed: "Cerrado",
};

export const ROLE_LABEL: Record<string, string> = {
  admin: "Administrador",
  supervisor: "Supervisor SOC",
  analyst: "Analista SOC",
  auditor: "Auditor",
  viewer: "Consulta",
};

export function slaState(due: string | null, closed?: string | null) {
  if (!due) return { label: "Sin SLA", tone: "neutral" as const };
  const dueDate = toDate(due);
  if (!dueDate) return { label: "Sin SLA", tone: "neutral" as const };
  if (closed) return { label: "Cumplido", tone: "ok" as const };
  const diffMinutes = Math.round((dueDate.getTime() - Date.now()) / 60000);
  if (diffMinutes < 0) {
    const overdue = Math.abs(diffMinutes);
    return {
      label: overdue >= 1440 ? `Vencido ${Math.floor(overdue / 1440)} d` : `Vencido ${overdue} min`,
      tone: "danger" as const,
    };
  }
  if (diffMinutes < 120) return { label: `Vence en ${diffMinutes} min`, tone: "warn" as const };
  return { label: `Vence en ${Math.round(diffMinutes / 60)} h`, tone: "ok" as const };
}

export function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}
