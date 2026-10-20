import type { ReactNode } from "react";
import type { NamedCount, SeriesPoint } from "../types";
import { cn, formatNumber } from "../lib/utils";

export function AreaTrend({
  data,
  height = 190,
  color = "#22d3ee",
}: {
  data: SeriesPoint[];
  height?: number;
  color?: string;
}) {
  const width = 720;
  const padding = { top: 18, right: 12, bottom: 28, left: 30 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;
  const max = Math.max(1, ...data.map((item) => item.value));
  const points = data.map((item, index) => {
    const x = padding.left + (data.length <= 1 ? innerW / 2 : (index / (data.length - 1)) * innerW);
    const y = padding.top + innerH - (item.value / max) * innerH;
    return { x, y, ...item };
  });
  const line = points.map((point) => `${point.x},${point.y}`).join(" ");
  const area = `${padding.left},${padding.top + innerH} ${line} ${padding.left + innerW},${padding.top + innerH}`;
  const gradientId = `trend-${color.replace("#", "")}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label="Evolución diaria de alertas">
      <defs>
        <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.32" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
        const y = padding.top + innerH * ratio;
        return (
          <g key={ratio}>
            <line x1={padding.left} x2={width - padding.right} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
            <text x={padding.left - 7} y={y + 3} textAnchor="end" className="fill-slate-500 text-[9px]">
              {Math.round(max * (1 - ratio))}
            </text>
          </g>
        );
      })}
      <polygon points={area} fill={`url(#${gradientId})`} />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" />
      {points.map((point, index) => {
        const show = data.length <= 10 || index % Math.ceil(data.length / 8) === 0 || index === data.length - 1;
        return (
          <g key={point.label}>
            <circle cx={point.x} cy={point.y} r="3" fill="#050b16" stroke={color} strokeWidth="2" />
            {show ? (
              <text x={point.x} y={height - 8} textAnchor="middle" className="fill-slate-500 text-[9px]">
                {point.label.slice(5)}
              </text>
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
  info: "#38bdf8",
};

const FALLBACK_COLORS = ["#22d3ee", "#a78bfa", "#f472b6", "#34d399", "#fbbf24", "#38bdf8"];

export function DonutChart({ data, totalLabel = "Total" }: { data: NamedCount[]; totalLabel?: string }) {
  const total = data.reduce((acc, item) => acc + item.value, 0);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const slices = data.map((item, index) => {
    const ratio = total ? item.value / total : 0;
    const length = ratio * circumference;
    const slice = {
      ...item,
      color: SEVERITY_COLORS[item.name] || FALLBACK_COLORS[index % FALLBACK_COLORS.length],
      dasharray: `${length} ${circumference - length}`,
      offset: -offset,
      ratio,
    };
    offset += length;
    return slice;
  });

  return (
    <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-center sm:justify-center">
      <div className="relative h-36 w-36 shrink-0">
        <svg viewBox="0 0 140 140" className="-rotate-90">
          <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14" />
          {slices.map((slice) => (
            <circle
              key={slice.name}
              cx="70"
              cy="70"
              r={radius}
              fill="none"
              stroke={slice.color}
              strokeWidth="14"
              strokeDasharray={slice.dasharray}
              strokeDashoffset={slice.offset}
              strokeLinecap="butt"
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-white">{formatNumber(total)}</span>
          <span className="text-[10px] uppercase tracking-wider text-slate-500">{totalLabel}</span>
        </div>
      </div>
      <div className="grid w-full grid-cols-2 gap-x-5 gap-y-2.5 sm:w-auto sm:grid-cols-1">
        {slices.map((slice) => (
          <div key={slice.name} className="flex items-center justify-between gap-4 text-xs sm:min-w-[130px]">
            <span className="flex items-center gap-2 text-slate-400">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: slice.color }} />
              {slice.name}
            </span>
            <span className="font-semibold text-slate-200">
              {slice.value}
              <span className="ml-1 text-[10px] text-slate-500">{Math.round(slice.ratio * 100)}%</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function BarList({
  data,
  color = "#22d3ee",
  emptyLabel = "Sin datos",
  formatValue,
}: {
  data: NamedCount[];
  color?: string;
  emptyLabel?: string;
  formatValue?: (value: number) => string;
}) {
  const max = Math.max(1, ...data.map((item) => item.value));
  if (!data.length) return <p className="py-6 text-center text-xs text-slate-500">{emptyLabel}</p>;
  return (
    <div className="space-y-3">
      {data.map((item, index) => (
        <div key={`${item.name}-${index}`}>
          <div className="mb-1 flex items-center justify-between gap-3 text-xs">
            <span className="truncate text-slate-300" title={item.name}>
              {item.name}
            </span>
            <span className="shrink-0 font-semibold text-slate-200">
              {formatValue ? formatValue(item.value) : formatNumber(item.value)}
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max(3, (item.value / max) * 100)}%`,
                backgroundColor: color,
                opacity: 1 - index * 0.06,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export function KpiCard({
  label,
  value,
  hint,
  icon,
  tone = "cyan",
  footer,
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: ReactNode;
  tone?: "cyan" | "rose" | "amber" | "emerald" | "violet";
  footer?: ReactNode;
}) {
  const tones = {
    cyan: "text-cyan-300 border-cyan-400/20 bg-cyan-400/10",
    rose: "text-rose-300 border-rose-400/20 bg-rose-400/10",
    amber: "text-amber-300 border-amber-400/20 bg-amber-400/10",
    emerald: "text-emerald-300 border-emerald-400/20 bg-emerald-400/10",
    violet: "text-violet-300 border-violet-400/20 bg-violet-400/10",
  };
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-white/[0.07] bg-slate-900/55 p-5 shadow-card transition hover:border-white/15 hover:bg-slate-900/80">
      <div className="absolute -right-8 -top-10 h-28 w-28 rounded-full bg-cyan-400/[0.04] blur-2xl transition group-hover:bg-cyan-400/[0.08]" />
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-slate-500">{label}</p>
          <p className="mt-2 text-3xl font-bold tracking-tight text-white">{value}</p>
        </div>
        <div className={cn("rounded-xl border p-2", tones[tone])}>{icon}</div>
      </div>
      {hint ? <p className="mt-3 text-xs text-slate-400">{hint}</p> : null}
      {footer}
    </div>
  );
}

export function Sparkline({ values, color = "#22d3ee" }: { values: number[]; color?: string }) {
  const max = Math.max(1, ...values);
  const points = values
    .map((value, index) => `${(index / Math.max(1, values.length - 1)) * 100},${28 - (value / max) * 24}`)
    .join(" ");
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="h-7 w-full">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
