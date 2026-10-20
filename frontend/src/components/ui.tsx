import {
  forwardRef,
  useEffect,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { ChevronLeft, ChevronRight, Loader2, X } from "lucide-react";
import type { AlertStatus, IncidentStatus, Severity, Verdict } from "../types";
import {
  ALERT_STATUS_LABEL,
  INCIDENT_STATUS_LABEL,
  SEVERITY_LABEL,
  VERDICT_LABEL,
  cn,
} from "../lib/utils";

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */
type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline" | "subtle";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-cyan-400 text-slate-950 hover:bg-cyan-300 shadow-[0_8px_30px_-12px_rgba(34,211,238,0.7)]",
  secondary: "bg-slate-800 text-slate-100 hover:bg-slate-700 border border-white/5",
  ghost: "text-slate-300 hover:bg-white/5 hover:text-white",
  danger: "bg-rose-500 text-white hover:bg-rose-400",
  outline: "border border-white/10 text-slate-200 hover:border-cyan-400/40 hover:bg-cyan-400/5",
  subtle: "bg-cyan-400/10 text-cyan-300 hover:bg-cyan-400/15 border border-cyan-400/20",
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs gap-1.5",
  md: "h-10 px-4 text-sm gap-2",
  lg: "h-11 px-5 text-sm gap-2",
  icon: "h-9 w-9 justify-center",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export function Button({
  className,
  variant = "primary",
  size = "md",
  loading = false,
  children,
  disabled,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center rounded-lg font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60 disabled:cursor-not-allowed disabled:opacity-50",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? <Loader2 size={16} className="animate-spin" /> : null}
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Card                                                                */
/* ------------------------------------------------------------------ */
export function Card({
  children,
  className,
  hover = false,
}: {
  children: ReactNode;
  className?: string;
  hover?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-white/[0.07] bg-slate-900/55 shadow-card backdrop-blur-sm",
        hover && "transition hover:border-cyan-400/20 hover:bg-slate-900/80",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 border-b border-white/[0.06] px-5 py-4", className)}>
      <div>
        <h3 className="text-sm font-semibold tracking-tight text-white">{title}</h3>
        {subtitle ? <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p> : null}
      </div>
      {action}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */
type Tone = "critical" | "high" | "medium" | "low" | "info" | "neutral" | "ok" | "warn" | "danger" | "violet" | "cyan";

const TONES: Record<Tone, string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  high: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  low: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  info: "border-sky-400/30 bg-sky-400/10 text-sky-300",
  neutral: "border-white/10 bg-white/5 text-slate-300",
  ok: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  warn: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  danger: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  violet: "border-violet-400/30 bg-violet-400/10 text-violet-300",
  cyan: "border-cyan-400/30 bg-cyan-400/10 text-cyan-300",
};

export function Badge({
  children,
  tone = "neutral",
  className,
  dot = false,
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
  dot?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-semibold leading-none",
        TONES[tone],
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current" /> : null}
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={SEVERITY_TONE[severity]} dot>
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

const ALERT_STATUS_TONE: Record<AlertStatus, Tone> = {
  pending: "warn",
  triaging: "cyan",
  triaged: "ok",
  escalated: "critical",
  false_positive: "neutral",
  closed: "neutral",
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <Badge tone={ALERT_STATUS_TONE[status]}>{ALERT_STATUS_LABEL[status]}</Badge>;
}

const VERDICT_TONE: Record<Verdict, Tone> = {
  true_positive: "critical",
  false_positive: "neutral",
  suspicious: "warn",
  benign: "low",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <Badge tone={VERDICT_TONE[verdict]}>{VERDICT_LABEL[verdict]}</Badge>;
}

const INCIDENT_TONE: Record<IncidentStatus, Tone> = {
  open: "critical",
  investigating: "warn",
  contained: "cyan",
  resolved: "ok",
  closed: "neutral",
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge tone={INCIDENT_TONE[status]}>{INCIDENT_STATUS_LABEL[status]}</Badge>;
}

/* ------------------------------------------------------------------ */
/* Form controls                                                       */
/* ------------------------------------------------------------------ */
interface FieldProps {
  label?: string;
  error?: string;
  hint?: string;
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & FieldProps>(
  ({ label, error, hint, className, id, ...props }, ref) => {
    const inputId = id || props.name;
    return (
      <label className="block" htmlFor={inputId}>
        {label ? <span className="mb-1.5 block text-xs font-medium text-slate-300">{label}</span> : null}
        <input
          ref={ref}
          id={inputId}
          className={cn(
            "h-10 w-full rounded-lg border border-white/10 bg-slate-950/60 px-3 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10",
            error && "border-rose-400/50",
            className,
          )}
          {...props}
        />
        {error ? <span className="mt-1 block text-[11px] text-rose-400">{error}</span> : null}
        {hint && !error ? <span className="mt-1 block text-[11px] text-slate-500">{hint}</span> : null}
      </label>
    );
  },
);
Input.displayName = "Input";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement> & FieldProps>(
  ({ label, error, className, children, id, ...props }, ref) => {
    const selectId = id || props.name;
    return (
      <label className="block" htmlFor={selectId}>
        {label ? <span className="mb-1.5 block text-xs font-medium text-slate-300">{label}</span> : null}
        <select
          ref={ref}
          id={selectId}
          className={cn(
            "h-10 w-full appearance-none rounded-lg border border-white/10 bg-slate-950/60 px-3 text-sm text-white focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10",
            error && "border-rose-400/50",
            className,
          )}
          {...props}
        >
          {children}
        </select>
        {error ? <span className="mt-1 block text-[11px] text-rose-400">{error}</span> : null}
      </label>
    );
  },
);
Select.displayName = "Select";

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement> & FieldProps
>(({ label, error, className, id, ...props }, ref) => {
  const inputId = id || props.name;
  return (
    <label className="block" htmlFor={inputId}>
      {label ? <span className="mb-1.5 block text-xs font-medium text-slate-300">{label}</span> : null}
      <textarea
        ref={ref}
        id={inputId}
        className={cn(
          "w-full rounded-lg border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/10",
          error && "border-rose-400/50",
          className,
        )}
        {...props}
      />
      {error ? <span className="mt-1 block text-[11px] text-rose-400">{error}</span> : null}
    </label>
  );
});
Textarea.displayName = "Textarea";

/* ------------------------------------------------------------------ */
/* Feedback                                                            */
/* ------------------------------------------------------------------ */
export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("animate-spin text-cyan-400", className)} size={22} />;
}

export function LoadingBlock({ label = "Cargando información…" }: { label?: string }) {
  return (
    <div className="flex min-h-[240px] flex-col items-center justify-center gap-3 text-sm text-slate-400">
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon ? <div className="rounded-2xl border border-white/10 bg-white/5 p-3 text-slate-400">{icon}</div> : null}
      <div>
        <p className="text-sm font-semibold text-white">{title}</p>
        {description ? <p className="mt-1 max-w-md text-xs leading-relaxed text-slate-400">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <EmptyState
      title="No se pudo cargar la información"
      description={message}
      action={
        onRetry ? (
          <Button variant="outline" size="sm" onClick={onRetry}>
            Reintentar
          </Button>
        ) : null
      }
    />
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-lg bg-white/[0.06]", className)} />;
}

/* ------------------------------------------------------------------ */
/* Layout helpers                                                      */
/* ------------------------------------------------------------------ */
export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow ? (
          <p className="mb-1 text-[10px] font-bold uppercase tracking-[0.22em] text-cyan-400">{eyebrow}</p>
        ) : null}
        <h1 className="text-2xl font-bold tracking-tight text-white">{title}</h1>
        {subtitle ? <p className="mt-1 max-w-2xl text-sm text-slate-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Pagination({
  page,
  pages,
  total,
  pageSize,
  onChange,
}: {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onChange: (page: number) => void;
}) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] px-4 py-3 text-xs text-slate-400">
      <span>
        {from}–{to} de {total}
      </span>
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => onChange(page - 1)}
          disabled={page <= 1}
          aria-label="Página anterior"
        >
          <ChevronLeft size={16} />
        </Button>
        <span className="rounded-md border border-white/10 bg-white/5 px-2.5 py-1 font-medium text-slate-200">
          {page} / {Math.max(pages, 1)}
        </span>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => onChange(page + 1)}
          disabled={page >= pages}
          aria-label="Página siguiente"
        >
          <ChevronRight size={16} />
        </Button>
      </div>
    </div>
  );
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button
        type="button"
        className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
        onClick={onClose}
        aria-label="Cerrar"
      />
      <div
        className={cn(
          "relative z-10 max-h-[90vh] w-full overflow-y-auto rounded-2xl border border-white/10 bg-slate-900 shadow-2xl",
          width,
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-white/10 px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-white">{title}</h2>
            {description ? <p className="mt-1 text-xs text-slate-400">{description}</p> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/5 hover:text-white"
            aria-label="Cerrar"
          >
            <X size={18} />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer ? <div className="flex justify-end gap-2 border-t border-white/10 px-5 py-3">{footer}</div> : null}
      </div>
    </div>
  );
}

export function RiskMeter({ score, className }: { score: number; className?: string }) {
  const color = score >= 80 ? "bg-rose-400" : score >= 60 ? "bg-orange-400" : score >= 40 ? "bg-amber-400" : "bg-emerald-400";
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-white/10", className)}>
      <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.max(4, score)}%` }} />
    </div>
  );
}
