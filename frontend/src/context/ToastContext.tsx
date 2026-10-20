import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { cn } from "../lib/utils";

type ToastKind = "success" | "error" | "info";
interface Toast {
  id: number;
  message: string;
  kind: ToastKind;
}

interface ToastContextValue {
  toast: (message: string, kind?: ToastKind) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICONS = {
  success: CheckCircle2,
  error: AlertTriangle,
  info: Info,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((message: string, kind: ToastKind = "info") => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, message, kind }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((item) => item.id !== id));
    }, 4800);
  }, []);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[100] flex w-[min(92vw,380px)] flex-col gap-2">
        {toasts.map((item) => {
          const Icon = ICONS[item.kind];
          return (
            <div
              key={item.id}
              className={cn(
                "pointer-events-auto flex animate-fade-up items-start gap-3 rounded-xl border p-3.5 shadow-2xl backdrop-blur-xl",
                item.kind === "success" && "border-emerald-400/30 bg-emerald-950/80",
                item.kind === "error" && "border-rose-400/30 bg-rose-950/80",
                item.kind === "info" && "border-cyan-400/30 bg-slate-950/90",
              )}
            >
              <Icon
                size={18}
                className={cn(
                  "mt-0.5 shrink-0",
                  item.kind === "success" && "text-emerald-400",
                  item.kind === "error" && "text-rose-400",
                  item.kind === "info" && "text-cyan-400",
                )}
              />
              <p className="flex-1 text-sm leading-snug text-slate-100">{item.message}</p>
              <button
                type="button"
                onClick={() => setToasts((current) => current.filter((toastItem) => toastItem.id !== item.id))}
                className="text-slate-400 transition hover:text-white"
                aria-label="Cerrar notificación"
              >
                <X size={15} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast debe usarse dentro de ToastProvider");
  return context;
}
