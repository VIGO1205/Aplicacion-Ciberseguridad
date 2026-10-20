import { Link } from "react-router-dom";
import { ArrowLeft, Radar } from "lucide-react";
import { Button } from "../components/ui";

export function NotFoundPage() {
  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center text-center">
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-3xl border border-cyan-400/20 bg-cyan-400/[0.06]">
        <Radar className="text-cyan-300" size={30} />
      </div>
      <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-cyan-400">Error 404</p>
      <h1 className="mt-2 text-2xl font-bold text-white">Ruta no encontrada</h1>
      <p className="mt-2 max-w-sm text-sm text-slate-400">
        La página que busca no existe o fue movida. Regrese al panel de control para continuar.
      </p>
      <Link to="/" className="mt-6">
        <Button variant="outline">
          <ArrowLeft size={15} /> Volver al dashboard
        </Button>
      </Link>
    </div>
  );
}
