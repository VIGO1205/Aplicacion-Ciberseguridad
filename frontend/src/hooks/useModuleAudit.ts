import { useEffect } from "react";
import { api, getAccessToken } from "../lib/api";

/**
 * Registra entrada y salida del módulo en la bitácora.
 * La salida usa fetch keepalive para sobrevivir a la navegación/cierre de pestaña.
 */
export function useModuleAudit(module: string) {
  useEffect(() => {
    if (!getAccessToken()) return;
    void api.post("/audit/module-event", { module, direction: "IN" }).catch(() => undefined);

    const sendExit = () => {
      const token = getAccessToken();
      if (!token) return;
      const base = api.defaults.baseURL || "/api/v1";
      void fetch(`${base}/audit/module-event`, {
        method: "POST",
        keepalive: true,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ module, direction: "OUT", detail: {} }),
      }).catch(() => undefined);
    };

    const onBeforeUnload = () => sendExit();
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
      sendExit();
    };
  }, [module]);
}
