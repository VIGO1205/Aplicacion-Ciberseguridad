"""Microservicio FastAPI de triaje con LangChain."""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException

from app.agent import triage
from app.schemas import TriageRequest, TriageResponse
from app.settings import settings
from app.tools import tool_catalog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s · %(message)s",
)
logger = logging.getLogger("soc-lite-ai")

app = FastAPI(
    title="SOC-Lite Triage AI",
    version=settings.app_version,
    description=(
        "Microservicio de triaje con LangChain: herramientas de enriquecimiento, "
        "razonamiento con LLM local (Ollama) y fallback heurístico explicable."
    ),
)


def verify_internal_key(x_internal_key: str | None = Header(default=None, alias="X-Internal-Key")) -> None:
    if settings.internal_api_key and x_internal_key != settings.internal_api_key:
        raise HTTPException(status_code=401, detail="Clave interna inválida")


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {"service": settings.app_name, "docs": "/docs", "health": "/health"}


@app.get("/health", summary="Health check")
def health() -> dict:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "llm_provider": settings.llm_provider,
        "ollama_model": settings.ollama_model,
        "enrichment_enabled": settings.enrichment_enabled,
        "external_enrichment_configured": settings.has_external_enrichment,
    }


@app.get("/tools", summary="Herramientas del agente", dependencies=[Depends(verify_internal_key)])
def tools() -> list[dict]:
    return tool_catalog()


@app.post("/triage", response_model=TriageResponse, summary="Triar una alerta", dependencies=[Depends(verify_internal_key)])
def run_triage(payload: TriageRequest) -> TriageResponse:
    logger.info("Triaje solicitado para alerta %s (%s)", payload.alert_id, payload.title[:80])
    return triage(payload)
