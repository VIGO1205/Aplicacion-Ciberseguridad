"""Punto de entrada de la API SOC-Lite."""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api import (
    routes_admin,
    routes_alerts,
    routes_audit,
    routes_auth,
    routes_dashboard,
    routes_incidents,
    routes_ingest,
    routes_meta,
    routes_reports,
)
from app.core.config import settings
from app.core.security import client_ip, decode_token
from app.db.session import SessionLocal, engine, init_db
from app.seed import seed_database
from app.services.audit import record_audit

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s · %(message)s",
)
logger = logging.getLogger("soc-lite")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if settings.auto_seed:
        with SessionLocal() as db:
            stats = seed_database(db)
            logger.info("Datos semilla verificados: %s", stats)
    logger.info("%s %s iniciado en %s", settings.app_name, settings.app_version, settings.environment)
    yield
    engine.dispose()


app = FastAPI(
    title="SOC-Lite API",
    version=settings.app_version,
    description=(
        "API de triaje automático de alertas SOC con enriquecimiento, RBAC, "
        "dashboard, reportes PDF/Word/Excel y bitácora de auditoría."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={"name": "Equipo SOC-Lite"},
    license_info={"name": "Uso académico / interno"},
)

SKIP_AUDIT_PREFIXES = (
    "/api/v1/auth",
    "/api/v1/meta",
    "/api/v1/ingest",
    "/api/v1/audit/module-event",
)
SKIP_AUDIT_EXACT = {"/", "/health", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}


@app.middleware("http")
async def request_context_and_audit(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()

    response = await call_next(request)
    duration_ms = int((time.perf_counter() - started) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    path = request.url.path
    should_audit = (
        request.method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        and path not in SKIP_AUDIT_EXACT
        and not any(path.startswith(prefix) for prefix in SKIP_AUDIT_PREFIXES)
        and request.headers.get("authorization", "").lower().startswith("bearer ")
    )
    if not should_audit:
        return response

    token = request.headers["authorization"].split(" ", 1)[1].strip()
    try:
        claims = decode_token(token, expected_type="access")
    except jwt.InvalidTokenError:
        return response

    relative = path[len(settings.api_v1_prefix) :].strip("/")
    module = relative.split("/")[0] if relative else "root"

    def _write() -> None:
        try:
            with SessionLocal() as db:
                record_audit(
                    db,
                    module=module,
                    action=f"{request.method} {path}",
                    event_type="API_ACCESS",
                    user_id=claims.get("sub"),
                    actor_email=claims.get("email", "desconocido"),
                    actor_role=claims.get("role", ""),
                    description=f"Acceso a {module}",
                    method=request.method,
                    path=path,
                    status_code=response.status_code,
                    ip_address=client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    request_id=request_id,
                    detail={"status": response.status_code},
                    duration_ms=duration_ms,
                )
                db.commit()
        except Exception:  # pragma: no cover - la auditoría no debe tumbar la API
            logger.exception("No se pudo registrar el evento de auditoría")

    await run_in_threadpool(_write)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Content-Disposition"],
    max_age=600,
)

for router in (
    routes_auth.router,
    routes_alerts.router,
    routes_incidents.router,
    routes_dashboard.router,
    routes_reports.router,
    routes_audit.router,
    routes_admin.router,
    routes_ingest.router,
    routes_meta.router,
):
    app.include_router(router, prefix=settings.api_v1_prefix)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "api": settings.api_v1_prefix,
    }


@app.get("/health", tags=["Metadatos"], summary="Health check")
def health() -> JSONResponse:
    database = "ok"
    try:
        with SessionLocal() as db:  # type: Session
            db.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        database = "error"
        logger.error("Health check de base de datos falló: %s", exc)
    payload = {
        "status": "ok" if database == "ok" else "degraded",
        "service": settings.app_name,
        "version": settings.app_version,
        "database": database,
    }
    return JSONResponse(payload, status_code=200 if database == "ok" else 503)
