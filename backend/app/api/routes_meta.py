"""Metadatos, health checks y catálogos para la interfaz."""
from __future__ import annotations

import platform
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.enums import AlertStatus, IncidentStatus, ReportFormat, ReportType, Severity, Verdict
from app.seed import USERS

router = APIRouter(prefix="/meta", tags=["Metadatos"])


@router.get("/health", summary="Estado del servicio y la base de datos")
def health(db: Session = Depends(get_db)) -> dict:
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover
        database = f"error: {exc}"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "database": database,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
    }


@router.get("/version", summary="Versión de la aplicación")
def version() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "api": settings.api_v1_prefix,
        "environment": settings.environment,
    }


@router.get("/catalog", summary="Catálogos de estados y severidades")
def catalog() -> dict:
    return {
        "severity": [
            {"value": item.value, "label": label}
            for item, label in [
                (Severity.CRITICAL, "Crítica"),
                (Severity.HIGH, "Alta"),
                (Severity.MEDIUM, "Media"),
                (Severity.LOW, "Baja"),
                (Severity.INFO, "Informativa"),
            ]
        ],
        "alert_status": [
            {"value": item.value, "label": label}
            for item, label in [
                (AlertStatus.PENDING, "Pendiente"),
                (AlertStatus.TRIAGING, "En triaje"),
                (AlertStatus.TRIAGED, "Triada"),
                (AlertStatus.ESCALATED, "Escalada"),
                (AlertStatus.FALSE_POSITIVE, "Falso positivo"),
                (AlertStatus.CLOSED, "Cerrada"),
            ]
        ],
        "incident_status": [
            {"value": item.value, "label": label}
            for item, label in [
                (IncidentStatus.OPEN, "Abierto"),
                (IncidentStatus.INVESTIGATING, "En investigación"),
                (IncidentStatus.CONTAINED, "Contenido"),
                (IncidentStatus.RESOLVED, "Resuelto"),
                (IncidentStatus.CLOSED, "Cerrado"),
            ]
        ],
        "verdict": [
            {"value": item.value, "label": label}
            for item, label in [
                (Verdict.TRUE_POSITIVE, "Verdadero positivo"),
                (Verdict.FALSE_POSITIVE, "Falso positivo"),
                (Verdict.SUSPICIOUS, "Sospechoso"),
                (Verdict.BENIGN, "Benigno"),
            ]
        ],
        "report_type": [
            {"value": ReportType.OPERATIONAL.value, "label": "Operacional"},
            {"value": ReportType.MANAGEMENT.value, "label": "Gestión"},
            {"value": ReportType.AUDIT.value, "label": "Auditoría"},
        ],
        "report_format": [item.value for item in ReportFormat],
    }


@router.get("/demo-accounts", summary="Credenciales demo (solo entorno de demostración)")
def demo_accounts() -> list[dict]:
    if not settings.demo_mode or settings.environment.lower() == "production":
        return []
    return [
        {
            "email": item["email"],
            "password": item["password"],
            "name": item["full_name"],
            "role": item["role"],
        }
        for item in USERS
    ]
