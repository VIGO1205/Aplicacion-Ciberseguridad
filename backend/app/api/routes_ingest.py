"""Ingesta de alertas desde n8n, Wazuh u OPNsense mediante API key."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import verify_ingest_key
from app.core.security import client_ip
from app.db.session import get_db
from app.models import User
from app.schemas import IngestResult, TriageResultOut
from app.services.audit import record_audit
from app.services.normalizer import ingest_alert
from app.services.triage import TriageUnavailable, triage_alert

router = APIRouter(prefix="/ingest", tags=["Ingesta"])


@router.post(
    "/alert",
    response_model=IngestResult,
    summary="Ingerir una alerta cruda (Wazuh, OPNsense o genérica)",
    dependencies=[Depends(verify_ingest_key)],
)
def ingest(
    payload: dict[str, Any],
    request: Request,
    response: Response,
    source: str | None = Query(default=None, max_length=40),
    auto_triage: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> IngestResult:
    # n8n puede enviar el cuerpo completo del webhook bajo la clave "body".
    if isinstance(payload.get("body"), dict) and "rule" not in payload:
        payload = payload["body"]

    alert, duplicate = ingest_alert(db, payload, source_hint=source)
    triage_out = None
    if auto_triage and not duplicate and alert.triage_result is None:
        try:
            triage = triage_alert(db, alert)
            triage_out = TriageResultOut.model_validate(triage)
        except TriageUnavailable as exc:
            record_audit(
                db,
                module="ingest",
                action="Alerta ingerida; triaje no disponible",
                event_type="TRIAGE_ERROR",
                actor_email="n8n@integracion",
                actor_role="integration",
                entity_type="alert",
                entity_id=alert.id,
                description=str(exc)[:500],
                status_code=503,
                ip_address=client_ip(request),
            )
            db.commit()
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    record_audit(
        db,
        module="ingest",
        action="Ingesta duplicada (idempotente)" if duplicate else "Ingesta de alerta",
        event_type="INGEST",
        actor_email="n8n@integracion",
        actor_role="integration",
        entity_type="alert",
        entity_id=alert.id,
        description=f"{alert.title} · fingerprint {alert.fingerprint[:12]}",
        detail={"duplicate": duplicate, "source": alert.source, "auto_triage": auto_triage},
        method="POST",
        path="/api/v1/ingest/alert",
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    response.status_code = 200 if duplicate else 201
    return IngestResult(
        alert_id=alert.id,
        status=alert.status.value,
        duplicate=duplicate,
        severity=alert.severity,
        message="Alerta duplicada: se actualizó last_seen_at" if duplicate else "Alerta creada",
        triage=triage_out,
    )


@router.get("/example", summary="Ejemplo de payload para n8n", dependencies=[Depends(verify_ingest_key)])
def example() -> dict:
    return {
        "id": "wazuh-5710-2026001",
        "timestamp": "2026-10-19T14:05:00-05:00",
        "rule": {"id": "5710", "level": 10, "description": "Fuerza bruta SSH detectada"},
        "agent": {"name": "srv-web01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
        "full_log": "48 intentos de autenticación fallidos en 3 minutos.",
    }
