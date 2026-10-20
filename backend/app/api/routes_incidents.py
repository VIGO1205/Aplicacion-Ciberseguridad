"""API de incidentes y respuesta."""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import Pagination, require_permissions
from app.core.security import client_ip
from app.db.session import get_db
from app.models import Alert, Incident, User
from app.models.enums import IncidentStatus, Severity
from app.schemas import IncidentCreate, IncidentOut, IncidentPage, IncidentUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/incidents", tags=["Incidentes"])

SLA_HOURS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 8,
    Severity.MEDIUM: 24,
    Severity.LOW: 48,
    Severity.INFO: 72,
}


def _next_code(db: Session) -> str:
    year = datetime.now().year
    sequence = (db.scalar(select(func.count(Incident.id))) or 0) + 1
    code = f"INC-{year}-{sequence:04d}"
    while db.scalar(select(Incident).where(Incident.code == code)):
        sequence += 1
        code = f"INC-{year}-{sequence:04d}"
    return code


def _get_incident(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    return incident


@router.get("", response_model=IncidentPage, summary="Listar incidentes")
def list_incidents(
    pagination: Pagination = Depends(),
    incident_status: IncidentStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
    owner_id: uuid.UUID | None = None,
    q: str | None = Query(default=None, max_length=120),
    open_only: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("incidents:read")),
) -> IncidentPage:
    conditions = []
    if incident_status:
        conditions.append(Incident.status == incident_status)
    if severity:
        conditions.append(Incident.severity == severity)
    if owner_id:
        conditions.append(Incident.owner_id == owner_id)
    if open_only:
        conditions.append(
            Incident.status.in_(
                [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]
            )
        )
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            or_(
                Incident.code.ilike(needle),
                Incident.title.ilike(needle),
                Incident.description.ilike(needle),
            )
        )

    count_stmt = select(func.count(Incident.id))
    stmt = select(Incident)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
        stmt = stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0
    incidents = list(
        db.scalars(
            stmt.order_by(Incident.opened_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        ).all()
    )
    return IncidentPage(
        items=[IncidentOut.model_validate(item) for item in incidents],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(total / pagination.page_size) if total else 0,
    )


@router.get("/{incident_id}", response_model=IncidentOut, summary="Detalle de incidente")
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("incidents:read")),
) -> IncidentOut:
    return IncidentOut.model_validate(_get_incident(db, incident_id))


@router.post("", response_model=IncidentOut, status_code=201, summary="Crear incidente")
def create_incident(
    payload: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("incidents:create")),
) -> IncidentOut:
    if payload.alert_id:
        alert = db.get(Alert, payload.alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alerta no encontrada")
        if alert.incident:
            raise HTTPException(status_code=409, detail="La alerta ya tiene un incidente")
    if payload.owner_id and db.get(User, payload.owner_id) is None:
        raise HTTPException(status_code=404, detail="Responsable no encontrado")

    now = datetime.now(timezone.utc)
    incident = Incident(
        code=_next_code(db),
        alert_id=payload.alert_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status=IncidentStatus.OPEN,
        owner_id=payload.owner_id or user.id,
        containment_actions=payload.containment_actions,
        ticket_external_id=payload.ticket_external_id,
        sla_due_at=now + timedelta(hours=SLA_HOURS.get(payload.severity, 24)),
        opened_at=now,
    )
    db.add(incident)
    db.flush()
    record_audit(
        db,
        module="incidents",
        action="Creación de incidente",
        event_type="CREATE",
        user=user,
        entity_type="incident",
        entity_id=incident.id,
        description=f"{incident.code} · {incident.title}",
        method="POST",
        path="/api/v1/incidents",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.patch("/{incident_id}", response_model=IncidentOut, summary="Actualizar incidente")
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("incidents:update")),
) -> IncidentOut:
    incident = _get_incident(db, incident_id)
    changes = payload.model_dump(exclude_unset=True)
    if "owner_id" in changes and changes["owner_id"] and db.get(User, changes["owner_id"]) is None:
        raise HTTPException(status_code=404, detail="Responsable no encontrado")

    for field, value in changes.items():
        setattr(incident, field, value)

    if changes.get("status") in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}:
        incident.closed_at = datetime.now(timezone.utc)
        if incident.alert and incident.status == IncidentStatus.CLOSED:
            from app.models.enums import AlertStatus

            incident.alert.status = AlertStatus.CLOSED
            incident.alert.closed_at = incident.closed_at
    elif "status" in changes and changes["status"] not in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}:
        incident.closed_at = None

    record_audit(
        db,
        module="incidents",
        action="Actualización de incidente",
        event_type="UPDATE",
        user=user,
        entity_type="incident",
        entity_id=incident.id,
        description=f"Campos actualizados: {', '.join(changes.keys())}",
        detail={"changes": {key: str(value) for key, value in changes.items()}},
        method="PATCH",
        path=f"/api/v1/incidents/{incident_id}",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.post("/{incident_id}/close", response_model=IncidentOut, summary="Cerrar incidente")
def close_incident(
    incident_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("incidents:update")),
) -> IncidentOut:
    incident = _get_incident(db, incident_id)
    incident.status = IncidentStatus.CLOSED
    incident.closed_at = datetime.now(timezone.utc)
    if incident.alert:
        from app.models.enums import AlertStatus

        incident.alert.status = AlertStatus.CLOSED
        incident.alert.closed_at = incident.closed_at
    record_audit(
        db,
        module="incidents",
        action="Cierre de incidente",
        event_type="CLOSE",
        user=user,
        entity_type="incident",
        entity_id=incident.id,
        description=incident.code,
        method="POST",
        path=f"/api/v1/incidents/{incident_id}/close",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)
