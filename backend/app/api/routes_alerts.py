"""API de alertas: consulta, triaje, escalamiento y cierre."""
from __future__ import annotations

import math
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import Pagination, get_current_user, require_permissions
from app.core.security import client_ip
from app.db.session import get_db
from app.models import Alert, AuditLog, Incident, TriageResult, User
from app.models.enums import (
    AlertStatus,
    IncidentStatus,
    Severity,
    Verdict,
)
from app.schemas import (
    AlertCreate,
    AlertDetailOut,
    AlertOut,
    AlertPage,
    AlertStatusUpdate,
    AlertUpdate,
    AuditOut,
    EscalateRequest,
    IncidentOut,
    TriageRequest,
    TriageResultIn,
    TriageResultOut,
)
from app.services.audit import record_audit
from app.services.normalizer import find_asset, manual_alert_values
from app.services.triage import TriageUnavailable, persist_triage, triage_alert

router = APIRouter(prefix="/alerts", tags=["Alertas"])

SLA_HOURS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 8,
    Severity.MEDIUM: 24,
    Severity.LOW: 48,
    Severity.INFO: 72,
}


def _get_alert(db: Session, alert_id: uuid.UUID, *, detail: bool = False) -> Alert:
    stmt = select(Alert).where(Alert.id == alert_id)
    if detail:
        stmt = stmt.options(selectinload(Alert.enrichment_data))
    alert = db.scalar(stmt)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    return alert


@router.get("", response_model=AlertPage, summary="Listar alertas")
def list_alerts(
    pagination: Pagination = Depends(),
    severity: Severity | None = None,
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    source: str | None = None,
    verdict: Verdict | None = None,
    q: str | None = Query(default=None, max_length=120),
    asset_id: uuid.UUID | None = None,
    assigned_to_id: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    open_only: bool = False,
    sort: str = Query(default="received_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("alerts:read")),
) -> AlertPage:
    conditions = []
    if severity:
        conditions.append(Alert.severity == severity)
    if alert_status:
        conditions.append(Alert.status == alert_status)
    if source:
        conditions.append(Alert.source == source)
    if verdict:
        conditions.append(TriageResult.verdict == verdict)
    if asset_id:
        conditions.append(Alert.asset_id == asset_id)
    if assigned_to_id:
        conditions.append(Alert.assigned_to_id == assigned_to_id)
    if date_from:
        conditions.append(Alert.received_at >= date_from)
    if date_to:
        conditions.append(Alert.received_at <= date_to)
    if open_only:
        conditions.append(
            Alert.status.in_(
                [AlertStatus.PENDING, AlertStatus.TRIAGING, AlertStatus.TRIAGED, AlertStatus.ESCALATED]
            )
        )
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            or_(
                Alert.title.ilike(needle),
                Alert.description.ilike(needle),
                Alert.source_ip.ilike(needle),
                Alert.hostname.ilike(needle),
                Alert.external_id.ilike(needle),
                Alert.rule_id.ilike(needle),
            )
        )

    count_stmt = select(func.count(Alert.id)).select_from(Alert).outerjoin(
        TriageResult, TriageResult.alert_id == Alert.id
    )
    stmt = select(Alert).outerjoin(TriageResult, TriageResult.alert_id == Alert.id)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
        stmt = stmt.where(*conditions)

    total = db.scalar(count_stmt) or 0
    order_column = {
        "received_at": Alert.received_at,
        "severity": Alert.rule_level,
        "risk": TriageResult.risk_score,
        "status": Alert.status,
        "source": Alert.source,
    }.get(sort, Alert.received_at)
    stmt = stmt.order_by(order_column.asc() if order == "asc" else order_column.desc())
    stmt = stmt.offset(pagination.offset).limit(pagination.page_size)
    alerts = list(db.scalars(stmt).unique().all())

    pages = math.ceil(total / pagination.page_size) if total else 0
    return AlertPage(
        items=[AlertOut.model_validate(alert) for alert in alerts],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Detalle de una alerta")
def get_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("alerts:read")),
) -> AlertDetailOut:
    alert = _get_alert(db, alert_id, detail=True)
    return AlertDetailOut.model_validate(alert)


@router.post("", response_model=AlertDetailOut, status_code=201, summary="Crear alerta manual")
def create_alert(
    payload: AlertCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:create")),
) -> AlertDetailOut:
    data = manual_alert_values(payload.model_dump())
    asset = find_asset(db, data.get("hostname"), data.get("source_ip"), data.get("destination_ip"))
    alert = Alert(**data, asset_id=asset.id if asset else None)
    db.add(alert)
    db.flush()
    record_audit(
        db,
        module="alerts",
        action="Creación manual de alerta",
        event_type="CREATE",
        user=user,
        entity_type="alert",
        entity_id=alert.id,
        description=alert.title,
        method="POST",
        path="/api/v1/alerts",
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    db.refresh(alert)
    return AlertDetailOut.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertDetailOut, summary="Actualizar alerta")
def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:update")),
) -> AlertDetailOut:
    alert = _get_alert(db, alert_id, detail=True)
    changes = payload.model_dump(exclude_unset=True)
    if "assigned_to_id" in changes and changes["assigned_to_id"]:
        assignee = db.get(User, changes["assigned_to_id"])
        if assignee is None or not assignee.is_active:
            raise HTTPException(status_code=404, detail="Usuario asignado no encontrado")
    for field, value in changes.items():
        setattr(alert, field, value)
    if changes.get("status") == AlertStatus.CLOSED and alert.closed_at is None:
        from datetime import timezone

        alert.closed_at = datetime.now(timezone.utc)
    record_audit(
        db,
        module="alerts",
        action="Actualización de alerta",
        event_type="UPDATE",
        user=user,
        entity_type="alert",
        entity_id=alert.id,
        description=f"Campos actualizados: {', '.join(changes.keys())}",
        detail={"changes": {key: str(value) for key, value in changes.items()}},
        method="PATCH",
        path=f"/api/v1/alerts/{alert_id}",
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    db.refresh(alert)
    return AlertDetailOut.model_validate(alert)


@router.post("/{alert_id}/triage", response_model=TriageResultOut, summary="Ejecutar triaje")
def run_triage(
    alert_id: uuid.UUID,
    request: Request,
    payload: TriageRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:triage")),
) -> TriageResultOut:
    alert = _get_alert(db, alert_id)
    if alert.triage_result is not None and not (payload and payload.force):
        return TriageResultOut.model_validate(alert.triage_result)
    try:
        triage = triage_alert(db, alert)
    except TriageUnavailable as exc:
        record_audit(
            db,
            module="alerts",
            action="Triaje fallido",
            event_type="TRIAGE_ERROR",
            user=user,
            entity_type="alert",
            entity_id=alert.id,
            description=str(exc)[:500],
            status_code=503,
            ip_address=client_ip(request) if request else None,
        )
        db.commit()
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    record_audit(
        db,
        module="alerts",
        action="Triaje automático ejecutado",
        event_type="TRIAGE",
        user=user,
        entity_type="alert",
        entity_id=alert.id,
        description=f"Veredicto {triage.verdict.value}; motor {triage.engine}",
        detail={
            "verdict": triage.verdict.value,
            "recommended_severity": triage.recommended_severity.value,
            "confidence": triage.confidence,
            "engine": triage.engine,
        },
        method="POST",
        path=f"/api/v1/alerts/{alert_id}/triage",
        ip_address=client_ip(request) if request else None,
    )
    db.commit()
    return TriageResultOut.model_validate(triage)


@router.post(
    "/{alert_id}/triage-result",
    response_model=TriageResultOut,
    summary="Persistir triaje externo (n8n)",
)
def store_triage_result(
    alert_id: uuid.UUID,
    payload: TriageResultIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:triage")),
) -> TriageResultOut:
    alert = _get_alert(db, alert_id)
    triage = persist_triage(db, alert, payload, raw_response={"source": "n8n"})
    record_audit(
        db,
        module="alerts",
        action="Triaje externo persistido",
        event_type="TRIAGE",
        user=user,
        entity_type="alert",
        entity_id=alert.id,
        description=f"Resultado recibido de n8n: {payload.verdict.value}",
        method="POST",
        path=f"/api/v1/alerts/{alert_id}/triage-result",
        ip_address=client_ip(request),
    )
    db.commit()
    return TriageResultOut.model_validate(triage)


@router.post("/{alert_id}/escalate", response_model=IncidentOut, status_code=201, summary="Escalar a incidente")
def escalate_alert(
    alert_id: uuid.UUID,
    payload: EscalateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("incidents:create")),
) -> IncidentOut:
    alert = _get_alert(db, alert_id, detail=True)
    if alert.incident:
        raise HTTPException(status_code=409, detail="La alerta ya tiene un incidente asociado")

    year = datetime.now().year
    sequence = (db.scalar(select(func.count(Incident.id))) or 0) + 1
    code = f"INC-{year}-{sequence:04d}"
    while db.scalar(select(Incident).where(Incident.code == code)):
        sequence += 1
        code = f"INC-{year}-{sequence:04d}"

    from datetime import timedelta, timezone

    now = datetime.now(timezone.utc)
    incident = Incident(
        code=code,
        alert_id=alert.id,
        title=(payload.title or alert.title)[:300],
        description=(payload.description or alert.description)[:5000],
        severity=alert.severity,
        status=IncidentStatus.OPEN,
        owner_id=user.id,
        sla_due_at=now + timedelta(hours=SLA_HOURS.get(alert.severity, 24)),
        opened_at=now,
    )
    alert.status = AlertStatus.ESCALATED
    db.add(incident)
    db.flush()
    record_audit(
        db,
        module="incidents",
        action="Escalamiento de alerta a incidente",
        event_type="CREATE",
        user=user,
        entity_type="incident",
        entity_id=incident.id,
        description=f"{code} · {incident.title}",
        detail={"alert_id": str(alert.id), "sla_due_at": incident.sla_due_at.isoformat()},
        method="POST",
        path=f"/api/v1/alerts/{alert_id}/escalate",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.post("/{alert_id}/status", response_model=AlertDetailOut, summary="Cambiar estado de la alerta")
def change_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:close")),
) -> AlertDetailOut:
    alert = _get_alert(db, alert_id, detail=True)
    alert.status = payload.status
    if payload.status in {AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE}:
        from datetime import timezone

        alert.closed_at = datetime.now(timezone.utc)
    record_audit(
        db,
        module="alerts",
        action=f"Cambio de estado a {payload.status.value}",
        event_type="CLOSE" if payload.status in {AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE} else "UPDATE",
        user=user,
        entity_type="alert",
        entity_id=alert.id,
        description=payload.reason or "Sin justificación adicional",
        detail={"status": payload.status.value, "reason": payload.reason},
        method="POST",
        path=f"/api/v1/alerts/{alert_id}/status",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(alert)
    return AlertDetailOut.model_validate(alert)


@router.get("/{alert_id}/timeline", response_model=list[AuditOut], summary="Timeline de la alerta")
def alert_timeline(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("alerts:read")),
) -> list[AuditOut]:
    alert = _get_alert(db, alert_id)
    logs = list(
        db.scalars(
            select(AuditLog)
            .where(
                or_(
                    (AuditLog.entity_type == "alert") & (AuditLog.entity_id == str(alert.id)),
                    (AuditLog.module == "alerts") & (AuditLog.action.ilike(f"%{alert.title[:40]}%")),
                )
            )
            .order_by(AuditLog.created_at.asc())
            .limit(100)
        ).all()
    )
    return [AuditOut.model_validate(log) for log in logs]
