"""Bitácora de auditoría: consulta y registro de entradas/salidas por módulo."""
from __future__ import annotations

import math
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import Pagination, get_current_user, require_permissions
from app.core.security import client_ip
from app.db.session import get_db
from app.models import AuditLog, User
from app.schemas import AuditOut, AuditPage, Message, ModuleEvent
from app.services.audit import record_audit

router = APIRouter(prefix="/audit", tags=["Auditoría"])


@router.get("", response_model=AuditPage, summary="Consultar bitácora")
def list_audit(
    pagination: Pagination = Depends(),
    module: str | None = None,
    event_type: str | None = None,
    direction: str | None = Query(default=None, pattern="^(IN|OUT)$"),
    user_email: str | None = None,
    q: str | None = Query(default=None, max_length=120),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("audit:read")),
) -> AuditPage:
    conditions = []
    if module:
        conditions.append(AuditLog.module == module)
    if event_type:
        conditions.append(AuditLog.event_type == event_type)
    if direction:
        conditions.append(AuditLog.direction == direction)
    if user_email:
        conditions.append(AuditLog.actor_email.ilike(f"%{user_email}%"))
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            or_(
                AuditLog.action.ilike(needle),
                AuditLog.description.ilike(needle),
                AuditLog.entity_id.ilike(needle),
                AuditLog.ip_address.ilike(needle),
            )
        )
    count_stmt = select(func.count(AuditLog.id))
    stmt = select(AuditLog)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
        stmt = stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0
    logs = list(
        db.scalars(
            stmt.order_by(AuditLog.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        ).all()
    )
    return AuditPage(
        items=[AuditOut.model_validate(log) for log in logs],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(total / pagination.page_size) if total else 0,
    )


@router.post("/module-event", response_model=Message, summary="Registrar entrada o salida de módulo")
def module_event(
    payload: ModuleEvent,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Message:
    event_type = "MODULE_ENTER" if payload.direction == "IN" else "MODULE_EXIT"
    record_audit(
        db,
        module=payload.module,
        action=f"{'Ingreso' if payload.direction == 'IN' else 'Salida'} al módulo {payload.module}",
        event_type=event_type,
        user=user,
        direction=payload.direction,
        description=f"Navegación del usuario en el módulo {payload.module}",
        detail=payload.detail,
        method="POST",
        path="/api/v1/audit/module-event",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    return Message(message="Evento de módulo registrado")


@router.get("/stats", summary="Estadísticas de auditoría")
def audit_stats(
    days: int = Query(default=7, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("audit:read")),
) -> dict:
    from datetime import timedelta, timezone

    start = datetime.now(timezone.utc) - timedelta(days=days)
    by_module = db.execute(
        select(AuditLog.module, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start)
        .group_by(AuditLog.module)
        .order_by(func.count(AuditLog.id).desc())
    ).all()
    by_event = db.execute(
        select(AuditLog.event_type, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start)
        .group_by(AuditLog.event_type)
        .order_by(func.count(AuditLog.id).desc())
    ).all()
    by_direction = db.execute(
        select(AuditLog.direction, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start, AuditLog.direction.is_not(None))
        .group_by(AuditLog.direction)
    ).all()
    active_users = db.scalar(
        select(func.count(func.distinct(AuditLog.user_id))).where(AuditLog.created_at >= start)
    ) or 0
    total = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.created_at >= start)) or 0
    return {
        "period_days": days,
        "total_events": total,
        "active_users": active_users,
        "by_module": [{"name": name or "sistema", "value": value} for name, value in by_module],
        "by_event": [{"name": name, "value": value} for name, value in by_event],
        "by_direction": [{"name": name, "value": value} for name, value in by_direction if name],
    }


@router.get("/options", summary="Catálogo de filtros de auditoría")
def audit_options(
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("audit:read")),
) -> dict:
    modules = [row[0] for row in db.execute(select(AuditLog.module).distinct().order_by(AuditLog.module)).all()]
    events = [
        row[0]
        for row in db.execute(select(AuditLog.event_type).distinct().order_by(AuditLog.event_type)).all()
    ]
    return {"modules": modules, "event_types": events}
