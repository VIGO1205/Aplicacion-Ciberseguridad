"""Servicio de bitácora de auditoría."""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog, User


def record_audit(
    db: Session,
    *,
    module: str,
    action: str,
    event_type: str = "API_ACCESS",
    user: User | None = None,
    user_id: uuid.UUID | str | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    direction: str | None = None,
    entity_type: str | None = None,
    entity_id: str | uuid.UUID | None = None,
    description: str = "",
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
    duration_ms: int | None = None,
) -> AuditLog:
    """Añade un evento a la sesión. El commit lo decide el caso de uso."""
    log = AuditLog(
        user_id=user.id if user else (uuid.UUID(str(user_id)) if user_id else None),
        actor_email=actor_email or (user.email if user else "sistema"),
        actor_role=actor_role or (user.role.name if user else ""),
        event_type=event_type,
        module=module,
        action=action,
        direction=direction,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        description=description[:500],
        method=method,
        path=path,
        status_code=status_code,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:300] or None,
        request_id=request_id,
        detail=detail or {},
        duration_ms=duration_ms,
    )
    db.add(log)
    return log
