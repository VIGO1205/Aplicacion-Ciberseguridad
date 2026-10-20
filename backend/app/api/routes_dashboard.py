"""Métricas e indicadores del dashboard."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_permissions
from app.db.session import get_db
from app.models import User
from app.schemas import DashboardOverview
from app.services.metrics import calculate_overview

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview", response_model=DashboardOverview, summary="Indicadores del dashboard")
def overview(
    days: int = Query(default=14, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("dashboard:read")),
) -> DashboardOverview:
    return calculate_overview(db, days=days)
