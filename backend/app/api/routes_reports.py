"""Consulta, generación y descarga de reportes."""
from __future__ import annotations

import math
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Pagination, require_permissions
from app.core.config import settings
from app.core.security import client_ip
from app.db.session import get_db
from app.models import Report, User
from app.models.enums import ReportFormat, ReportType
from app.schemas import ReportCreate, ReportOut, ReportPage
from app.services.audit import record_audit
from app.services.reports import generate_report

router = APIRouter(prefix="/reports", tags=["Reportes"])

MEDIA_TYPES = {
    ReportFormat.PDF: "application/pdf",
    ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ReportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def _download_url(report: Report) -> str:
    return f"{settings.api_v1_prefix}/reports/{report.id}/download"


@router.get("", response_model=ReportPage, summary="Listar reportes generados")
def list_reports(
    pagination: Pagination = Depends(),
    report_type: ReportType | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("reports:read")),
) -> ReportPage:
    conditions = []
    if "audit:read" not in user.permission_codes and user.role.name != "admin":
        conditions.append(Report.report_type != ReportType.AUDIT)
    if report_type:
        conditions.append(Report.report_type == report_type)
    count_stmt = select(func.count(Report.id))
    stmt = select(Report)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
        stmt = stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0
    reports = list(
        db.scalars(
            stmt.order_by(Report.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        ).all()
    )
    items = []
    for report in reports:
        item = ReportOut.model_validate(report)
        item.download_url = _download_url(report)
        items.append(item)
    return ReportPage(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(total / pagination.page_size) if total else 0,
    )


@router.post("", response_model=ReportOut, status_code=201, summary="Generar reporte")
def create_report(
    payload: ReportCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("reports:export")),
) -> ReportOut:
    if payload.report_type == ReportType.AUDIT and "audit:read" not in user.permission_codes:
        raise HTTPException(status_code=403, detail="Se requiere permiso audit:read para el reporte de auditoría")
    try:
        report = generate_report(db, user, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - protección de borde
        raise HTTPException(status_code=500, detail=f"No se pudo generar el reporte: {exc}") from exc

    record_audit(
        db,
        module="reports",
        action=f"Generación de reporte {payload.report_type.value} en {payload.format.value.upper()}",
        event_type="EXPORT",
        user=user,
        entity_type="report",
        entity_id=report.id,
        description=report.name,
        detail={"format": payload.format.value, "size_bytes": report.size_bytes},
        method="POST",
        path="/api/v1/reports",
        ip_address=client_ip(request),
    )
    db.commit()
    result = ReportOut.model_validate(report)
    result.download_url = _download_url(report)
    return result


@router.get("/{report_id}/download", summary="Descargar reporte")
def download_report(
    report_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("reports:read")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    if report.report_type == ReportType.AUDIT and "audit:read" not in user.permission_codes and user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Se requiere permiso audit:read para este reporte")
    path = (settings.reports_path / report.file_name).resolve()
    if settings.reports_path.resolve() not in path.parents or not path.exists():
        raise HTTPException(status_code=404, detail="El archivo del reporte no está disponible")
    record_audit(
        db,
        module="reports",
        action=f"Descarga de reporte {report.format.value.upper()}",
        event_type="DOWNLOAD",
        user=user,
        entity_type="report",
        entity_id=report.id,
        description=report.name,
        method="GET",
        path=f"/api/v1/reports/{report_id}/download",
        ip_address=client_ip(request),
    )
    db.commit()
    return FileResponse(
        path=str(path),
        media_type=MEDIA_TYPES.get(report.format, "application/octet-stream"),
        filename=report.file_name,
    )
