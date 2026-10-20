"""Contratos Pydantic de la API (request/response)."""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.models.enums import (
    AlertStatus,
    Criticality,
    IncidentStatus,
    ReportFormat,
    ReportType,
    Severity,
    Verdict,
)

T = TypeVar("T")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def _validate_email(value: str) -> str:
    value = value.strip().lower()
    if not _EMAIL_RE.match(value):
        raise ValueError("Correo electrónico inválido")
    return value


EmailStr = Annotated[str, AfterValidator(_validate_email)]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Message(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Autenticación, usuarios y RBAC
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class PermissionOut(ORMModel):
    id: uuid.UUID
    code: str
    module: str
    description: str


class RoleOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    color: str
    is_system: bool
    permissions: list[PermissionOut] = []


class RoleBrief(ORMModel):
    id: uuid.UUID
    name: str
    color: str


class UserBrief(ORMModel):
    id: uuid.UUID
    full_name: str
    email: EmailStr
    role: RoleBrief | None = None


class UserOut(ORMModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_active: bool
    job_title: str
    department: str
    phone: str
    last_login_at: datetime | None
    created_at: datetime
    role: RoleOut


class UserPage(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    page_size: int
    pages: int


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=3, max_length=150)
    password: str = Field(min_length=10, max_length=128)
    role_id: uuid.UUID
    job_title: str = Field(default="", max_length=120)
    department: str = Field(default="", max_length=120)
    phone: str = Field(default="", max_length=40)

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        if not any(c.isupper() for c in value):
            raise ValueError("La contraseña debe incluir al menos una mayúscula")
        if not any(c.islower() for c in value):
            raise ValueError("La contraseña debe incluir al menos una minúscula")
        if not any(c.isdigit() for c in value):
            raise ValueError("La contraseña debe incluir al menos un número")
        return value


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=3, max_length=150)
    role_id: uuid.UUID | None = None
    is_active: bool | None = None
    job_title: str | None = Field(default=None, max_length=120)
    department: str | None = Field(default=None, max_length=120)
    phone: str | None = Field(default=None, max_length=40)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=10, max_length=128)


class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


# ---------------------------------------------------------------------------
# Activos y alertas
# ---------------------------------------------------------------------------
class AssetOut(ORMModel):
    id: uuid.UUID
    hostname: str
    ip_address: str | None
    criticality: Criticality
    owner: str
    environment: str
    operating_system: str
    tags: list[Any] = []


class EnrichmentOut(ORMModel):
    id: uuid.UUID
    provider: str
    indicator: str
    indicator_type: str
    status: str
    risk_score: float | None
    summary: str
    payload: dict[str, Any] = {}
    fetched_at: datetime
    expires_at: datetime | None


class TriageResultOut(ORMModel):
    id: uuid.UUID
    verdict: Verdict
    recommended_severity: Severity
    confidence: float
    risk_score: int
    summary: str
    reasoning: str
    recommended_actions: list[Any] = []
    mitre_techniques: list[Any] = []
    should_escalate: bool
    false_positive_reason: str | None
    engine: str
    model_name: str
    prompt_version: str
    latency_ms: int
    tokens_used: int
    created_at: datetime


class IncidentBrief(ORMModel):
    id: uuid.UUID
    code: str
    title: str
    severity: Severity
    status: IncidentStatus
    sla_due_at: datetime | None
    opened_at: datetime
    closed_at: datetime | None


class OsticketTicketBrief(ORMModel):
    ticket_number: str
    status_state: str
    status_name: str
    last_synced_at: datetime


class AlertOut(ORMModel):
    id: uuid.UUID
    external_id: str | None
    source: str
    title: str
    description: str
    rule_id: str | None
    rule_level: int
    severity: Severity
    status: AlertStatus
    source_ip: str | None
    destination_ip: str | None
    hostname: str | None
    agent_name: str | None
    username: str | None
    mitre_techniques: list[Any] = []
    tags: list[Any] = []
    received_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    asset: AssetOut | None = None
    assigned_to: UserBrief | None = None
    triage_result: TriageResultOut | None = None
    incident: IncidentBrief | None = None
    osticket_link: OsticketTicketBrief | None = None


class AlertDetailOut(AlertOut):
    raw_payload: dict[str, Any] = {}
    enrichment_data: list[EnrichmentOut] = []
    fingerprint: str


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


class AlertCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=5000)
    source: str = Field(default="manual", max_length=40)
    severity: Severity = Severity.MEDIUM
    rule_id: str | None = None
    rule_level: int = Field(default=5, ge=0, le=15)
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    agent_name: str | None = None
    username: str | None = None
    raw_payload: dict[str, Any] = {}


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    severity: Severity | None = None
    assigned_to_id: uuid.UUID | None = None
    tags: list[str] | None = None


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    reason: str = Field(default="", max_length=1000)


class TriageRequest(BaseModel):
    force: bool = False


class TriageResultIn(BaseModel):
    """Resultado de triaje producido por n8n/LangChain y persistido por la API."""

    verdict: Verdict
    recommended_severity: Severity
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    summary: str
    reasoning: str = ""
    recommended_actions: list[Any] = []
    mitre_techniques: list[Any] = []
    should_escalate: bool = False
    false_positive_reason: str | None = None
    engine: str = "langchain"
    model_name: str = ""
    prompt_version: str = "v1"
    latency_ms: int = 0
    tokens_used: int = 0
    enrichment: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Incidentes
# ---------------------------------------------------------------------------
class IncidentOut(ORMModel):
    id: uuid.UUID
    code: str
    alert_id: uuid.UUID | None
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    containment_actions: str
    ticket_external_id: str | None
    sla_due_at: datetime | None
    opened_at: datetime
    closed_at: datetime | None
    created_at: datetime
    owner: UserBrief | None = None


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    page: int
    page_size: int
    pages: int


class IncidentCreate(BaseModel):
    alert_id: uuid.UUID | None = None
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=5000)
    severity: Severity
    owner_id: uuid.UUID | None = None
    containment_actions: str = ""
    ticket_external_id: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: IncidentStatus | None = None
    severity: Severity | None = None
    owner_id: uuid.UUID | None = None
    containment_actions: str | None = None
    ticket_external_id: str | None = None


class EscalateRequest(BaseModel):
    title: str | None = None
    description: str | None = None


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
class KPIBlock(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_open: int
    high_open: int
    false_positive_rate: float
    triage_coverage: float
    automation_rate: float
    mttt_minutes: float
    mttr_hours: float
    sla_compliance: float
    open_incidents: int
    total_incidents: int


class SeriesPoint(BaseModel):
    label: str
    value: float


class NamedCount(BaseModel):
    name: str
    value: int


class DashboardOverview(BaseModel):
    period_days: int
    generated_at: datetime
    kpis: KPIBlock
    alerts_by_day: list[SeriesPoint]
    by_severity: list[NamedCount]
    by_status: list[NamedCount]
    by_source: list[NamedCount]
    by_verdict: list[NamedCount]
    top_source_ips: list[NamedCount]
    top_rules: list[NamedCount]
    top_mitre: list[NamedCount]
    incidents_by_status: list[NamedCount]
    recent_alerts: list[AlertOut]


# ---------------------------------------------------------------------------
# Reportes
# ---------------------------------------------------------------------------
class ReportCreate(BaseModel):
    report_type: ReportType = ReportType.OPERATIONAL
    format: ReportFormat = ReportFormat.PDF
    period_start: datetime | None = None
    period_end: datetime | None = None
    days: int = Field(default=30, ge=1, le=366)


class ReportOut(ORMModel):
    id: uuid.UUID
    name: str
    report_type: ReportType
    format: ReportFormat
    period_start: datetime
    period_end: datetime
    file_name: str
    size_bytes: int
    created_at: datetime
    download_url: str | None = None
    generated_by: UserBrief | None = None


class ReportPage(BaseModel):
    items: list[ReportOut]
    total: int
    page: int
    page_size: int
    pages: int


# ---------------------------------------------------------------------------
# Auditoría
# ---------------------------------------------------------------------------
class AuditOut(ORMModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    actor_email: str
    actor_role: str
    event_type: str
    module: str
    action: str
    direction: str | None
    entity_type: str | None
    entity_id: str | None
    description: str
    method: str | None
    path: str | None
    status_code: int | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    detail: dict[str, Any] = {}
    duration_ms: int | None
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditOut]
    total: int
    page: int
    page_size: int
    pages: int


class ModuleEvent(BaseModel):
    module: str = Field(min_length=2, max_length=40)
    direction: str = Field(pattern="^(IN|OUT)$")
    detail: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Ingesta
# ---------------------------------------------------------------------------
class IngestResult(BaseModel):
    alert_id: uuid.UUID
    status: str
    duplicate: bool
    severity: Severity
    message: str
    triage: TriageResultOut | None = None


class ToolInfo(BaseModel):
    name: str
    description: str
    enabled: bool


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int
