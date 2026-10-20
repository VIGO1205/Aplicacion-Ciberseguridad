"""Contratos del microservicio de triaje."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Verdict = Literal["true_positive", "false_positive", "suspicious", "benign"]
RoutingTeam = Literal["soc_l1", "soc_l2", "infrastructure", "soc_lead"]


class AssetContext(BaseModel):
    hostname: str | None = None
    criticality: str | None = None
    environment: str | None = None
    owner: str | None = None


class SimilarIncident(BaseModel):
    code: str | None = None
    title: str
    verdict: str | None = None
    summary: str | None = None


class TriageRequest(BaseModel):
    alert_id: str | None = None
    external_id: str | None = None
    source: str = "generic"
    title: str
    description: str = ""
    rule_id: str | None = None
    rule_level: int = Field(default=0, ge=0, le=15)
    severity: Severity = "medium"
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    agent_name: str | None = None
    username: str | None = None
    mitre_techniques: list[str] = []
    tags: list[str] = []
    asset: AssetContext | None = None
    received_at: str | None = None
    similar_incidents: list[SimilarIncident] = []
    raw_payload: dict[str, Any] = {}


class TriageAction(BaseModel):
    priority: int = Field(default=1, ge=1, le=10)
    action: str
    owner: str = "SOC L1"
    sla_minutes: int = Field(default=60, ge=1, le=10080)
    type: str = "validation"


class EnrichmentItem(BaseModel):
    provider: str
    indicator: str
    indicator_type: str = "ip"
    status: str = "ok"
    risk_score: float | None = None
    summary: str = ""
    payload: dict[str, Any] = {}


class TriageResponse(BaseModel):
    verdict: Verdict
    recommended_severity: Severity
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    routing_team: RoutingTeam
    summary: str
    reasoning: str
    recommended_actions: list[TriageAction] = []
    mitre_techniques: list[str] = []
    should_escalate: bool = False
    false_positive_reason: str | None = None
    engine: str
    model_name: str
    prompt_version: str
    latency_ms: int
    tokens_used: int = 0
    enrichment: list[EnrichmentItem] = []


class LLMDecision(BaseModel):
    verdict: Verdict
    recommended_severity: Severity
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    routing_team: RoutingTeam
    summary: str
    reasoning: str = ""
    recommended_actions: list[TriageAction | str] = []
    mitre_techniques: list[str] = []
    should_escalate: bool = False
    false_positive_reason: str | None = None
