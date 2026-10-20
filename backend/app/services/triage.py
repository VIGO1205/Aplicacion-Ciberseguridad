"""Orquestación del triaje: microservicio LangChain + fallback heurístico local."""
from __future__ import annotations

import json
import logging
import time
from datetime import timezone
from typing import Any

import httpx
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Alert, EnrichmentData, Incident, TriageResult
from app.models.enums import AlertStatus, IncidentStatus, Severity, Verdict
from app.schemas import TriageResultIn
from app.services.normalizer import keyword_hits, suspicious_ip

logger = logging.getLogger(__name__)

SEVERITY_SCORE = {
    Severity.CRITICAL: 62,
    Severity.HIGH: 50,
    Severity.MEDIUM: 32,
    Severity.LOW: 15,
    Severity.INFO: 5,
}

KEYWORD_SCORE = {
    "brute_force": 12,
    "malware": 20,
    "exploit": 18,
    "scan": 5,
    "phishing": 14,
    "c2": 20,
    "lateral": 15,
    "test": -25,
}

KEYWORD_MITRE = {
    "brute_force": ["T1110"],
    "malware": ["T1204", "T1486"],
    "exploit": ["T1190"],
    "scan": ["T1046"],
    "phishing": ["T1566"],
    "c2": ["T1071"],
    "lateral": ["T1021"],
}


class TriageUnavailable(RuntimeError):
    pass


def _severity_for_score(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 68:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 25:
        return Severity.LOW
    return Severity.INFO


def _asset_dict(alert: Alert) -> dict[str, Any] | None:
    if not alert.asset:
        return None
    return {
        "hostname": alert.asset.hostname,
        "criticality": alert.asset.criticality.value,
        "environment": alert.asset.environment,
        "owner": alert.asset.owner,
    }


def alert_to_payload(alert: Alert, similar_incidents: list[dict] | None = None) -> dict[str, Any]:
    return {
        "alert_id": str(alert.id),
        "external_id": alert.external_id,
        "source": alert.source,
        "title": alert.title,
        "description": alert.description,
        "rule_id": alert.rule_id,
        "rule_level": alert.rule_level,
        "severity": alert.severity.value,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "hostname": alert.hostname,
        "agent_name": alert.agent_name,
        "username": alert.username,
        "mitre_techniques": alert.mitre_techniques or [],
        "asset": _asset_dict(alert),
        "received_at": alert.received_at.isoformat(),
        "tags": alert.tags or [],
        "similar_incidents": similar_incidents or [],
        "raw_payload": alert.raw_payload or {},
    }


def heuristic_triage(alert: Alert, similar_incidents: list[dict] | None = None) -> dict[str, Any]:
    """Motor determinista, sin LLM ni APIs externas.

    Se usa como fallback cuando Ollama/microservicio no están disponibles. Es
    explicable y auditable: cada punto del riesgo tiene una razón asociada.
    """
    started = time.perf_counter()
    text = f"{alert.title} {alert.description}".lower()
    hits = keyword_hits(text)
    score = SEVERITY_SCORE.get(alert.severity, 30) + min(18, alert.rule_level * 0.8)
    reasons: list[str] = [
        f"Severidad de origen {alert.severity.value} (regla nivel {alert.rule_level})."
    ]

    for hit in hits:
        score += KEYWORD_SCORE[hit]
        if hit != "test":
            reasons.append(f"Patrón identificado: {hit.replace('_', ' ')}.")
        else:
            reasons.append("El texto contiene indicios de prueba/monitorización.")

    if alert.asset:
        bonus = {"critical": 15, "high": 8, "medium": 3, "low": 0}.get(
            alert.asset.criticality.value, 0
        )
        score += bonus
        if bonus:
            reasons.append(
                f"Activo {alert.asset.hostname} con criticidad {alert.asset.criticality.value} (+{bonus})."
            )
    else:
        reasons.append("Activo no inventariado: se aplica prudencia (+2).")
        score += 2

    if suspicious_ip(alert.source_ip):
        score += 4
        reasons.append(f"IP origen pública expuesta: {alert.source_ip} (+4).")
    elif alert.source_ip:
        score -= 3
        reasons.append(f"IP origen privada {alert.source_ip} (-3).")

    if alert.username and alert.username.lower() in {"root", "administrator", "admin"}:
        score += 4
        reasons.append("La cuenta afectada es privilegiada (+4).")

    if similar_incidents:
        reasons.append(f"Se consideran {len(similar_incidents)} incidentes históricos similares.")

    score = max(0, min(100, int(round(score))))

    false_positive = False
    fp_reason: str | None = None
    if "test" in hits and score < 65:
        false_positive = True
        fp_reason = "Patrón de prueba/monitorización y riesgo contenido."
    elif (
        alert.rule_level <= 3
        and not (set(hits) - {"test", "scan"})
        and not suspicious_ip(alert.source_ip)
    ):
        false_positive = True
        fp_reason = "Regla de baja severidad, origen interno y sin indicadores maliciosos."

    if false_positive:
        verdict = Verdict.FALSE_POSITIVE
    elif score >= 68:
        verdict = Verdict.TRUE_POSITIVE
    elif score >= 45:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN

    recommended = _severity_for_score(score)
    confidence = round(min(0.94, 0.58 + abs(score - 45) / 180), 2)
    if false_positive:
        confidence = max(confidence, 0.78)

    mitre = list(dict.fromkeys((alert.mitre_techniques or [])))
    for hit in hits:
        mitre.extend(KEYWORD_MITRE.get(hit, []))
    mitre = list(dict.fromkeys(mitre))[:8]

    host = alert.hostname or alert.agent_name or "activo no inventariado"
    summary = (
        f"Alerta {alert.severity.value} de {alert.source} sobre {host}. "
        f"El motor determinista asigna un riesgo de {score}/100 y un veredicto "
        f"{verdict.value.replace('_', ' ')}. "
        f"Regla: {alert.title}."
    )
    if alert.source_ip:
        summary += f" Origen: {alert.source_ip}."
    if false_positive:
        summary += f" Posible falso positivo: {fp_reason}"

    if verdict == Verdict.TRUE_POSITIVE and recommended in {Severity.CRITICAL, Severity.HIGH}:
        actions = [
            {
                "priority": 1,
                "action": f"Aislar {host} de la red y preservar evidencia volátil.",
                "owner": "SOC L2 / Infraestructura",
                "sla_minutes": 15,
                "type": "containment",
            },
            {
                "priority": 2,
                "action": f"Bloquear la IP {alert.source_ip} en firewall/perímetro."
                if alert.source_ip
                else "Revisar reglas de firewall y segmentación del activo.",
                "owner": "Infraestructura",
                "sla_minutes": 20,
                "type": "containment",
            },
            {
                "priority": 3,
                "action": "Recolectar logs del host, procesos y conexiones de red.",
                "owner": "SOC L2",
                "sla_minutes": 30,
                "type": "evidence",
            },
            {
                "priority": 4,
                "action": "Abrir incidente, asignar responsable y notificar según el plan de respuesta.",
                "owner": "SOC Lead",
                "sla_minutes": 30,
                "type": "escalation",
            },
        ]
    elif verdict in {Verdict.TRUE_POSITIVE, Verdict.SUSPICIOUS}:
        actions = [
            {
                "priority": 1,
                "action": "Validar la alerta contra logs del EDR, firewall y autenticación.",
                "owner": "SOC L1",
                "sla_minutes": 30,
                "type": "validation",
            },
            {
                "priority": 2,
                "action": "Consultar reputación de IP/dominio y contexto del activo.",
                "owner": "SOC L1",
                "sla_minutes": 30,
                "type": "enrichment",
            },
            {
                "priority": 3,
                "action": "Si se confirma actividad maliciosa, aislar y escalar a L2.",
                "owner": "SOC L1 / L2",
                "sla_minutes": 60,
                "type": "escalation",
            },
        ]
    else:
        actions = [
            {
                "priority": 1,
                "action": "Documentar el análisis y cerrar como falso positivo si se confirma.",
                "owner": "SOC L1",
                "sla_minutes": 60,
                "type": "closure",
            },
            {
                "priority": 2,
                "action": "Ajustar umbral/excepción de la regla para reducir ruido futuro.",
                "owner": "Ingeniería SOC",
                "sla_minutes": 240,
                "type": "tuning",
            },
        ]

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "verdict": verdict.value,
        "recommended_severity": recommended.value,
        "confidence": confidence,
        "risk_score": score,
        "summary": summary,
        "reasoning": " ".join(reasons),
        "recommended_actions": actions,
        "mitre_techniques": mitre,
        "should_escalate": recommended in {Severity.CRITICAL, Severity.HIGH}
        and verdict != Verdict.FALSE_POSITIVE,
        "false_positive_reason": fp_reason,
        "engine": "heuristic-local",
        "model_name": "soc-lite-rules-v1",
        "prompt_version": "heuristic-v1",
        "latency_ms": elapsed_ms,
        "tokens_used": 0,
        "enrichment": [],
        "raw_response": {},
    }


def _remote_triage(alert: Alert, similar_incidents: list[dict] | None = None) -> dict[str, Any]:
    url = f"{settings.triage_service_url.rstrip('/')}/triage"
    headers = {"X-Internal-Key": settings.triage_api_key} if settings.triage_api_key else {}
    try:
        with httpx.Client(timeout=settings.triage_timeout_seconds) as client:
            response = client.post(
                url, json=alert_to_payload(alert, similar_incidents), headers=headers
            )
            response.raise_for_status()
            body = response.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise TriageUnavailable(f"Microservicio de triaje no disponible: {exc}") from exc
    if not isinstance(body, dict):
        raise TriageUnavailable("Respuesta inválida del microservicio de triaje")
    return body


def _coerce_result(payload: dict[str, Any]) -> TriageResultIn:
    data = dict(payload)
    data.setdefault("engine", "langchain")
    data.setdefault("prompt_version", "v1")
    data.setdefault("model_name", "")
    data.setdefault("latency_ms", 0)
    data.setdefault("tokens_used", 0)
    data.setdefault("enrichment", [])
    try:
        return TriageResultIn.model_validate(data)
    except ValidationError as exc:
        raise TriageUnavailable(f"Triaje con formato inválido: {exc.errors()[:2]}") from exc


def run_triage(
    alert: Alert, similar_incidents: list[dict] | None = None
) -> tuple[TriageResultIn, dict[str, Any]]:
    """Ejecuta el motor remoto o el fallback y devuelve (resultado, crudo)."""
    mode = settings.triage_mode.lower()
    if mode != "heuristic":
        try:
            raw = _remote_triage(alert, similar_incidents)
            return _coerce_result(raw), raw
        except TriageUnavailable:
            if mode == "remote":
                raise
            logger.warning("Triaje remoto no disponible; se usa el motor heurístico local.")

    raw = heuristic_triage(alert, similar_incidents)
    return _coerce_result(raw), raw


def _enrichment_rows(alert_id, items: list[dict[str, Any]]) -> list[EnrichmentData]:
    rows: list[EnrichmentData] = []
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider") or "desconocido")[:40]
        indicator = str(item.get("indicator") or alert_id)[:190]
        rows.append(
            EnrichmentData(
                alert_id=alert_id,
                provider=provider,
                indicator=indicator,
                indicator_type=str(item.get("indicator_type") or "ip")[:30],
                status=str(item.get("status") or "ok")[:30],
                risk_score=float(item["risk_score"]) if item.get("risk_score") is not None else None,
                summary=str(item.get("summary") or "")[:500],
                payload=item.get("payload") if isinstance(item.get("payload"), dict) else {},
            )
        )
    return rows


def persist_triage(
    db: Session,
    alert: Alert,
    result: TriageResultIn,
    *,
    raw_response: dict[str, Any] | None = None,
) -> TriageResult:
    triage = alert.triage_result
    if triage is None:
        triage = TriageResult(alert_id=alert.id)
        db.add(triage)

    triage.verdict = result.verdict
    triage.recommended_severity = result.recommended_severity
    triage.confidence = result.confidence
    triage.risk_score = result.risk_score
    triage.summary = result.summary
    triage.reasoning = result.reasoning
    triage.recommended_actions = result.recommended_actions
    triage.mitre_techniques = list(dict.fromkeys(result.mitre_techniques))[:12]
    triage.should_escalate = result.should_escalate
    triage.false_positive_reason = result.false_positive_reason
    triage.engine = result.engine
    triage.model_name = result.model_name
    triage.prompt_version = result.prompt_version
    triage.latency_ms = result.latency_ms
    triage.tokens_used = result.tokens_used
    triage.raw_response = raw_response if raw_response is not None else {}

    if result.enrichment:
        db.execute(delete(EnrichmentData).where(EnrichmentData.alert_id == alert.id))
        db.add_all(_enrichment_rows(alert.id, result.enrichment))

    alert.status = AlertStatus.TRIAGED
    alert.mitre_techniques = list(
        dict.fromkeys((alert.mitre_techniques or []) + list(triage.mitre_techniques or []))
    )[:12]
    db.commit()
    db.refresh(triage)
    db.refresh(alert)
    return triage


def _similar_incidents(db: Session, alert: Alert, limit: int = 3) -> list[dict[str, Any]]:
    """Memoria operativa: incidentes cerrados del mismo nivel de severidad."""
    rows = list(
        db.scalars(
            select(Incident)
            .where(
                Incident.severity == alert.severity,
                Incident.status.in_([IncidentStatus.RESOLVED, IncidentStatus.CLOSED]),
            )
            .order_by(Incident.closed_at.desc())
            .limit(limit)
        ).all()
    )
    memory: list[dict[str, Any]] = []
    for incident in rows:
        verdict = None
        if incident.alert and incident.alert.triage_result:
            verdict = incident.alert.triage_result.verdict.value
        memory.append(
            {
                "code": incident.code,
                "title": incident.title,
                "verdict": verdict,
                "summary": incident.description[:300],
            }
        )
    return memory


def triage_alert(db: Session, alert: Alert) -> TriageResult:
    alert.status = AlertStatus.TRIAGING
    db.commit()
    similar = _similar_incidents(db, alert)
    try:
        result, raw = run_triage(alert, similar)
    except TriageUnavailable:
        alert.status = AlertStatus.PENDING
        db.commit()
        raise
    return persist_triage(db, alert, result, raw_response=raw)
