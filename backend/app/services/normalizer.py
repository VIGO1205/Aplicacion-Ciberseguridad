"""Normalización de alertas heterogéneas (Wazuh, OPNsense, genéricas)."""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import Alert, Asset
from app.models.enums import Severity

SEVERITY_BY_LEVEL = (
    (12, Severity.CRITICAL),
    (9, Severity.HIGH),
    (6, Severity.MEDIUM),
    (3, Severity.LOW),
    (0, Severity.INFO),
)

SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "critica": Severity.CRITICAL,
    "crítica": Severity.CRITICAL,
    "high": Severity.HIGH,
    "alta": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "media": Severity.MEDIUM,
    "low": Severity.LOW,
    "baja": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "informacion": Severity.INFO,
}


def severity_from_level(level: int) -> Severity:
    for threshold, severity in SEVERITY_BY_LEVEL:
        if level >= threshold:
            return severity
    return Severity.INFO


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _first(data: dict, *keys: str, default: Any = None) -> Any:
    for key in keys:
        current: Any = data
        for part in key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                current = None
                break
        if current not in (None, ""):
            return current
    return default


def _detect_source(payload: dict, hint: str | None) -> str:
    if hint:
        return hint.lower()[:40]
    if "rule" in payload and "agent" in payload:
        return "wazuh"
    if any(key in payload for key in ("src_ip", "dest_ip", "interface", "action")):
        return "opnsense"
    if "event" in payload and "observer" in payload:
        return "opnsense"
    return "generic"


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def fingerprint_for(source: str, external_id: str | None, title: str, source_ip: str | None,
                    hostname: str | None, occurred_at: datetime, bucket_minutes: int = 5) -> str:
    """FNV-1a de 64 bits + bucket temporal.

    Se usa el mismo algoritmo en n8n (BigInt) para que ambas rutas de ingesta
    produzcan la misma huella. No es un hash criptográfico: su objetivo es la
    deduplicación, no la integridad forense.
    """
    bucket = int(occurred_at.timestamp() // (bucket_minutes * 60))
    material = "|".join(
        [source, external_id or "", title.strip().lower(), source_ip or "", hostname or "", str(bucket)]
    )
    value = 1469598103934665603
    for char in material:
        value ^= ord(char)
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}-{bucket:x}"


def normalize_payload(payload: dict[str, Any], source_hint: str | None = None) -> dict[str, Any]:
    """Convierte un evento crudo en el contrato interno de alerta."""
    source = _detect_source(payload, source_hint)
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}

    raw_level = _first(
        payload,
        "rule.level",
        "rule_level",
        "level",
        "severity_level",
        default=rule.get("level", 5),
    )
    try:
        level = max(0, min(15, int(raw_level)))
    except (TypeError, ValueError):
        level = 5

    explicit = _first(payload, "severity", "priority", "risk_level", default=None)
    if isinstance(explicit, str) and explicit.lower() in SEVERITY_ALIASES:
        severity = SEVERITY_ALIASES[explicit.lower()]
    elif isinstance(explicit, int):
        severity = severity_from_level(explicit)
    else:
        severity = severity_from_level(level)

    title = str(
        _first(
            payload,
            "rule.description",
            "title",
            "event",
            "message",
            "description",
            default="Alerta de seguridad sin título",
        )
    )[:300]
    description = str(
        _first(
            payload,
            "full_log",
            "description",
            "message",
            "details",
            default="",
        )
        or ""
    )[:8000]

    source_ip = _first(
        payload, "data.srcip", "src_ip", "source_ip", "data.src_ip", "client_ip", default=None
    )
    destination_ip = _first(
        payload, "data.dstip", "dest_ip", "destination_ip", "data.dst_ip", "server_ip", default=None
    )
    hostname = _first(
        payload, "agent.name", "hostname", "observer.hostname", "host", default=None
    )
    username = _first(payload, "data.dstuser", "data.srcuser", "username", "user", default=None)
    external_id = _first(payload, "id", "event_id", "alert_id", "uuid", default=None)
    occurred_at = parse_timestamp(
        _first(payload, "timestamp", "@timestamp", "event_time", "date", default=None)
    )

    fingerprint = fingerprint_for(
        source,
        str(external_id) if external_id else None,
        title,
        str(source_ip) if source_ip else None,
        str(hostname) if hostname else None,
        occurred_at,
    )

    mitre = payload.get("mitre") or rule.get("mitre") or []
    techniques: list[str] = []
    if isinstance(mitre, dict):
        ids = mitre.get("id") or []
        techniques = [str(item) for item in ids] if isinstance(ids, list) else [str(ids)]
    elif isinstance(mitre, list):
        techniques = [str(item) for item in mitre if item]

    tags: list[str] = [source]
    if rule.get("id"):
        tags.append(f"rule:{rule['id']}")
    if isinstance(payload.get("tags"), list):
        tags.extend(str(tag) for tag in payload["tags"][:10])

    return {
        "external_id": str(external_id)[:180] if external_id else None,
        "fingerprint": fingerprint,
        "source": source,
        "title": title,
        "description": description,
        "rule_id": str(rule.get("id") or _first(payload, "rule_id", default=""))[:40] or None,
        "rule_level": level,
        "severity": severity,
        "source_ip": str(source_ip)[:45] if source_ip else None,
        "destination_ip": str(destination_ip)[:45] if destination_ip else None,
        "hostname": str(hostname)[:150] if hostname else None,
        "agent_name": str(agent.get("name") or hostname or "")[:150] or None,
        "username": str(username)[:150] if username else None,
        "mitre_techniques": techniques,
        "tags": tags,
        "raw_payload": payload,
        "received_at": occurred_at,
        "first_seen_at": occurred_at,
        "last_seen_at": occurred_at,
    }


def find_asset(db: Session, hostname: str | None, source_ip: str | None,
               destination_ip: str | None) -> Asset | None:
    conditions = []
    if hostname:
        conditions.append(Asset.hostname == hostname)
        conditions.append(Asset.ip_address == hostname)
    for ip in (source_ip, destination_ip):
        if ip:
            conditions.append(Asset.ip_address == ip)
    if not conditions:
        return None
    return db.scalar(select(Asset).where(or_(*conditions)).limit(1))


def ingest_alert(
    db: Session,
    payload: dict[str, Any],
    *,
    source_hint: str | None = None,
    asset: Asset | None = None,
) -> tuple[Alert, bool]:
    """Crea la alerta si no existe. Devuelve (alerta, es_duplicada)."""
    data = normalize_payload(payload, source_hint)
    existing = db.scalar(select(Alert).where(Alert.fingerprint == data["fingerprint"]))
    if existing:
        current = existing.last_seen_at
        candidate = data["last_seen_at"]
        if current.tzinfo is None and candidate.tzinfo is not None:
            current = current.replace(tzinfo=timezone.utc)
        elif current.tzinfo is not None and candidate.tzinfo is None:
            candidate = candidate.replace(tzinfo=timezone.utc)
        existing.last_seen_at = max(current, candidate)
        db.commit()
        return existing, True

    if asset is None:
        asset = find_asset(db, data["hostname"], data["source_ip"], data["destination_ip"])
    alert = Alert(**data, asset_id=asset.id if asset else None)
    db.add(alert)
    try:
        db.commit()
    except Exception:
        db.rollback()
        existing = db.scalar(select(Alert).where(Alert.fingerprint == data["fingerprint"]))
        if existing:
            return existing, True
        raise
    db.refresh(alert)
    return alert, False


def manual_alert_values(data: dict[str, Any]) -> dict[str, Any]:
    """Completa los campos obligatorios para alertas creadas desde el dashboard."""
    received_at = datetime.now(timezone.utc)
    source = str(data.get("source") or "manual")
    title = str(data["title"])
    source_ip = data.get("source_ip")
    hostname = data.get("hostname")
    fingerprint = fingerprint_for(
        source, f"manual-{uuid.uuid4().hex}", title, source_ip, hostname, received_at
    )
    return {
        **data,
        "fingerprint": fingerprint,
        "received_at": received_at,
        "first_seen_at": received_at,
        "last_seen_at": received_at,
        "tags": data.get("tags") or ["manual"],
        "mitre_techniques": data.get("mitre_techniques") or [],
        "raw_payload": data.get("raw_payload") or {"origen": "dashboard"},
    }


def suspicious_ip(ip: str | None) -> bool:
    """Heurística local: IP pública (no RFC1918) se considera expuesta."""
    return bool(ip) and not _is_private(ip)


def keyword_hits(text: str) -> list[str]:
    patterns = {
        "brute_force": r"brute\s*force|fuerza\s*bruta|failed\s*password|autenticaci[oó]n fallida",
        "malware": r"malware|trojan|virus|ransomware|backdoor|rootkit",
        "exploit": r"exploit|sql\s*injection|rce|buffer\s*overflow|shellcode",
        "scan": r"scan|escaneo|port\s*sweep|nmap",
        "phishing": r"phishing|correo\s+sospechoso|credential\s+harvest",
        "c2": r"command\s*and\s*control|c2|beacon|reverse\s*shell",
        "lateral": r"lateral\s*movement|movimiento\s*lateral|psexec|wmic",
        "test": r"\btest\b|prueba|demo|monitor|heartbeat|health\s*check",
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, text, re.IGNORECASE)]
