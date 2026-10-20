"""Herramientas de enriquecimiento expuestas como LangChain StructuredTools.

El agente no depende del function-calling del modelo: un planificador determinista
invoca las herramientas y entrega el contexto al LLM. Esto permite usar modelos
locales pequeños y mantiene el triaje reproducible y auditable.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import httpx
from langchain_core.tools import StructuredTool

from app.settings import settings

logger = logging.getLogger(__name__)

MITRE_KEYWORDS = {
    "T1110": r"brute\s*force|fuerza\s*bruta|failed\s*password|autenticaci[oó]n fallida",
    "T1190": r"sql\s*injection|exploit|rce|buffer\s*overflow|shellcode",
    "T1059": r"powershell|cmd\.exe|bash|command\s*execution|ejecuci[oó]n de comandos",
    "T1486": r"ransomware|cifrado|encrypted|\.locked",
    "T1071": r"command\s*and\s*control|c2|beacon|reverse\s*shell",
    "T1046": r"scan|escaneo|port\s*sweep|nmap",
    "T1566": r"phishing|correo\s+sospechoso|credential\s+harvest",
    "T1204": r"macro|adjunto|attachment|ejecuci[oó]n del usuario",
    "T1021": r"lateral|psexec|smb|rdp|wmic",
    "T1078": r"valid\s*account|credencial|login|inicio de sesi[oó]n",
    "T1041": r"exfiltr|saliente|outbound",
    "T1105": r"download|descarga|certutil|bitsadmin",
    "T1565": r"integrity|integridad|fim",
    "T1568": r"dns|dynamic\s*resolution|domain\s*generation",
}

ASSET_INVENTORY = {
    "srv-dc01": {"criticality": "critical", "environment": "produccion", "owner": "Infraestructura"},
    "srv-db01": {"criticality": "critical", "environment": "produccion", "owner": "DBA"},
    "srv-web01": {"criticality": "high", "environment": "dmz", "owner": "Aplicaciones"},
    "srv-app01": {"criticality": "high", "environment": "dmz", "owner": "Aplicaciones"},
    "fw-edge01": {"criticality": "critical", "environment": "perimetro", "owner": "Redes"},
    "vpn-gw01": {"criticality": "high", "environment": "perimetro", "owner": "Redes"},
    "srv-backup01": {"criticality": "high", "environment": "produccion", "owner": "Infraestructura"},
    "srv-mail01": {"criticality": "high", "environment": "dmz", "owner": "Mesa de ayuda"},
    "k8s-prod-01": {"criticality": "high", "environment": "produccion", "owner": "Plataforma"},
    "ws-fin-014": {"criticality": "medium", "environment": "corporativo", "owner": "Finanzas"},
    "ws-rrhh-07": {"criticality": "low", "environment": "corporativo", "owner": "RRHH"},
    "ws-dev-03": {"criticality": "low", "environment": "desarrollo", "owner": "Desarrollo"},
}


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _is_public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
    except ValueError:
        return False


def _virustotal(ip: str) -> str:
    if not settings.virustotal_api_key:
        return _json({"status": "disabled", "summary": "VirusTotal no configurado"})
    if not _is_public_ip(ip):
        return _json({"status": "skipped", "summary": "IP privada: no se consulta VirusTotal"})
    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=settings.http_timeout_seconds,
        )
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value) for value in stats.values() if isinstance(value, (int, float)))
        risk = min(100.0, malicious * 8 + suspicious * 3)
        return _json(
            {
                "status": "ok",
                "risk_score": risk,
                "summary": f"{malicious} motores maliciosos y {suspicious} sospechosos de {total}.",
                "payload": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": int(stats.get("harmless", 0)),
                    "country": attributes.get("country"),
                    "as_owner": attributes.get("as_owner"),
                },
            }
        )
    except Exception as exc:
        logger.warning("VirusTotal falló para %s: %s", ip, exc)
        return _json({"status": "error", "summary": f"No se pudo consultar VirusTotal: {exc}"})


def _abuseipdb(ip: str) -> str:
    if not settings.abuseipdb_api_key:
        return _json({"status": "disabled", "summary": "AbuseIPDB no configurado"})
    if not _is_public_ip(ip):
        return _json({"status": "skipped", "summary": "IP privada: no se consulta AbuseIPDB"})
    try:
        response = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=settings.http_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = float(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        return _json(
            {
                "status": "ok",
                "risk_score": score,
                "summary": f"Confianza de abuso {score:.0f}% con {reports} reportes en 90 días.",
                "payload": {
                    "abuse_confidence": score,
                    "reports": reports,
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                },
            }
        )
    except Exception as exc:
        logger.warning("AbuseIPDB falló para %s: %s", ip, exc)
        return _json({"status": "error", "summary": f"No se pudo consultar AbuseIPDB: {exc}"})


def _geoip(ip: str) -> str:
    if not settings.geoip_enabled:
        return _json({"status": "disabled", "summary": "GeoIP deshabilitado"})
    if not _is_public_ip(ip):
        return _json(
            {
                "status": "ok",
                "risk_score": 0,
                "summary": "IP privada / RFC1918",
                "payload": {"country": "Interno", "proxy": False, "hosting": False},
            }
        )
    try:
        response = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query"},
            timeout=settings.http_timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        risk = 20.0 if data.get("proxy") or data.get("hosting") else 0.0
        return _json(
            {
                "status": "ok" if data.get("status") == "success" else "error",
                "risk_score": risk,
                "summary": f"{data.get('city', '')} {data.get('country', '')} · {data.get('isp', '')}".strip(),
                "payload": {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "proxy": data.get("proxy"),
                    "hosting": data.get("hosting"),
                },
            }
        )
    except Exception as exc:
        logger.warning("GeoIP falló para %s: %s", ip, exc)
        return _json({"status": "error", "summary": f"No se pudo consultar GeoIP: {exc}"})


def _mitre_lookup(text: str) -> str:
    import re

    matches: list[dict[str, str]] = []
    for technique, pattern in MITRE_KEYWORDS.items():
        if re.search(pattern, text, re.IGNORECASE):
            matches.append({"id": technique, "evidence": pattern})
    return _json({"techniques": matches})


def _asset_lookup(hostname: str) -> str:
    asset = ASSET_INVENTORY.get(hostname)
    if not asset:
        return _json({"found": False, "hostname": hostname, "context": "Activo no inventariado"})
    return _json({"found": True, "hostname": hostname, **asset})


virustotal_tool = StructuredTool.from_function(
    func=_virustotal,
    name="virustotal_ip",
    description="Consulta la reputación de una IP pública en VirusTotal. Devuelve JSON con risk_score.",
)
abuseipdb_tool = StructuredTool.from_function(
    func=_abuseipdb,
    name="abuseipdb_ip",
    description="Consulta la confianza de abuso de una IP en AbuseIPDB. Devuelve JSON con risk_score.",
)
geoip_tool = StructuredTool.from_function(
    func=_geoip,
    name="geoip_ip",
    description="Obtiene país, ciudad, ISP y si la IP es proxy/hosting. Devuelve JSON.",
)
mitre_tool = StructuredTool.from_function(
    func=_mitre_lookup,
    name="mitre_attack_lookup",
    description="Mapea el texto de la alerta a técnicas MITRE ATT&CK locales.",
)
asset_tool = StructuredTool.from_function(
    func=_asset_lookup,
    name="asset_context",
    description="Consulta criticidad, entorno y propietario de un activo del inventario.",
)

TOOLS = {
    tool.name: tool
    for tool in (virustotal_tool, abuseipdb_tool, geoip_tool, mitre_tool, asset_tool)
}


def tool_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": "virustotal_ip",
            "description": virustotal_tool.description,
            "enabled": bool(settings.virustotal_api_key),
        },
        {
            "name": "abuseipdb_ip",
            "description": abuseipdb_tool.description,
            "enabled": bool(settings.abuseipdb_api_key),
        },
        {
            "name": "geoip_ip",
            "description": geoip_tool.description,
            "enabled": settings.geoip_enabled,
        },
        {"name": "mitre_attack_lookup", "description": mitre_tool.description, "enabled": True},
        {"name": "asset_context", "description": asset_tool.description, "enabled": True},
    ]


def _safe_invoke(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = TOOLS[name].invoke(arguments)
        return json.loads(result) if isinstance(result, str) else result
    except Exception as exc:  # pragma: no cover - defensivo
        logger.exception("Herramienta %s falló", name)
        return {"status": "error", "summary": str(exc)}


def enrich_ip(ip: str | None) -> list[dict[str, Any]]:
    if not ip or not _is_public_ip(ip):
        return []
    tasks = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        if settings.virustotal_api_key:
            tasks[executor.submit(_safe_invoke, "virustotal_ip", {"ip": ip})] = "VirusTotal"
        if settings.abuseipdb_api_key:
            tasks[executor.submit(_safe_invoke, "abuseipdb_ip", {"ip": ip})] = "AbuseIPDB"
        if settings.geoip_enabled:
            tasks[executor.submit(_safe_invoke, "geoip_ip", {"ip": ip})] = "GeoIP"

        items: list[dict[str, Any]] = []
        for future in as_completed(tasks):
            provider = tasks[future]
            result = future.result()
            if result.get("status") in {"disabled", "skipped"}:
                continue
            items.append(
                {
                    "provider": provider,
                    "indicator": ip,
                    "indicator_type": "ip",
                    "status": result.get("status", "ok"),
                    "risk_score": result.get("risk_score"),
                    "summary": result.get("summary", ""),
                    "payload": result.get("payload", {}),
                }
            )
    return items


def lookup_mitre(text: str) -> tuple[list[str], dict[str, Any]]:
    result = _safe_invoke("mitre_attack_lookup", {"text": text})
    return [item["id"] for item in result.get("techniques", [])], result


def lookup_asset(hostname: str | None) -> dict[str, Any]:
    if not hostname:
        return {"found": False, "context": "Sin hostname"}
    return _safe_invoke("asset_context", {"hostname": hostname})
