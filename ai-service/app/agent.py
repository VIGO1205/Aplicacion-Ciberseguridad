"""Agente de triaje con LLM configurable y fallback heurístico."""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage

from app.schemas import (
    AssetContext,
    EnrichmentItem,
    LLMDecision,
    TriageAction,
    TriageRequest,
    TriageResponse,
    RoutingTeam,
)
from app.settings import settings
from app.tools import (
    enrich_ip,
    lookup_asset,
    lookup_mitre,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Eres un analista senior de un Centro de Operaciones de Seguridad (SOC).
Tu tarea es triar una alerta y devolver EXCLUSIVAMENTE un objeto JSON válido, sin markdown.

Criterios:
- No inventes datos que no estén en la alerta o en el enriquecimiento.
- Diferencia entre actividad maliciosa confirmada, sospechosa, benigna y falso positivo.
- Si faltan datos, baja la confianza y propone acciones de validación.
- Prioriza protección de activos críticos y contención proporcional.
- Elige routing_team solo entre soc_l1, soc_l2, infrastructure y soc_lead.
- routing_team es una recomendación de equipo, nunca un nombre de persona.
- Las alertas críticas no deben quedar en soc_l1.
- No propongas acciones destructivas ni acceso a datos personales innecesario.
- Usa español profesional y conciso.

Esquema JSON obligatorio:
{
  "verdict": "true_positive|false_positive|suspicious|benign",
  "recommended_severity": "critical|high|medium|low|info",
  "confidence": 0.0,
  "risk_score": 0,
  "routing_team": "soc_l1|soc_l2|infrastructure|soc_lead",
  "summary": "resumen ejecutivo de 2-3 frases",
  "reasoning": "razonamiento breve basado en evidencia",
  "recommended_actions": [
    {"priority": 1, "action": "acción concreta", "owner": "SOC L1|SOC L2|Infraestructura|SOC Lead", "sla_minutes": 30, "type": "validation|containment|evidence|escalation|closure|tuning"}
  ],
  "mitre_techniques": ["T1110"],
  "should_escalate": true,
  "false_positive_reason": null
}"""

HUMAN_PROMPT = """Analiza la siguiente alerta y su contexto. Devuelve solo el JSON.

CONTEXTO:
{context}
"""

SEVERITY_BASE = {"critical": 62, "high": 50, "medium": 32, "low": 15, "info": 5}
KEYWORDS = {
    "brute_force": (r"brute\s*force|fuerza\s*bruta|failed\s*password|autenticaci[oó]n fallida", 12),
    "malware": (r"malware|trojan|virus|ransomware|backdoor|rootkit", 20),
    "exploit": (r"exploit|sql\s*injection|rce|buffer\s*overflow|shellcode", 18),
    "scan": (r"scan|escaneo|port\s*sweep|nmap", 5),
    "phishing": (r"phishing|correo\s+sospechoso|credential\s+harvest", 14),
    "c2": (r"command\s*and\s*control|c2|beacon|reverse\s*shell", 20),
    "lateral": (r"lateral|psexec|smb|rdp|wmic", 15),
    "test": (r"\btest\b|prueba|demo|monitor|heartbeat|health\s*check", -25),
}


def _is_public_ip(ip: str | None) -> bool:
    import ipaddress

    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
    except ValueError:
        return False


def _keyword_hits(text: str) -> list[str]:
    return [name for name, (pattern, _) in KEYWORDS.items() if re.search(pattern, text, re.IGNORECASE)]


def _actions_for(severity: str, verdict: str, host: str, ip: str | None) -> list[TriageAction]:
    if verdict == "true_positive" and severity in {"critical", "high"}:
        return [
            TriageAction(priority=1, action=f"Aislar {host} de la red y preservar evidencia volátil.", owner="SOC L2 / Infraestructura", sla_minutes=15, type="containment"),
            TriageAction(priority=2, action=f"Bloquear {ip} en firewall, proxy y DNS." if ip else "Revisar reglas de firewall y segmentación.", owner="Infraestructura", sla_minutes=20, type="containment"),
            TriageAction(priority=3, action="Recolectar logs del host, procesos y conexiones de red.", owner="SOC L2", sla_minutes=30, type="evidence"),
            TriageAction(priority=4, action="Abrir incidente y notificar según el plan de respuesta.", owner="SOC Lead", sla_minutes=30, type="escalation"),
        ]
    if verdict in {"true_positive", "suspicious"}:
        return [
            TriageAction(priority=1, action="Validar la alerta contra logs de EDR, firewall y autenticación.", owner="SOC L1", sla_minutes=30, type="validation"),
            TriageAction(priority=2, action="Consultar reputación de indicadores y contexto del activo.", owner="SOC L1", sla_minutes=30, type="enrichment"),
            TriageAction(priority=3, action="Si se confirma, aislar y escalar a L2.", owner="SOC L1 / L2", sla_minutes=60, type="escalation"),
        ]
    return [
        TriageAction(priority=1, action="Documentar el análisis y cerrar como falso positivo si se confirma.", owner="SOC L1", sla_minutes=60, type="closure"),
        TriageAction(priority=2, action="Ajustar umbral o excepción de la regla para reducir ruido.", owner="Ingeniería SOC", sla_minutes=240, type="tuning"),
    ]


def _heuristic_team(request: TriageRequest, severity: str) -> RoutingTeam:
    if severity == "critical":
        return "soc_lead"
    if request.source.lower() == "opnsense" and severity == "high":
        return "infrastructure"
    if severity == "high":
        return "soc_l2"
    return "soc_l1"


def _safe_team(decision: LLMDecision, request: TriageRequest) -> RoutingTeam:
    if decision.recommended_severity == "critical" and decision.routing_team == "soc_l1":
        return "soc_lead"
    if decision.confidence < 0.6:
        return _heuristic_team(request, decision.recommended_severity)
    return decision.routing_team


def heuristic_decision(
    request: TriageRequest,
    enrichments: list[EnrichmentItem],
    asset_context: dict[str, Any],
    mitre_from_tools: list[str],
) -> LLMDecision:
    text = f"{request.title} {request.description}".lower()
    hits = _keyword_hits(text)
    score = SEVERITY_BASE.get(request.severity, 30) + min(18, request.rule_level * 0.8)
    reasons = [f"Severidad declarada {request.severity} (nivel de regla {request.rule_level})."]

    for hit in hits:
        score += KEYWORDS[hit][1]
        if hit != "test":
            reasons.append(f"Patrón «{hit.replace('_', ' ')}» identificado.")

    criticality = (request.asset.criticality if request.asset else asset_context.get("criticality")) or "medium"
    bonus = {"critical": 15, "high": 8, "medium": 3, "low": 0}.get(criticality, 3)
    score += bonus
    reasons.append(f"Criticidad del activo {criticality} (+{bonus}).")

    if _is_public_ip(request.source_ip):
        score += 4
        reasons.append("IP de origen pública (+4).")
    elif request.source_ip:
        score -= 3
        reasons.append("IP de origen privada (-3).")

    if request.username and request.username.lower() in {"root", "administrator", "admin"}:
        score += 4
        reasons.append("Cuenta privilegiada afectada (+4).")

    enrichment_risk = max([e.risk_score or 0 for e in enrichments] + [0])
    if enrichment_risk:
        score += min(18, enrichment_risk * 0.18)
        reasons.append(f"Reputación externa con riesgo {enrichment_risk:.0f}/100.")

    score = max(0, min(100, int(round(score))))
    false_positive = False
    fp_reason = None
    if "test" in hits and score < 65:
        false_positive = True
        fp_reason = "Patrón de prueba o monitorización con riesgo contenido."
    elif request.rule_level <= 3 and not (set(hits) - {"test", "scan"}) and not _is_public_ip(request.source_ip):
        false_positive = True
        fp_reason = "Regla de baja severidad, origen interno y sin indicadores maliciosos."

    if false_positive:
        verdict = "false_positive"
    elif score >= 68:
        verdict = "true_positive"
    elif score >= 45:
        verdict = "suspicious"
    else:
        verdict = "benign"

    if score >= 85:
        recommended = "critical"
    elif score >= 68:
        recommended = "high"
    elif score >= 45:
        recommended = "medium"
    elif score >= 25:
        recommended = "low"
    else:
        recommended = "info"

    confidence = round(min(0.94, 0.58 + abs(score - 45) / 180), 2)
    if false_positive:
        confidence = max(confidence, 0.78)

    mitre = list(dict.fromkeys(request.mitre_techniques + mitre_from_tools))
    host = request.hostname or request.agent_name or "activo no inventariado"
    summary = (
        f"Alerta {request.severity} de {request.source} sobre {host}. "
        f"Riesgo calculado {score}/100 con veredicto {verdict.replace('_', ' ')}. "
        f"Regla: {request.title}."
    )
    if request.source_ip:
        summary += f" Origen: {request.source_ip}."
    if false_positive:
        summary += f" Posible falso positivo: {fp_reason}"

    return LLMDecision(
        verdict=verdict,
        recommended_severity=recommended,
        confidence=confidence,
        risk_score=score,
        routing_team=_heuristic_team(request, recommended),
        summary=summary,
        reasoning=" ".join(reasons),
        recommended_actions=_actions_for(recommended, verdict, host, request.source_ip),
        mitre_techniques=mitre[:10],
        should_escalate=verdict == "true_positive" and recommended in {"critical", "high"},
        false_positive_reason=fp_reason,
    )


def _build_context(
    request: TriageRequest,
    enrichments: list[EnrichmentItem],
    asset_context: dict[str, Any],
    mitre_from_tools: list[str],
) -> str:
    payload = request.model_dump()
    payload["description"] = payload.get("description", "")[: settings.max_description_chars]
    payload["raw_payload"] = {"omitido": "payload crudo no enviado al LLM"}
    return json.dumps(
        {
            "alerta": payload,
            "enriquecimiento": [item.model_dump() for item in enrichments],
            "activo": asset_context,
            "mitre_sugerido": mitre_from_tools,
        },
        ensure_ascii=False,
        default=str,
    )


def _get_llm():
    provider = settings.llm_provider.lower()
    if provider == "groq":
        from langchain_openai import ChatOpenAI

        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY no configurada")
        return (
            ChatOpenAI(
                model=settings.groq_model,
                temperature=0.1,
                api_key=settings.groq_api_key,
                base_url="https://api.groq.com/openai/v1",
                max_tokens=1200,
                timeout=30,
                max_retries=1,
            ),
            "groq",
            settings.groq_model,
        )
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        kwargs: dict[str, Any] = {
            "model": settings.openai_model,
            "temperature": 0.1,
            "api_key": settings.openai_api_key,
            "max_tokens": 1200,
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        return ChatOpenAI(**kwargs), "openai", settings.openai_model

    if provider in {"auto", "ollama"}:
        from langchain_ollama import ChatOllama

        return (
            ChatOllama(
                base_url=settings.ollama_base_url,
                model=settings.ollama_model,
                temperature=0.1,
                format="json",
                num_predict=1200,
            ),
            "ollama",
            settings.ollama_model,
        )
    return None, "heuristic", "soc-lite-rules-v1"


def _extract_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return "".join(parts)
    return str(content)


def _parse_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        cleaned = cleaned[start : end + 1]
    return json.loads(cleaned)


def _usage_tokens(message: Any) -> int:
    usage = getattr(message, "usage_metadata", None) or {}
    if isinstance(usage, dict):
        return int(usage.get("input_tokens", 0) or 0) + int(usage.get("output_tokens", 0) or 0)
    return 0


def _llm_decision(
    request: TriageRequest,
    enrichments: list[EnrichmentItem],
    asset_context: dict[str, Any],
    mitre_from_tools: list[str],
) -> tuple[LLMDecision, str, str, int, int]:
    llm, engine, model_name = _get_llm()
    if llm is None:
        raise RuntimeError("Proveedor LLM deshabilitado")
    prompt = ChatPromptTemplate.from_messages(
        [SystemMessage(content=SYSTEM_PROMPT), ("human", HUMAN_PROMPT)]
    )
    chain = prompt | llm
    context = _build_context(request, enrichments, asset_context, mitre_from_tools)
    started = time.perf_counter()
    message = chain.invoke({"context": context})
    latency_ms = int((time.perf_counter() - started) * 1000)
    raw = _extract_text(message)
    data = _parse_json(raw)
    decision = LLMDecision.model_validate(data)

    # Normalizar acciones que el modelo pueda devolver como texto.
    normalized_actions: list[TriageAction] = []
    for index, item in enumerate(decision.recommended_actions[:6], start=1):
        if isinstance(item, str):
            normalized_actions.append(TriageAction(priority=index, action=item))
        else:
            normalized_actions.append(item)
    decision.recommended_actions = normalized_actions
    decision.mitre_techniques = list(dict.fromkeys(decision.mitre_techniques + mitre_from_tools))[:10]
    return decision, engine, model_name, latency_ms, _usage_tokens(message)


def triage(request: TriageRequest) -> TriageResponse:
    started = time.perf_counter()
    enrichments: list[EnrichmentItem] = []
    if settings.enrichment_enabled:
        enrichments = [EnrichmentItem.model_validate(item) for item in enrich_ip(request.source_ip)]

    asset_context = lookup_asset(request.hostname)
    if request.asset:
        asset_context = {**asset_context, **request.asset.model_dump(exclude_none=True)}
    elif not asset_context.get("found"):
        asset_context = {
            "found": False,
            "hostname": request.hostname,
            "criticality": "medium",
            "environment": "desconocido",
            "context": "Activo no inventariado",
        }

    text = f"{request.title} {request.description}"
    mitre_from_tools, _ = lookup_mitre(text)

    provider = settings.llm_provider.lower()
    engine = "heuristic-local"
    model_name = "soc-lite-rules-v1"
    tokens = 0
    raw_decision: dict[str, Any] | None = None

    if provider != "heuristic":
        try:
            decision, engine, model_name, _, tokens = _llm_decision(
                request, enrichments, asset_context, mitre_from_tools
            )
            raw_decision = decision.model_dump()
        except Exception as exc:
            logger.warning("LLM no disponible (%s); se usa fallback heurístico", exc)
            decision = heuristic_decision(request, enrichments, asset_context, mitre_from_tools)
            engine = "heuristic-fallback"
            model_name = "soc-lite-rules-v1"
    else:
        decision = heuristic_decision(request, enrichments, asset_context, mitre_from_tools)

    if raw_decision is None and engine == "heuristic-local":
        raw_decision = decision.model_dump()

    latency_ms = int((time.perf_counter() - started) * 1000)
    return TriageResponse(
        verdict=decision.verdict,
        recommended_severity=decision.recommended_severity,
        confidence=max(0.0, min(1.0, decision.confidence)),
        risk_score=max(0, min(100, decision.risk_score)),
        routing_team=_safe_team(decision, request),
        summary=decision.summary[:4000],
        reasoning=decision.reasoning[:6000],
        recommended_actions=decision.recommended_actions,
        mitre_techniques=list(dict.fromkeys(decision.mitre_techniques))[:10],
        should_escalate=decision.should_escalate,
        false_positive_reason=decision.false_positive_reason,
        engine=engine,
        model_name=model_name,
        prompt_version=settings.prompt_version,
        latency_ms=latency_ms,
        tokens_used=tokens,
        enrichment=enrichments,
    )
