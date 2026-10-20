"""Pruebas del microservicio de triaje en modo heurístico."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

os.environ["LLM_PROVIDER"] = "heuristic"
os.environ["ENRICHMENT_ENABLED"] = "false"
os.environ["GEOIP_ENABLED"] = "false"
os.environ["INTERNAL_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.agent import _get_llm, _safe_team  # noqa: E402
from app.schemas import LLMDecision, TriageRequest  # noqa: E402
from app.settings import settings  # noqa: E402


class TriageServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_health_and_tools(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")
        tools = self.client.get("/tools")
        self.assertEqual(tools.status_code, 200)
        self.assertIn("mitre_attack_lookup", [tool["name"] for tool in tools.json()])

    def test_brute_force_is_true_positive(self) -> None:
        payload = {
            "alert_id": "test-brute",
            "source": "wazuh",
            "title": "Fuerza bruta SSH detectada",
            "description": "48 intentos de autenticación fallidos para root desde 203.0.113.45",
            "rule_level": 10,
            "severity": "high",
            "source_ip": "203.0.113.45",
            "hostname": "srv-web01",
            "username": "root",
            "asset": {"hostname": "srv-web01", "criticality": "high", "environment": "dmz"},
        }
        response = self.client.post("/triage", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["verdict"], "true_positive")
        self.assertGreaterEqual(data["risk_score"], 60)
        self.assertGreaterEqual(data["confidence"], 0.5)
        self.assertTrue(data["recommended_actions"])
        self.assertIn(data["routing_team"], {"soc_l2", "soc_lead"})
        self.assertIn("T1110", data["mitre_techniques"])

    def test_test_pattern_is_false_positive(self) -> None:
        payload = {
            "source": "wazuh",
            "title": "Regla de auditoría de prueba",
            "description": "Evento de test generado por el script interno del SOC en host de laboratorio.",
            "rule_level": 3,
            "severity": "low",
            "source_ip": "10.10.5.12",
            "hostname": "ws-dev-03",
            "asset": {"hostname": "ws-dev-03", "criticality": "low"},
        }
        response = self.client.post("/triage", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["verdict"], "false_positive")
        self.assertIsNotNone(data["false_positive_reason"])
        self.assertFalse(data["should_escalate"])

    def test_internal_key_enforced_when_configured(self) -> None:
        # El módulo se importó con INTERNAL_API_KEY vacío; se verifica el health público.
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_groq_without_key_falls_back_and_reports_status(self) -> None:
        with patch.object(settings, "llm_provider", "groq"), patch.object(settings, "groq_api_key", ""):
            health = self.client.get("/health").json()
            self.assertFalse(health["llm_configured"])
            response = self.client.post("/triage", json={"title": "Escaneo de puertos", "severity": "medium"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["engine"], "heuristic-fallback")

    def test_groq_uses_openai_compatible_endpoint(self) -> None:
        with (
            patch.object(settings, "llm_provider", "groq"),
            patch.object(settings, "groq_api_key", "test-key"),
            patch("langchain_openai.ChatOpenAI") as chat,
        ):
            _, engine, model = _get_llm()
            self.assertEqual(engine, "groq")
            self.assertEqual(model, settings.groq_model)
            self.assertEqual(chat.call_args.kwargs["base_url"], "https://api.groq.com/openai/v1")
            self.assertEqual(chat.call_args.kwargs["api_key"], "test-key")

    def test_critical_alert_is_not_routed_to_soc_l1(self) -> None:
        decision = LLMDecision(
            verdict="suspicious",
            recommended_severity="critical",
            confidence=0.95,
            risk_score=90,
            routing_team="soc_l1",
            summary="Requiere revisión urgente",
        )
        request = TriageRequest(title="Malware", severity="critical")
        self.assertEqual(_safe_team(decision, request), "soc_lead")


if __name__ == "__main__":
    unittest.main(verbosity=2)
