"""Pruebas de integración de SOC-Lite (unittest, SQLite aislado).

Ejecutar:
    $env:PYTHONPATH="backend"; python -m unittest discover -s backend/tests -v
"""
from __future__ import annotations

import os
import shutil
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "storage" / "test_api.db"
REPORTS_PATH = ROOT / "storage" / "test_reports"
if DB_PATH.exists():
    DB_PATH.unlink()
if REPORTS_PATH.exists():
    shutil.rmtree(REPORTS_PATH, ignore_errors=True)
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH.as_posix()}"
os.environ["AUTO_SEED"] = "true"
os.environ["TRIAGE_MODE"] = "heuristic"
os.environ["DEMO_MODE"] = "true"
os.environ["INGEST_API_KEY"] = "test-ingest-key"
os.environ["REPORTS_DIR"] = str(REPORTS_PATH)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


class SOCLiteAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)
        cls.client.__enter__()
        response = cls.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@soclite.local", "password": "Admin2026!"},
        )
        assert response.status_code == 200, response.text
        cls.token = response.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}
        cls.refresh_token = response.json()["refresh_token"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        shutil.rmtree(REPORTS_PATH, ignore_errors=True)
        if DB_PATH.exists():
            DB_PATH.unlink()

    def test_01_health_and_catalog(self) -> None:
        self.assertEqual(self.client.get("/health").status_code, 200)
        catalog = self.client.get("/api/v1/meta/catalog")
        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(len(catalog.json()["severity"]), 5)

    def test_02_dashboard_and_alerts(self) -> None:
        dashboard = self.client.get("/api/v1/dashboard/overview?days=30", headers=self.headers)
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        kpis = dashboard.json()["kpis"]
        self.assertGreater(kpis["total_alerts"], 0)
        self.assertGreaterEqual(kpis["mttt_minutes"], 0)

        alerts = self.client.get("/api/v1/alerts?page_size=5&severity=critical", headers=self.headers)
        self.assertEqual(alerts.status_code, 200, alerts.text)
        self.assertGreater(alerts.json()["total"], 0)

        alert_id = alerts.json()["items"][0]["id"]
        detail = self.client.get(f"/api/v1/alerts/{alert_id}", headers=self.headers)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("raw_payload", detail.json())

    def test_03_triage_heuristic(self) -> None:
        alerts = self.client.get("/api/v1/alerts?status=pending&page_size=1", headers=self.headers).json()
        alert_id = alerts["items"][0]["id"]
        response = self.client.post(
            f"/api/v1/alerts/{alert_id}/triage", headers=self.headers, json={"force": True}
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn(data["verdict"], {"true_positive", "false_positive", "suspicious", "benign"})
        self.assertGreaterEqual(data["confidence"], 0)

    def test_04_viewer_and_auditor_rbac(self) -> None:
        viewer = self.client.post(
            "/api/v1/auth/login",
            json={"email": "consulta@soclite.local", "password": "Consulta2026!"},
        )
        self.assertEqual(viewer.status_code, 200, viewer.text)
        viewer_headers = {"Authorization": f"Bearer {viewer.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/v1/alerts", headers=viewer_headers).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/audit", headers=viewer_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/users", headers=viewer_headers).status_code, 403)

        auditor = self.client.post(
            "/api/v1/auth/login",
            json={"email": "auditor@soclite.local", "password": "Auditor2026!"},
        )
        auditor_headers = {"Authorization": f"Bearer {auditor.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/v1/audit", headers=auditor_headers).status_code, 200)
        alert_id = self.client.get("/api/v1/alerts?page_size=1", headers=auditor_headers).json()["items"][0]["id"]
        self.assertEqual(
            self.client.post(f"/api/v1/alerts/{alert_id}/triage", headers=auditor_headers, json={}).status_code,
            403,
        )

    def test_05_ingest_idempotent_and_auto_triage(self) -> None:
        payload = {
            "id": f"test-{uuid.uuid4().hex}",
            "timestamp": "2026-10-19T15:00:00-05:00",
            "rule": {"id": "5710", "level": 10, "description": "Fuerza bruta SSH de prueba"},
            "agent": {"name": "srv-web01"},
            "data": {"srcip": "203.0.113.200", "dstuser": "root"},
            "full_log": "48 intentos fallidos de autenticación",
        }
        headers = {"X-API-Key": "test-ingest-key"}
        first = self.client.post("/api/v1/ingest/alert?auto_triage=true", json=payload, headers=headers)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertFalse(first.json()["duplicate"])
        second = self.client.post("/api/v1/ingest/alert", json=payload, headers=headers)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertTrue(second.json()["duplicate"])
        denied = self.client.post("/api/v1/ingest/alert", json=payload, headers={"X-API-Key": "bad"})
        self.assertEqual(denied.status_code, 401)

    def test_06_reports_all_formats(self) -> None:
        for fmt, content_type in (
            ("pdf", "application/pdf"),
            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ):
            response = self.client.post(
                "/api/v1/reports",
                headers=self.headers,
                json={"report_type": "operational", "format": fmt, "days": 30},
            )
            self.assertEqual(response.status_code, 201, response.text)
            report = response.json()
            self.assertGreater(report["size_bytes"], 1000)
            download = self.client.get(report["download_url"], headers=self.headers)
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.headers["content-type"].split(";")[0], content_type)
            self.assertGreater(len(download.content), 1000)

    def test_07_audit_and_module_events(self) -> None:
        event = self.client.post(
            "/api/v1/audit/module-event",
            headers=self.headers,
            json={"module": "alerts", "direction": "IN"},
        )
        self.assertEqual(event.status_code, 200, event.text)
        audit = self.client.get("/api/v1/audit?module=alerts&page_size=5", headers=self.headers)
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertGreater(audit.json()["total"], 0)
        self.assertTrue(any(item["direction"] in {"IN", "OUT"} for item in audit.json()["items"]))

    def test_08_users_and_roles(self) -> None:
        roles = self.client.get("/api/v1/roles", headers=self.headers)
        self.assertEqual(roles.status_code, 200)
        analyst_role = next(role for role in roles.json() if role["name"] == "analyst")
        email = f"nuevo-{uuid.uuid4().hex[:8]}@soclite.local"
        created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={
                "email": email,
                "full_name": "Usuario de Prueba",
                "password": "Prueba2026!",
                "role_id": analyst_role["id"],
                "job_title": "Analista",
                "department": "SOC",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        user_id = created.json()["id"]
        reset = self.client.post(
            f"/api/v1/users/{user_id}/reset-password",
            headers=self.headers,
            json={"new_password": "Nueva2026!"},
        )
        self.assertEqual(reset.status_code, 200, reset.text)
        login = self.client.post(
            "/api/v1/auth/login", json={"email": email, "password": "Nueva2026!"}
        )
        self.assertEqual(login.status_code, 200, login.text)

    def test_09_refresh_and_logout(self) -> None:
        refreshed = self.client.post(
            "/api/v1/auth/refresh", json={"refresh_token": self.refresh_token}
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        new_token = refreshed.json()["access_token"]
        new_refresh = refreshed.json()["refresh_token"]
        logout = self.client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {new_token}"},
            json={"refresh_token": new_refresh},
        )
        self.assertEqual(logout.status_code, 200, logout.text)
        reused = self.client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
        self.assertEqual(reused.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
