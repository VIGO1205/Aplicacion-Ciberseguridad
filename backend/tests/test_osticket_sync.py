"""Transiciones del vínculo osTicket sin depender de servicios externos."""
from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models import Alert, AuditLog, OsticketTicketLink
from app.models.enums import AlertStatus, Severity
from app.services.osticket_sync import TicketSnapshot, sync_ticket


class OsticketSyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(self.engine)
        self.alert_id = uuid.uuid4()
        with Session(self.engine) as db:
            db.add(
                Alert(
                    id=self.alert_id,
                    fingerprint=uuid.uuid4().hex,
                    title="Alerta de prueba",
                    description="Caso sintético",
                    rule_level=12,
                    severity=Severity.CRITICAL,
                    status=AlertStatus.TRIAGED,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        self.engine.dispose()

    def ticket(self, state: str, *, ticket_id: int = 50) -> TicketSnapshot:
        return TicketSnapshot(
            ticket_id=ticket_id,
            number="123456",
            state=state,
            status_name="Closed" if state == "closed" else "Open",
            body=f"Alerta ID: {self.alert_id}\\nCaso de prueba",
        )

    def test_close_is_idempotent_and_reopen_restores_previous_state(self) -> None:
        with Session(self.engine) as db:
            self.assertEqual(sync_ticket(db, self.ticket("open")), "changed")
            db.commit()
            self.assertEqual(db.get(Alert, self.alert_id).status, AlertStatus.TRIAGED)

            self.assertEqual(sync_ticket(db, self.ticket("closed")), "changed")
            db.commit()
            alert = db.get(Alert, self.alert_id)
            self.assertEqual(alert.status, AlertStatus.CLOSED)
            self.assertIsNotNone(alert.closed_at)
            self.assertEqual(db.get(OsticketTicketLink, self.alert_id).ticket_number, "123456")

            audit_count = db.scalar(select(func.count()).select_from(AuditLog))
            self.assertEqual(sync_ticket(db, self.ticket("closed")), "unchanged")
            db.commit()
            self.assertEqual(db.scalar(select(func.count()).select_from(AuditLog)), audit_count)

            self.assertEqual(sync_ticket(db, self.ticket("open")), "changed")
            db.commit()
            alert = db.get(Alert, self.alert_id)
            self.assertEqual(alert.status, AlertStatus.TRIAGED)
            self.assertIsNone(alert.closed_at)

    def test_human_closed_alert_is_not_reopened(self) -> None:
        with Session(self.engine) as db:
            alert = db.get(Alert, self.alert_id)
            alert.status = AlertStatus.CLOSED
            db.commit()
            sync_ticket(db, self.ticket("closed"))
            db.commit()
            self.assertFalse(db.get(OsticketTicketLink, self.alert_id).closed_by_ticket)
            sync_ticket(db, self.ticket("open"))
            db.commit()
            self.assertEqual(db.get(Alert, self.alert_id).status, AlertStatus.CLOSED)

    def test_human_reclosure_is_not_undone_by_ticket_reopen(self) -> None:
        with Session(self.engine) as db:
            sync_ticket(db, self.ticket("closed"))
            db.commit()
            alert = db.get(Alert, self.alert_id)
            alert.closed_at = datetime.now(timezone.utc) + timedelta(minutes=1)
            db.commit()

            sync_ticket(db, self.ticket("open"))
            db.commit()
            self.assertEqual(db.get(Alert, self.alert_id).status, AlertStatus.CLOSED)
            self.assertFalse(db.get(OsticketTicketLink, self.alert_id).closed_by_ticket)

    def test_unknown_or_duplicate_link_does_not_update_alert(self) -> None:
        with Session(self.engine) as db:
            unknown = TicketSnapshot(51, "999999", "closed", "Closed", f"Alerta ID: {uuid.uuid4()}")
            self.assertEqual(sync_ticket(db, unknown), "ignored")
            self.assertEqual(sync_ticket(db, self.ticket("open")), "changed")
            db.commit()
            self.assertEqual(sync_ticket(db, self.ticket("closed", ticket_id=52)), "duplicate")
            self.assertEqual(db.get(Alert, self.alert_id).status, AlertStatus.TRIAGED)


if __name__ == "__main__":
    unittest.main()
