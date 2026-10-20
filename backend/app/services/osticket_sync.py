"""Sincroniza el estado de tickets de osTicket con sus alertas SOC-Lite.

osTicket no ofrece lectura de tickets en su API pública. Este proceso consulta
su base en modo lectura; solo acepta tickets API del solicitante configurado
cuyo mensaje inicial contiene el UUID de una alerta existente.
"""
from __future__ import annotations

import logging
import os
import re
import signal
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, init_db
from app.models import Alert, OsticketTicketLink
from app.models.enums import AlertStatus
from app.services.audit import record_audit

logger = logging.getLogger("soc-lite.osticket-sync")
ALERT_ID_PATTERN = re.compile(r"^Alerta ID:\s*([0-9a-fA-F-]{36})\b")

TICKET_QUERY = text(
    """
    SELECT t.ticket_id, t.number, s.state, s.name AS status_name, e.body
    FROM ost_ticket AS t
    JOIN ost_ticket_status AS s ON s.id = t.status_id
    JOIN ost_user AS u ON u.id = t.user_id
    JOIN ost_user_email AS email ON email.id = u.default_email_id
    JOIN ost_thread AS thread ON thread.object_type = 'T' AND thread.object_id = t.ticket_id
    JOIN ost_thread_entry AS e ON e.thread_id = thread.id AND e.type = 'M'
    WHERE t.source = 'API'
      AND LOWER(email.address) = LOWER(:requester_email)
      AND e.body LIKE 'Alerta ID:%'
    ORDER BY t.ticket_id, e.id
    """
)


@dataclass(frozen=True)
class TicketSnapshot:
    ticket_id: int
    number: str
    state: str
    status_name: str
    body: str

    @property
    def alert_id(self) -> uuid.UUID | None:
        match = ALERT_ID_PATTERN.search(self.body)
        if not match:
            return None
        try:
            return uuid.UUID(match.group(1))
        except ValueError:
            return None


def read_tickets(osticket_engine, requester_email: str) -> list[TicketSnapshot]:
    """Devuelve solo el primer mensaje que identifica cada ticket de SOC-Lite."""
    tickets: dict[int, TicketSnapshot] = {}
    with osticket_engine.connect() as connection:
        for row in connection.execute(TICKET_QUERY, {"requester_email": requester_email}).mappings():
            ticket_id = int(row["ticket_id"])
            if ticket_id in tickets:
                continue
            state = str(row["state"] or "").lower()
            if state not in {"open", "closed"}:
                continue
            tickets[ticket_id] = TicketSnapshot(
                ticket_id=ticket_id,
                number=str(row["number"] or ""),
                state=state,
                status_name=str(row["status_name"] or state),
                body=str(row["body"] or ""),
            )
    return list(tickets.values())


def sync_ticket(db: Session, ticket: TicketSnapshot) -> str:
    """Aplica una transición una sola vez y respeta cierres humanos de SOC-Lite."""
    alert_id = ticket.alert_id
    if not alert_id or not ticket.number:
        return "ignored"
    alert = db.get(Alert, alert_id)
    if alert is None:
        return "ignored"

    link = db.get(OsticketTicketLink, alert_id)
    if link is not None and link.ticket_id != ticket.ticket_id:
        logger.warning("Alerta %s ya vinculada al ticket %s", alert_id, link.ticket_number)
        return "duplicate"
    other_link = db.scalar(
        select(OsticketTicketLink).where(OsticketTicketLink.ticket_id == ticket.ticket_id)
    )
    if other_link is not None and other_link.alert_id != alert_id:
        logger.warning("Ticket %s ya vinculado a otra alerta", ticket.number)
        return "duplicate"

    old_state = link.status_state if link else None
    old_name = link.status_name if link else None
    old_number = link.ticket_number if link else None
    if old_state == ticket.state and old_name == ticket.status_name and old_number == ticket.number:
        return "unchanged"

    now = datetime.now(timezone.utc)
    if link is None:
        link = OsticketTicketLink(
            alert_id=alert_id,
            ticket_id=ticket.ticket_id,
            ticket_number=ticket.number,
            status_state=ticket.state,
            status_name=ticket.status_name,
            last_synced_at=now,
        )
        db.add(link)
    else:
        link.ticket_number = ticket.number
        link.status_state = ticket.state
        link.status_name = ticket.status_name
        link.last_synced_at = now

    previous_alert_status = alert.status.value
    if ticket.state == "closed" and old_state != "closed":
        if alert.status not in {AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE}:
            link.previous_alert_status = alert.status.value
            link.closed_by_ticket = True
            link.applied_closed_at = now
            alert.status = AlertStatus.CLOSED
            alert.closed_at = now
    elif ticket.state == "open" and old_state == "closed":
        if (
            link.closed_by_ticket
            and alert.status == AlertStatus.CLOSED
            and alert.closed_at == link.applied_closed_at
        ):
            prior = link.previous_alert_status or AlertStatus.TRIAGED.value
            alert.status = AlertStatus(prior)
            alert.closed_at = None
        link.closed_by_ticket = False
        link.previous_alert_status = None
        link.applied_closed_at = None

    record_audit(
        db,
        module="alerts",
        action="Estado de osTicket sincronizado",
        event_type="TICKET_SYNC",
        actor_email="osticket-sync@soclite.local",
        actor_role="integration",
        direction="IN",
        entity_type="alert",
        entity_id=alert_id,
        description=f"Ticket {ticket.number}: {old_name or 'sin vínculo'} → {ticket.status_name}",
        detail={
            "ticket_id": ticket.ticket_id,
            "ticket_number": ticket.number,
            "ticket_state": ticket.state,
            "previous_alert_status": previous_alert_status,
            "alert_status": alert.status.value,
        },
    )
    return "changed"


def sync_once(osticket_engine, requester_email: str) -> dict[str, int]:
    counts = {"changed": 0, "unchanged": 0, "ignored": 0, "duplicate": 0}
    for ticket in read_tickets(osticket_engine, requester_email):
        try:
            with SessionLocal.begin() as db:
                result = sync_ticket(db, ticket)
            counts[result] += 1
        except Exception:
            logger.exception("No se pudo sincronizar el ticket %s", ticket.number)
    return counts


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s · %(message)s")
    password = os.environ["OSTICKET_DB_PASSWORD"]
    requester_email = os.environ.get("OSTICKET_REQUESTER_EMAIL", "soc-lite@example.org")
    interval = max(5, int(os.environ.get("OSTICKET_SYNC_INTERVAL_SECONDS", "20")))
    url = URL.create(
        "mysql+pymysql",
        username=os.environ.get("OSTICKET_DB_USER", "osticket"),
        password=password,
        host=os.environ.get("OSTICKET_DB_HOST", "osticket-db"),
        database=os.environ.get("OSTICKET_DB_NAME", "osticket"),
    )
    osticket_engine = create_engine(url, pool_pre_ping=True)
    init_db()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    logger.info("Sincronización osTicket iniciada; intervalo %ss", interval)
    try:
        while not stop.is_set():
            try:
                counts = sync_once(osticket_engine, requester_email)
                if counts["changed"] or counts["duplicate"]:
                    logger.info("Sincronización: %s", counts)
            except Exception:
                logger.exception("No se pudo consultar osTicket; se reintentará")
            stop.wait(interval)
    finally:
        osticket_engine.dispose()


if __name__ == "__main__":
    main()
