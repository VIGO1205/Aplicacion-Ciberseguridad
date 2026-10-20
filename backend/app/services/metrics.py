"""Cálculo de indicadores del dashboard y de los reportes."""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import ensure_aware
from app.models import Alert, Incident, TriageResult
from app.models.enums import AlertStatus, IncidentStatus, Severity, Verdict
from app.schemas import (
    DashboardOverview,
    KPIBlock,
    NamedCount,
    SeriesPoint,
)

OPEN_ALERT_STATUSES = {
    AlertStatus.PENDING,
    AlertStatus.TRIAGING,
    AlertStatus.TRIAGED,
    AlertStatus.ESCALATED,
}
OPEN_INCIDENT_STATUSES = {
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
}


def _period(days: int) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=days), end


def _count_values(items: list[str]) -> list[NamedCount]:
    return [NamedCount(name=name, value=count) for name, count in Counter(items).most_common()]


def calculate_overview(
    db: Session,
    days: int = 14,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> DashboardOverview:
    if start is None or end is None:
        start, end = _period(days)
    alerts = list(
        db.scalars(
            select(Alert).where(Alert.received_at >= start).order_by(Alert.received_at.desc())
        ).all()
    )
    incidents = list(
        db.scalars(
            select(Incident).where(
                or_(
                    Incident.opened_at.between(start, end),
                    Incident.closed_at.between(start, end),
                    Incident.status.in_(OPEN_INCIDENT_STATUSES),
                )
            )
        ).all()
    )

    total = len(alerts)
    open_alerts = [a for a in alerts if a.status in OPEN_ALERT_STATUSES]
    triaged = [a for a in alerts if a.triage_result is not None]
    fp = [
        a
        for a in alerts
        if a.status == AlertStatus.FALSE_POSITIVE
        or (a.triage_result is not None and a.triage_result.verdict == Verdict.FALSE_POSITIVE)
    ]

    mttt_values: list[float] = []
    for alert in triaged:
        triage = alert.triage_result
        if triage is None:
            continue
        created = ensure_aware(triage.created_at)
        received = ensure_aware(alert.received_at)
        if created and received:
            mttt_values.append(max(0.0, (created - received).total_seconds() / 60))

    closed_incidents = [
        i for i in incidents if i.status in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED} and i.closed_at
    ]
    mttr_values = [
        max(0.0, (ensure_aware(i.closed_at) - ensure_aware(i.opened_at)).total_seconds() / 3600)
        for i in closed_incidents
        if i.closed_at
    ]

    with_sla = [i for i in incidents if i.sla_due_at]
    on_time = 0
    for incident in with_sla:
        due = ensure_aware(incident.sla_due_at)
        if incident.closed_at:
            if ensure_aware(incident.closed_at) <= due:
                on_time += 1
        elif datetime.now(timezone.utc) <= due:
            on_time += 1
    sla_compliance = (on_time / len(with_sla) * 100) if with_sla else 100.0

    automated = [a for a in triaged if (a.triage_result and a.triage_result.engine != "manual")]
    fp_rate = (len(fp) / len(triaged) * 100) if triaged else 0.0

    kpis = KPIBlock(
        total_alerts=total,
        open_alerts=len(open_alerts),
        critical_open=sum(1 for a in open_alerts if a.severity == Severity.CRITICAL),
        high_open=sum(1 for a in open_alerts if a.severity == Severity.HIGH),
        false_positive_rate=round(fp_rate, 1),
        triage_coverage=round(len(triaged) / total * 100, 1) if total else 0.0,
        automation_rate=round(len(automated) / len(triaged) * 100, 1) if triaged else 0.0,
        mttt_minutes=round(sum(mttt_values) / len(mttt_values), 1) if mttt_values else 0.0,
        mttr_hours=round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else 0.0,
        sla_compliance=round(sla_compliance, 1),
        open_incidents=sum(1 for i in incidents if i.status in OPEN_INCIDENT_STATUSES),
        total_incidents=len(incidents),
    )

    counts_by_day: Counter[str] = Counter()
    for alert in alerts:
        received = ensure_aware(alert.received_at)
        if received:
            counts_by_day[received.date().isoformat()] += 1
    series: list[SeriesPoint] = []
    cursor: date = start.date()
    while cursor <= end.date():
        key = cursor.isoformat()
        series.append(SeriesPoint(label=key, value=counts_by_day.get(key, 0)))
        cursor += timedelta(days=1)

    by_severity = [
        NamedCount(
            name=severity.value,
            value=sum(1 for a in alerts if a.severity == severity),
        )
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]
    by_status = _count_values([a.status.value for a in alerts])
    by_source = _count_values([a.source for a in alerts])
    by_verdict = _count_values(
        [a.triage_result.verdict.value for a in triaged if a.triage_result]
    )
    top_ips = _count_values([a.source_ip for a in alerts if a.source_ip])[:8]
    top_rules = _count_values(
        [f"{a.rule_id or 'sin-regla'} · {a.title[:60]}" for a in alerts]
    )[:8]

    mitre_counter: Counter[str] = Counter()
    for alert in alerts:
        for technique in alert.mitre_techniques or []:
            mitre_counter[str(technique)] += 1
        if alert.triage_result:
            for technique in alert.triage_result.mitre_techniques or []:
                mitre_counter[str(technique)] += 1
    top_mitre = [
        NamedCount(name=name, value=value) for name, value in mitre_counter.most_common(8)
    ]

    incident_status = _count_values([i.status.value for i in incidents])

    return DashboardOverview(
        period_days=days,
        generated_at=end,
        kpis=kpis,
        alerts_by_day=series,
        by_severity=by_severity,
        by_status=by_status,
        by_source=by_source,
        by_verdict=by_verdict,
        top_source_ips=top_ips,
        top_rules=top_rules,
        top_mitre=top_mitre,
        incidents_by_status=incident_status,
        recent_alerts=alerts[:8],
    )


def period_bounds(days: int) -> tuple[datetime, datetime]:
    return _period(days)


def alert_rows_for_report(db: Session, start: datetime, end: datetime) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .where(Alert.received_at >= start, Alert.received_at <= end)
            .order_by(Alert.received_at.desc())
        ).all()
    )


def incident_rows_for_report(db: Session, start: datetime, end: datetime) -> list[Incident]:
    return list(
        db.scalars(
            select(Incident)
            .where(Incident.opened_at >= start, Incident.opened_at <= end)
            .order_by(Incident.opened_at.desc())
        ).all()
    )


def triage_rows_for_report(db: Session, start: datetime, end: datetime) -> list[TriageResult]:
    return list(
        db.scalars(
            select(TriageResult)
            .where(TriageResult.created_at >= start, TriageResult.created_at <= end)
            .order_by(TriageResult.created_at.desc())
        ).all()
    )
