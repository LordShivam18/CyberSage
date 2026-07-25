import hashlib
from datetime import timedelta
from typing import Iterable, Optional, Set

from sqlalchemy.orm import Session

from .models import Alert, Detection, Incident, IncidentAlert, NormalizedEvent


OPEN_INCIDENT_STATUSES = {"new", "triaged", "investigating", "contained"}


def _hash_key(parts: Iterable[str]) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"incident-{digest}"


def _techniques(alert: Alert) -> Set[str]:
    return set(alert.mitre_techniques or [])


def _matches(alert: Alert, incident: Incident) -> bool:
    if incident.status not in OPEN_INCIDENT_STATUSES:
        return False
    same_pair = (
        alert.source_ip
        and alert.destination_ip
        and alert.source_ip == incident.source_ip
        and alert.destination_ip == incident.destination_ip
    )
    same_class = alert.classification and alert.classification == incident.classification
    shared_technique = bool(_techniques(alert).intersection(set(incident.mitre_techniques or [])))
    return bool(same_pair and (same_class or shared_technique))


def correlate_alert(
    db: Session,
    alert: Alert,
    detection: Detection,
    event: NormalizedEvent,
    window_minutes: int = 60,
) -> Incident:
    existing_link = db.query(IncidentAlert).filter(IncidentAlert.alert_id == alert.id).first()
    if existing_link:
        return existing_link.incident

    window_start = (alert.first_seen or alert.timestamp) - timedelta(minutes=window_minutes)
    candidates = (
        db.query(Incident)
        .filter(
            Incident.last_seen >= window_start,
            Incident.status.in_(OPEN_INCIDENT_STATUSES),
        )
        .order_by(Incident.last_seen.desc())
        .all()
    )
    incident: Optional[Incident] = next((candidate for candidate in candidates if _matches(alert, candidate)), None)

    if incident is None:
        key = _hash_key(
            [
                alert.source_ip or "unknown-src",
                alert.destination_ip or "unknown-dst",
                alert.classification or "unknown-class",
                (alert.first_seen or alert.timestamp).strftime("%Y%m%d%H"),
            ]
        )
        incident = Incident(
            incident_key=key,
            title=f"{alert.classification or alert.prediction} involving {alert.source_ip or 'unknown source'}",
            status="new",
            severity=alert.severity or "low",
            priority=alert.priority or "medium",
            classification=alert.classification,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            attack_family=alert.classification,
            mitre_techniques=alert.mitre_techniques or [],
            related_assets=[value for value in [event.host_id, event.device_id, event.destination_ip] if value],
            indicators=[value for value in [event.source_ip, event.destination_ip] if value],
            first_seen=alert.first_seen or alert.timestamp,
            last_seen=alert.last_seen or alert.timestamp,
        )
        db.add(incident)
        db.flush()
    else:
        incident.last_seen = max(incident.last_seen, alert.last_seen or alert.timestamp)
        incident.severity = _max_severity(incident.severity, alert.severity)
        incident.mitre_techniques = sorted(set(incident.mitre_techniques or []).union(alert.mitre_techniques or []))
        incident.related_assets = sorted(
            set(incident.related_assets or []).union(
                value for value in [event.host_id, event.device_id, event.destination_ip] if value
            )
        )
        incident.indicators = sorted(
            set(incident.indicators or []).union(value for value in [event.source_ip, event.destination_ip] if value)
        )

    db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.flush()
    return incident


def _max_severity(current: str, new: str) -> str:
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return new if order.get(new or "low", 1) > order.get(current or "low", 1) else current
