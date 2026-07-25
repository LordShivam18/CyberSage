import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from .anomaly import anomaly_detector
from .correlation import correlate_alert
from .detection_types import DetectorResult
from .inference import model_detector
from .mitre import map_to_mitre
from .models import Alert, DeadLetterEvent, Detection, NormalizedEvent
from .risk import risk_scorer, severity_from_score
from .rules_engine import rule_engine
from .telemetry import NormalizedNetworkEvent, normalize_event
from .threat_intel_service import threat_intel_service


def _hash_key(prefix: str, payload: str) -> str:
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:32]}"


def _json_ready(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _model_dump(model):
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _persist_event(db: Session, event: NormalizedNetworkEvent) -> NormalizedEvent:
    existing = db.query(NormalizedEvent).filter(NormalizedEvent.event_id == event.event_id).first()
    if existing:
        return existing
    data = event.to_db_dict()
    record = NormalizedEvent(**data)
    db.add(record)
    db.flush()
    return record


def _event_from_record(record: NormalizedEvent) -> NormalizedNetworkEvent:
    return NormalizedNetworkEvent(
        event_id=record.event_id,
        timestamp=record.timestamp,
        sensor_type=record.sensor_type,
        source_ip=record.source_ip,
        source_port=record.source_port,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        protocol=record.protocol,
        duration=record.duration,
        bytes_sent=record.bytes_sent,
        bytes_received=record.bytes_received,
        packets_sent=record.packets_sent,
        packets_received=record.packets_received,
        tcp_flags=record.tcp_flags,
        flow_id=record.flow_id,
        host_id=record.host_id,
        device_id=record.device_id,
        raw_event_reference=record.raw_event_reference,
        schema_version=record.schema_version,
        ingestion_timestamp=record.ingestion_timestamp,
        raw_event=record.raw_event or {},
    )


def _context_for_event(db: Session, event: NormalizedNetworkEvent) -> Dict[str, Any]:
    if not event.source_ip:
        return {}
    since = event.timestamp - timedelta(minutes=5)
    rows = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.source_ip == event.source_ip, NormalizedEvent.timestamp >= since)
        .all()
    )
    return {
        "source_connection_count_5m": len(rows),
        "unique_destination_ports_5m": len({row.destination_port for row in rows if row.destination_port}),
    }


def _repeat_count(db: Session, event: NormalizedNetworkEvent, classification: str) -> int:
    since = event.timestamp - timedelta(hours=24)
    query = db.query(Alert).filter(Alert.timestamp >= since, Alert.classification == classification)
    if event.source_ip:
        query = query.filter(Alert.source_ip == event.source_ip)
    if event.destination_ip:
        query = query.filter(Alert.destination_ip == event.destination_ip)
    return query.count()


def _severity_max(*values: str) -> str:
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max([value for value in values if value], key=lambda value: order.get(value, 0), default="low")


def _classification(
    model_result: DetectorResult,
    anomaly_result: DetectorResult,
    rule_result: DetectorResult,
    threat_intel_hits,
) -> str:
    if threat_intel_hits and rule_result.triggered_rules:
        return "Known Malicious Indicator"
    if model_result.classification.upper() not in {"BENIGN", "NORMAL"}:
        return model_result.classification
    if anomaly_result.classification == "ANOMALY":
        return "Anomalous Network Activity"
    if rule_result.triggered_rules:
        return rule_result.triggered_rules[0]["name"]
    return "BENIGN"


def _recommended_actions(*results: DetectorResult) -> list:
    actions = []
    for result in results:
        for action in result.recommended_actions:
            if action not in actions:
                actions.append(action)
    if not actions:
        actions.append("Review related flows and confirm whether this activity is expected.")
    return actions


def _contributing_features(*results: DetectorResult) -> list:
    features = []
    seen = set()
    for result in results:
        for item in result.contributing_features:
            key = (item.get("feature"), item.get("reason"))
            if key in seen:
                continue
            seen.add(key)
            features.append(item)
    return features[:10]


def process_payload(
    payload: Dict[str, Any],
    db: Session,
    source_hint: Optional[str] = None,
    raw_reference: Optional[str] = None,
) -> Dict[str, Any]:
    event = normalize_event(payload, source_hint=source_hint, raw_reference=raw_reference)
    event_record = _persist_event(db, event)
    event = _event_from_record(event_record)

    detection_key = _hash_key("det", f"{event.event_id}|hybrid-v1")
    existing_detection = db.query(Detection).filter(Detection.detection_key == detection_key).first()
    if existing_detection:
        return {
            "event": event_record,
            "detection": existing_detection,
            "alert": existing_detection.alert,
            "incident": existing_detection.alert.incidents[0].incident
            if existing_detection.alert and existing_detection.alert.incidents
            else None,
            "created": False,
        }

    threat_intel_hits = threat_intel_service.lookup_event_indicators(event, db=db)
    context = _context_for_event(db, event)
    model_result = model_detector.predict_event(event)
    anomaly_result = anomaly_detector.score_event(event)
    rule_result = rule_engine.evaluate(event, context=context, threat_intel_hits=threat_intel_hits)
    classification = _classification(model_result, anomaly_result, rule_result, threat_intel_hits)
    repeat_count = _repeat_count(db, event, classification)
    risk = risk_scorer.score(
        model_result=model_result,
        anomaly_result=anomaly_result,
        rule_result=rule_result,
        threat_intel_hits=threat_intel_hits,
        repeat_occurrence_count=repeat_count,
    )
    rule_ids = [rule["id"] for rule in rule_result.triggered_rules]
    mitre = sorted(
        set(model_result.mitre_techniques)
        .union(anomaly_result.mitre_techniques)
        .union(rule_result.mitre_techniques)
        .union(map_to_mitre(classification, model_result.classification, anomaly_result.classification, rule_ids=rule_ids))
    )
    severity = _severity_max(risk.severity, model_result.severity, anomaly_result.severity, rule_result.severity)
    if risk.score < 15 and classification == "BENIGN":
        severity = severity_from_score(risk.score)

    detection = Detection(
        detection_key=detection_key,
        event_id=event.event_id,
        detection_source="hybrid",
        classification=classification,
        confidence=max(model_result.confidence, anomaly_result.confidence, rule_result.confidence),
        severity=severity,
        risk_score=risk.score,
        model_name=model_result.model_name,
        model_version=model_result.model_version,
        model_file_checksum=model_result.model_file_checksum,
        triggered_rules=rule_result.triggered_rules,
        anomaly_score=anomaly_result.anomaly_score,
        threat_intel=threat_intel_hits,
        score_components=risk.components,
        contributing_features=_contributing_features(model_result, anomaly_result),
        mitre_techniques=mitre,
        recommended_actions=_recommended_actions(model_result, anomaly_result, rule_result),
        related_event_ids=[event.event_id],
        raw_evidence_reference=event.raw_event_reference,
        latency_ms=model_result.latency_ms,
    )
    db.add(detection)
    db.flush()

    alert = None
    incident = None
    should_alert = classification != "BENIGN" or risk.score >= 15 or bool(rule_result.triggered_rules)
    if should_alert:
        alert_key = _hash_key("alert", detection_key)
        alert = db.query(Alert).filter(Alert.alert_key == alert_key).first()
        if alert is None:
            alert = Alert(
                alert_key=alert_key,
                detection_id=detection.id,
                timestamp=event.timestamp,
                prediction="ATTACK" if classification != "BENIGN" else "BENIGN",
                probability=detection.confidence,
                details=json.dumps(_json_ready(event.raw_event), sort_keys=True),
                status="new",
                severity=severity,
                classification=classification,
                confidence=detection.confidence,
                detection_source=detection.detection_source,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                risk_score=risk.score,
                triggered_rules=rule_result.triggered_rules,
                anomaly_score=anomaly_result.anomaly_score,
                model_version=model_result.model_version,
                mitre_techniques=mitre,
                related_event_ids=[event.event_id],
                investigation_actions=detection.recommended_actions,
                risk_components=risk.components,
                raw_evidence_reference=event.raw_event_reference,
                priority="high" if severity in {"critical", "high"} else "medium",
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
            db.add(alert)
            db.flush()
        incident = correlate_alert(db, alert, detection, event_record)

    return {
        "event": event_record,
        "detection": detection,
        "alert": alert,
        "incident": incident,
        "created": True,
    }


def persist_dead_letter(
    db: Session,
    payload: Dict[str, Any],
    error: str,
    event_key: Optional[str] = None,
    topic: Optional[str] = None,
    partition: Optional[int] = None,
    offset: Optional[int] = None,
) -> DeadLetterEvent:
    record = DeadLetterEvent(
        event_key=event_key,
        topic=topic,
        partition=partition,
        offset=offset,
        payload=payload if isinstance(payload, dict) else {"raw": payload},
        error=error,
    )
    db.add(record)
    db.flush()
    return record


def process_payload_safe(
    payload: Dict[str, Any],
    db: Session,
    source_hint: Optional[str] = None,
    raw_reference: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        return process_payload(payload, db, source_hint=source_hint, raw_reference=raw_reference)
    except Exception as exc:
        persist_dead_letter(db, payload, str(exc), event_key=payload.get("event_id") if isinstance(payload, dict) else None)
        raise
