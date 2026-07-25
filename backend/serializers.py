from datetime import datetime


def _dt(value):
    return value.isoformat() if isinstance(value, datetime) else value


def event_to_dict(event):
    return {
        "id": event.id,
        "event_id": event.event_id,
        "timestamp": _dt(event.timestamp),
        "ingestion_timestamp": _dt(event.ingestion_timestamp),
        "sensor_type": event.sensor_type,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "duration": event.duration,
        "bytes_sent": event.bytes_sent,
        "bytes_received": event.bytes_received,
        "packets_sent": event.packets_sent,
        "packets_received": event.packets_received,
        "tcp_flags": event.tcp_flags,
        "flow_id": event.flow_id,
        "host_id": event.host_id,
        "device_id": event.device_id,
        "raw_event_reference": event.raw_event_reference,
        "schema_version": event.schema_version,
        "raw_event": event.raw_event,
        "normalized": event.normalized,
    }


def detection_to_dict(detection):
    return {
        "id": detection.id,
        "detection_key": detection.detection_key,
        "event_id": detection.event_id,
        "created_at": _dt(detection.created_at),
        "detection_source": detection.detection_source,
        "classification": detection.classification,
        "confidence": detection.confidence,
        "severity": detection.severity,
        "risk_score": detection.risk_score,
        "model_name": detection.model_name,
        "model_version": detection.model_version,
        "model_file_checksum": detection.model_file_checksum,
        "triggered_rules": detection.triggered_rules or [],
        "anomaly_score": detection.anomaly_score,
        "threat_intel": detection.threat_intel or [],
        "score_components": detection.score_components or {},
        "contributing_features": detection.contributing_features or [],
        "mitre_techniques": detection.mitre_techniques or [],
        "recommended_actions": detection.recommended_actions or [],
        "related_event_ids": detection.related_event_ids or [],
        "raw_evidence_reference": detection.raw_evidence_reference,
        "latency_ms": detection.latency_ms,
    }


def alert_to_dict(alert, include_detection=False):
    data = {
        "id": alert.id,
        "timestamp": _dt(alert.timestamp),
        "prediction": alert.prediction,
        "probability": alert.probability,
        "details": alert.details,
        "alert_key": alert.alert_key,
        "status": alert.status,
        "severity": alert.severity,
        "classification": alert.classification,
        "confidence": alert.confidence,
        "detection_source": alert.detection_source,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "risk_score": alert.risk_score,
        "triggered_rules": alert.triggered_rules or [],
        "anomaly_score": alert.anomaly_score,
        "model_version": alert.model_version,
        "mitre_techniques": alert.mitre_techniques or [],
        "related_event_ids": alert.related_event_ids or [],
        "investigation_actions": alert.investigation_actions or [],
        "risk_components": alert.risk_components or {},
        "raw_evidence_reference": alert.raw_evidence_reference,
        "assignee": alert.assignee,
        "priority": alert.priority,
        "analyst_notes": alert.analyst_notes,
        "resolution_reason": alert.resolution_reason,
        "first_seen": _dt(alert.first_seen),
        "last_seen": _dt(alert.last_seen),
        "updated_at": _dt(alert.updated_at),
    }
    if include_detection and alert.detection:
        data["detection"] = detection_to_dict(alert.detection)
    return data


def incident_to_dict(incident, include_alerts=False):
    data = {
        "id": incident.id,
        "incident_key": incident.incident_key,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "priority": incident.priority,
        "assignee": incident.assignee,
        "classification": incident.classification,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,
        "attack_family": incident.attack_family,
        "mitre_techniques": incident.mitre_techniques or [],
        "related_assets": incident.related_assets or [],
        "indicators": incident.indicators or [],
        "first_seen": _dt(incident.first_seen),
        "last_seen": _dt(incident.last_seen),
        "created_at": _dt(incident.created_at),
        "updated_at": _dt(incident.updated_at),
        "analyst_notes": incident.analyst_notes,
        "resolution_reason": incident.resolution_reason,
    }
    if include_alerts:
        data["alerts"] = [alert_to_dict(link.alert) for link in incident.alerts]
    return data
