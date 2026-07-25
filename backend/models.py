from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow():
    return datetime.utcnow()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(64), nullable=False, default="security_analyst", index=True)
    disabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(128), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    ingestion_timestamp = Column(DateTime, nullable=False, default=utcnow, index=True)
    sensor_type = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(32), nullable=True, index=True)
    duration = Column(Float, nullable=True)
    bytes_sent = Column(Float, nullable=True)
    bytes_received = Column(Float, nullable=True)
    packets_sent = Column(Float, nullable=True)
    packets_received = Column(Float, nullable=True)
    tcp_flags = Column(String(128), nullable=True)
    flow_id = Column(String(255), nullable=True, index=True)
    host_id = Column(String(255), nullable=True, index=True)
    device_id = Column(String(255), nullable=True, index=True)
    raw_event_reference = Column(String(512), nullable=True)
    schema_version = Column(String(32), nullable=False, default="ndr.event.v1")
    raw_event = Column(JSON, nullable=False, default=dict)
    normalized = Column(JSON, nullable=False, default=dict)

    detections = relationship("Detection", back_populates="event")


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    detection_key = Column(String(128), unique=True, nullable=False, index=True)
    event_id = Column(String(128), ForeignKey("normalized_events.event_id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    detection_source = Column(String(64), nullable=False, index=True)
    classification = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    severity = Column(String(32), nullable=False, default="low", index=True)
    risk_score = Column(Float, nullable=False, default=0.0, index=True)
    model_name = Column(String(255), nullable=True)
    model_version = Column(String(255), nullable=True)
    model_file_checksum = Column(String(128), nullable=True)
    triggered_rules = Column(JSON, nullable=False, default=list)
    anomaly_score = Column(Float, nullable=True)
    threat_intel = Column(JSON, nullable=False, default=list)
    score_components = Column(JSON, nullable=False, default=dict)
    contributing_features = Column(JSON, nullable=False, default=list)
    mitre_techniques = Column(JSON, nullable=False, default=list)
    recommended_actions = Column(JSON, nullable=False, default=list)
    related_event_ids = Column(JSON, nullable=False, default=list)
    raw_evidence_reference = Column(String(512), nullable=True)
    latency_ms = Column(Float, nullable=True)

    event = relationship("NormalizedEvent", back_populates="detections")
    alert = relationship("Alert", back_populates="detection", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    prediction = Column(String, index=True)
    probability = Column(Float)
    details = Column(Text)
    alert_key = Column(String(128), unique=True, nullable=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), nullable=True, index=True)
    status = Column(String(64), nullable=False, default="new", index=True)
    severity = Column(String(32), nullable=False, default="low", index=True)
    classification = Column(String(128), nullable=True, index=True)
    confidence = Column(Float, nullable=True)
    detection_source = Column(String(64), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    risk_score = Column(Float, nullable=True, index=True)
    triggered_rules = Column(JSON, nullable=False, default=list)
    anomaly_score = Column(Float, nullable=True)
    model_version = Column(String(255), nullable=True)
    mitre_techniques = Column(JSON, nullable=False, default=list)
    related_event_ids = Column(JSON, nullable=False, default=list)
    investigation_actions = Column(JSON, nullable=False, default=list)
    risk_components = Column(JSON, nullable=False, default=dict)
    raw_evidence_reference = Column(String(512), nullable=True)
    assignee = Column(String(255), nullable=True)
    priority = Column(String(32), nullable=False, default="medium", index=True)
    analyst_notes = Column(Text, nullable=True)
    resolution_reason = Column(Text, nullable=True)
    first_seen = Column(DateTime, nullable=True, index=True)
    last_seen = Column(DateTime, nullable=True, index=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    detection = relationship("Detection", back_populates="alert")
    incidents = relationship("IncidentAlert", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_key = Column(String(128), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(64), nullable=False, default="new", index=True)
    severity = Column(String(32), nullable=False, default="low", index=True)
    priority = Column(String(32), nullable=False, default="medium", index=True)
    assignee = Column(String(255), nullable=True)
    classification = Column(String(128), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    attack_family = Column(String(128), nullable=True, index=True)
    mitre_techniques = Column(JSON, nullable=False, default=list)
    related_assets = Column(JSON, nullable=False, default=list)
    indicators = Column(JSON, nullable=False, default=list)
    first_seen = Column(DateTime, nullable=False, default=utcnow, index=True)
    last_seen = Column(DateTime, nullable=False, default=utcnow, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    analyst_notes = Column(Text, nullable=True)
    resolution_reason = Column(Text, nullable=True)

    alerts = relationship("IncidentAlert", back_populates="incident")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    incident = relationship("Incident", back_populates="alerts")
    alert = relationship("Alert", back_populates="incidents")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    username = Column(String(255), nullable=False)
    disposition = Column(String(64), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(64), nullable=False, index=True)
    source = Column(String(128), nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    verdict = Column(String(64), nullable=False, default="unknown")
    details = Column(JSON, nullable=False, default=dict)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(255), nullable=False)
    model_type = Column(String(128), nullable=False)
    checksum = Column(String(128), nullable=True)
    feature_list = Column(JSON, nullable=False, default=list)
    class_mapping = Column(JSON, nullable=False, default=dict)
    metrics = Column(JSON, nullable=False, default=dict)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    action = Column(String(128), nullable=False, index=True)
    target_type = Column(String(128), nullable=False, index=True)
    target_id = Column(String(128), nullable=True, index=True)
    details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"

    id = Column(Integer, primary_key=True, index=True)
    event_key = Column(String(128), nullable=True, index=True)
    topic = Column(String(255), nullable=True)
    partition = Column(Integer, nullable=True)
    offset = Column(Integer, nullable=True)
    payload = Column(JSON, nullable=False, default=dict)
    error = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
