from datetime import datetime, timezone

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
from sqlalchemy.dialects.postgresql import JSONB

from .database import Base

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
    raw_event = Column(JSONType, nullable=False, default=dict)
    normalized = Column(JSONType, nullable=False, default=dict)

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
    triggered_rules = Column(JSONType, nullable=False, default=list)
    anomaly_score = Column(Float, nullable=True)
    threat_intel = Column(JSONType, nullable=False, default=list)
    score_components = Column(JSONType, nullable=False, default=dict)
    contributing_features = Column(JSONType, nullable=False, default=list)
    mitre_techniques = Column(JSONType, nullable=False, default=list)
    recommended_actions = Column(JSONType, nullable=False, default=list)
    related_event_ids = Column(JSONType, nullable=False, default=list)
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
    triggered_rules = Column(JSONType, nullable=False, default=list)
    anomaly_score = Column(Float, nullable=True)
    model_version = Column(String(255), nullable=True)
    mitre_techniques = Column(JSONType, nullable=False, default=list)
    related_event_ids = Column(JSONType, nullable=False, default=list)
    investigation_actions = Column(JSONType, nullable=False, default=list)
    risk_components = Column(JSONType, nullable=False, default=dict)
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
    mitre_techniques = Column(JSONType, nullable=False, default=list)
    related_assets = Column(JSONType, nullable=False, default=list)
    indicators = Column(JSONType, nullable=False, default=list)
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
    details = Column(JSONType, nullable=False, default=dict)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    task = Column(String(128), nullable=False, default="network_detection", index=True)
    version = Column(String(255), nullable=False)
    model_type = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="candidate", index=True)
    checksum = Column(String(128), nullable=True)
    dataset_identifier = Column(String(255), nullable=True)
    feature_list = Column(JSONType, nullable=False, default=list)
    class_mapping = Column(JSONType, nullable=False, default=dict)
    metrics = Column(JSONType, nullable=False, default=dict)
    metadata_json = Column(JSONType, nullable=False, default=dict)
    validation_result = Column(JSONType, nullable=False, default=dict)
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    activated_at = Column(DateTime, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    action = Column(String(128), nullable=False, index=True)
    target_type = Column(String(128), nullable=False, index=True)
    target_id = Column(String(128), nullable=True, index=True)
    details = Column(JSONType, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"

    id = Column(Integer, primary_key=True, index=True)
    event_key = Column(String(128), nullable=True, index=True)
    topic = Column(String(255), nullable=True)
    partition = Column(Integer, nullable=True)
    offset = Column(Integer, nullable=True)
    payload = Column(JSONType, nullable=False, default=dict)
    error = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


# ---------------------------------------------------------------------------
# Portable Assessment -- v1
# ---------------------------------------------------------------------------


class AssessmentRun(Base):
    """
    One portable assessment import.

    assessment_id is the UUID from the scanner JSON report.
    report_checksum is the SHA-256 of the canonical JSON payload (integrity only).

    Alert creation rules enforced at API layer:
    * create_alerts must be explicitly requested (default False).
    * Only administrator or security_analyst roles may request alert creation.
    * Alerts only for findings with status=fail AND severity high or critical.
    * detection_source is always portable_assessment.
    * Never create alerts for warning, unavailable, permission_required, or error.
    """

    __tablename__ = "assessment_runs"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(String(128), unique=True, nullable=False, index=True)
    scanner_version = Column(String(64), nullable=False)
    schema_version = Column(String(32), nullable=False, default="assessment.v1")
    score_algorithm = Column(String(64), nullable=False, default="posture_score_v1")
    privacy_mode = Column(String(32), nullable=False, default="standard")
    privilege_level = Column(String(32), nullable=False, default="standard")
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=False)
    imported_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    imported_by = Column(String(255), nullable=True, index=True)
    host_hostname = Column(String(255), nullable=True)
    host_os_name = Column(String(128), nullable=True)
    host_os_version = Column(String(128), nullable=True)
    host_os_build = Column(String(64), nullable=True)
    host_architecture = Column(String(64), nullable=True)
    checks_attempted = Column(Integer, nullable=False, default=0)
    coverage_pct = Column(Float, nullable=True)
    coverage_failed = Column(Integer, nullable=False, default=0)
    coverage_unavailable = Column(Integer, nullable=False, default=0)
    coverage_permission_required = Column(Integer, nullable=False, default=0)
    coverage_errors = Column(Integer, nullable=False, default=0)
    posture_score = Column(Integer, nullable=False, default=0, index=True)
    posture_score_components = Column(JSONType, nullable=True)
    posture_score_caveat = Column(Text, nullable=True)
    report_checksum = Column(String(128), nullable=False)
    report_checksum_algorithm = Column(String(32), nullable=False, default="sha256")
    checksum_verified = Column(Boolean, nullable=False, default=False)
    full_report = Column(JSONType, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    findings = relationship("AssessmentFinding", back_populates="assessment_run", cascade="all, delete-orphan")


class AssessmentFinding(Base):
    """
    One finding from a portable assessment.
    UNIQUE (assessment_run_id, finding_id) enforces import idempotency.
    finding_id is the stable entity key -- never a PID.
    """

    __tablename__ = "assessment_findings"
    __table_args__ = (
        UniqueConstraint("assessment_run_id", "finding_id", name="uq_assessment_run_finding"),
    )

    id = Column(Integer, primary_key=True, index=True)
    assessment_run_id = Column(
        Integer, ForeignKey("assessment_runs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    check_id = Column(String(32), nullable=False, index=True)
    finding_id = Column(String(512), nullable=False)
    title = Column(String(512), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="informational", index=True)
    confidence = Column(String(32), nullable=False, default="medium")
    status = Column(String(32), nullable=False, default="informational", index=True)
    evidence = Column(JSONType, nullable=True)
    explanation = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    device_impact = Column(String(512), nullable=True)
    admin_required = Column(Boolean, nullable=False, default=False)
    may_disrupt = Column(Boolean, nullable=False, default=False)
    references_json = Column(JSONType, nullable=True)
    collected_at = Column(DateTime, nullable=True)
    collector_version = Column(String(32), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    assessment_run = relationship("AssessmentRun", back_populates="findings")


# ---------------------------------------------------------------------------
# Guardian v2 -- Phase 1 (additive)
# ---------------------------------------------------------------------------


class GuardianAgent(Base):
    __tablename__ = "guardian_agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_key = Column(String(128), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    host_id = Column(String(128), nullable=True)
    os_name = Column(String(128), nullable=True)
    os_version = Column(String(128), nullable=True)
    agent_version = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="active", index=True)
    registered_at = Column(DateTime, nullable=False, default=utcnow)
    last_heartbeat_at = Column(DateTime, nullable=True)
    metadata_json = Column(JSONType, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    heartbeats = relationship("GuardianHeartbeat", back_populates="agent")
    events = relationship("GuardianEvent", back_populates="agent")


class GuardianHeartbeat(Base):
    __tablename__ = "guardian_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("guardian_agents.id"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow, index=True)
    agent_version = Column(String(64), nullable=True)
    uptime_seconds = Column(Integer, nullable=True)
    cpu_usage_pct = Column(Float, nullable=True)
    memory_usage_pct = Column(Float, nullable=True)
    events_queued = Column(Integer, nullable=True, default=0)
    events_processed = Column(Integer, nullable=True, default=0)
    detections_pending = Column(Integer, nullable=True, default=0)
    metadata_json = Column(JSONType, nullable=False, default=dict)

    agent = relationship("GuardianAgent", back_populates="heartbeats")


class GuardianEvent(Base):
    __tablename__ = "guardian_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(128), unique=True, nullable=False, index=True)
    schema_version = Column(String(32), nullable=False, default="guardian.event.v1")
    agent_id = Column(Integer, ForeignKey("guardian_agents.id"), nullable=False, index=True)
    event_category = Column(String(32), nullable=False, default="process", index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    ingestion_timestamp = Column(DateTime, nullable=False, default=utcnow)

    process_name = Column(String(255), nullable=True)
    process_pid = Column(Integer, nullable=True)
    process_exe_path = Column(Text, nullable=True, index=True)
    process_exe_hash_sha256 = Column(String(128), nullable=True)
    process_command_line = Column(Text, nullable=True)
    parent_process_name = Column(String(255), nullable=True)
    parent_process_pid = Column(Integer, nullable=True)
    parent_process_exe_path = Column(Text, nullable=True)

    user_name = Column(String(255), nullable=True)
    user_sid = Column(String(128), nullable=True)

    source_ip = Column(String(64), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    bytes_sent = Column(Float, nullable=True)
    bytes_received = Column(Float, nullable=True)

    file_path = Column(Text, nullable=True)
    file_operation = Column(String(32), nullable=True)
    file_hash_sha256 = Column(String(128), nullable=True)

    persistence_type = Column(String(64), nullable=True)
    persistence_path = Column(Text, nullable=True)
    persistence_data = Column(JSONType, nullable=True)

    evidence = Column(JSONType, nullable=False, default=dict)
    raw_event = Column(JSONType, nullable=False, default=dict)
    status = Column(String(32), nullable=False, default="ingested", index=True)

    created_at = Column(DateTime, nullable=False, default=utcnow)

    agent = relationship("GuardianAgent", back_populates="events")


# ---------------------------------------------------------------------------
# Guardian v2 -- Phase 2 (additive)
# ---------------------------------------------------------------------------


class GuardianDetection(Base):
    __tablename__ = "guardian_detections"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(String(128), unique=True, nullable=False, index=True)
    event_id = Column(String(128), nullable=False, index=True)
    detector_id = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="low", index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(JSONType, nullable=False, default=dict)
    mitre_technique = Column(String(32), nullable=True)
    mitre_tactic = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class GuardianIncident(Base):
    __tablename__ = "guardian_incidents"

    id = Column(Integer, primary_key=True, index=True)
    candidate_id = Column(String(128), unique=True, nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), nullable=False, default="low", index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    status = Column(String(32), nullable=False, default="open", index=True)
    evidence_ids = Column(JSONType, nullable=False, default=list)
    event_ids = Column(JSONType, nullable=False, default=list)
    host_ids = Column(JSONType, nullable=False, default=list)
    mitre_techniques = Column(JSONType, nullable=False, default=list)
    mitre_tactics = Column(JSONType, nullable=False, default=list)
    risk_score_id = Column(Integer, nullable=True)
    response_decision_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class GuardianIncidentEvent(Base):
    __tablename__ = "guardian_incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("guardian_incidents.id"), nullable=False, index=True)
    event_id = Column(String(128), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    data = Column(JSONType, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class GuardianRiskScore(Base):
    __tablename__ = "guardian_risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    score = Column(Float, nullable=False, default=0.0)
    severity = Column(String(32), nullable=False, default="low")
    confidence = Column(Float, nullable=False, default=0.0)
    factors = Column(JSONType, nullable=False, default=list)
    explanation = Column(Text, nullable=True)
    detection_ids = Column(JSONType, nullable=False, default=list)
    incident_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class GuardianResponseDecision(Base):
    __tablename__ = "guardian_response_decisions"

    id = Column(Integer, primary_key=True, index=True)
    decision_id = Column(String(128), unique=True, nullable=False, index=True)
    incident_id = Column(Integer, nullable=True, index=True)
    severity = Column(String(32), nullable=False, default="low", index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    recommended_action = Column(String(64), nullable=False, default="monitor")
    rationale = Column(Text, nullable=True)
    evidence = Column(JSONType, nullable=False, default=list)
    expected_effect = Column(Text, nullable=True)
    risk = Column(JSONType, nullable=True)
    requires_approval = Column(Boolean, nullable=False, default=True)
    rollback_available = Column(Boolean, nullable=False, default=False)
    verification_plan = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
