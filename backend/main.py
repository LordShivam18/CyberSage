from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .anomaly import anomaly_detector
from .auth import (
    ALL_ROLES,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    LoginRequest,
    TokenResponse,
    audit_event,
    authenticate_token,
    auth_rate_limiter,
    authenticate_user,
    create_access_token,
    predict_rate_limiter,
    require_roles,
)
from .config import settings
from .database import SessionLocal, get_db
from .inference import model_detector, run_prediction
from .migrations.runner import current_revision
from .model_governance import GovernanceError
from .model_registry import active_model, archive_model, list_models, model_version_to_public, promote_model, validate_registered_model
from .models import Alert, AuditEvent, Detection, Incident, ModelVersion, NormalizedEvent
from .pipeline import process_payload
from .realtime import manager
from .rules_engine import rule_engine
from .schemas import (
    AlertResponse,
    AlertUpdateRequest,
    IncidentUpdateRequest,
    ModelValidationRequest,
    NetworkFlow,
    TelemetryIngestRequest,
    ThreatIntelLookupRequest,
)
from .serializers import alert_to_dict, detection_to_dict, event_to_dict, incident_to_dict
from .threat_intel_service import threat_intel_service


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.validate_runtime_security()
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


ALERT_STATUSES = {"new", "acknowledged", "investigating", "resolved", "false_positive"}
INCIDENT_STATUSES = {"new", "triaged", "investigating", "contained", "resolved", "false_positive"}
PRIORITIES = {"low", "medium", "high", "critical"}


def _dump_model(model):
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _recent_model_feature_rows(db: Session, limit: int = 200):
    rows = db.query(NormalizedEvent).order_by(NormalizedEvent.timestamp.desc()).limit(limit).all()
    feature_rows = []
    for row in rows:
        values = dict(row.normalized or {})
        values.update(row.raw_event or {})
        feature_rows.append(values)
    return feature_rows


def _model_governance_status(db: Session):
    drift = model_detector.evaluate_recent_drift(_recent_model_feature_rows(db))
    active = active_model(db)
    return {
        "active_model": model_version_to_public(active) if active else None,
        "drift": drift,
    }


def _governance_http_error(db: Session, exc: GovernanceError):
    db.rollback()
    raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@app.get("/api/v1/ready")
def ready(db: Session = Depends(get_db)):
    database_ok = True
    database_error = None
    revision = None
    try:
        db.execute(text("SELECT 1"))
        revision = current_revision()
    except Exception as exc:
        database_ok = False
        database_error = str(exc)
    return {
        "ready": database_ok and rule_engine.error is None,
        "database": {"ok": database_ok, "error": database_error, "revision": revision},
        "model": model_detector.status(),
        "anomaly": anomaly_detector.status(),
        "rules": rule_engine.status(),
        "kafka_consumer": "separate worker process; start with python -m backend.worker",
    }


@app.post("/api/v1/auth/login", response_model=TokenResponse, dependencies=[Depends(auth_rate_limiter)])
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    audit_event(db, "login", "user", user.username, user=user)
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        username=user.username,
        role=user.role,
    )


@app.post("/predict", dependencies=[Depends(predict_rate_limiter)])
def predict_flow(flow: NetworkFlow):
    prediction, probability = run_prediction(_dump_model(flow))
    status_payload = model_detector.status()
    return {
        "prediction": prediction,
        "probability": probability,
        "model_available": status_payload["available"],
        "degraded": not status_payload["available"],
        "model_name": status_payload["model_name"],
        "model_version": status_payload["model_version"],
        "warning": status_payload["fallback_reason"],
    }


@app.get("/alerts", response_model=list[AlertResponse])
def get_legacy_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()


@app.post(
    "/api/v1/events",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER))],
)
async def ingest_event(request: TelemetryIngestRequest, db: Session = Depends(get_db)):
    result = process_payload(
        request.payload,
        db,
        source_hint=request.source_hint,
        raw_reference=request.raw_reference,
    )
    db.commit()
    response = {
        "event": event_to_dict(result["event"]),
        "detection": detection_to_dict(result["detection"]),
        "alert": alert_to_dict(result["alert"]) if result["alert"] else None,
        "incident": incident_to_dict(result["incident"]) if result["incident"] else None,
        "created": result["created"],
    }
    if result["alert"]:
        await manager.broadcast({"type": "alert.created", "alert": response["alert"]})
    if result["incident"]:
        await manager.broadcast({"type": "incident.updated", "incident": response["incident"]})
    return response


@app.get("/api/v1/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sensor_type: Optional[str] = None,
    protocol: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    db: Session = Depends(get_db),
):
    query = db.query(NormalizedEvent)
    if sensor_type:
        query = query.filter(NormalizedEvent.sensor_type == sensor_type)
    if protocol:
        query = query.filter(NormalizedEvent.protocol == protocol.upper())
    if source_ip:
        query = query.filter(NormalizedEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NormalizedEvent.destination_ip == destination_ip)
    if destination_port:
        query = query.filter(NormalizedEvent.destination_port == destination_port)
    if start:
        query = query.filter(NormalizedEvent.timestamp >= start)
    if end:
        query = query.filter(NormalizedEvent.timestamp <= end)
    total = query.count()
    rows = query.order_by(NormalizedEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [event_to_dict(row) for row in rows]}


@app.get("/api/v1/detections")
def list_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    detection_source: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Detection)
    if severity:
        query = query.filter(Detection.severity == severity)
    if classification:
        query = query.filter(Detection.classification == classification)
    if detection_source:
        query = query.filter(Detection.detection_source == detection_source)
    total = query.count()
    rows = query.order_by(Detection.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [detection_to_dict(row) for row in rows]}


@app.get("/api/v1/alerts")
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    classification: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    detection_source: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if classification:
        query = query.filter(Alert.classification == classification)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if destination_ip:
        query = query.filter(Alert.destination_ip == destination_ip)
    if detection_source:
        query = query.filter(Alert.detection_source == detection_source)
    if start:
        query = query.filter(Alert.timestamp >= start)
    if end:
        query = query.filter(Alert.timestamp <= end)
    rows = query.order_by(Alert.timestamp.desc()).all()
    if mitre_technique:
        rows = [row for row in rows if mitre_technique in (row.mitre_techniques or [])]
    total = len(rows)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [alert_to_dict(row) for row in rows[offset : offset + limit]],
    }


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert, include_detection=True)


@app.patch(
    "/api/v1/alerts/{alert_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER))],
)
async def update_alert(alert_id: int, request: AlertUpdateRequest, db: Session = Depends(get_db), user=Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER))):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    data = _dump_model(request)
    if data.get("status") and data["status"] not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(ALERT_STATUSES)}")
    if data.get("priority") and data["priority"] not in PRIORITIES:
        raise HTTPException(status_code=422, detail=f"priority must be one of {sorted(PRIORITIES)}")
    for field, value in data.items():
        if value is not None:
            setattr(alert, field, value)
    audit_event(db, "alert_updated", "alert", str(alert.id), data, user=user)
    db.commit()
    db.refresh(alert)
    payload = alert_to_dict(alert, include_detection=True)
    await manager.broadcast({"type": "alert.updated", "alert": payload})
    return payload


@app.get("/api/v1/incidents")
def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if classification:
        query = query.filter(Incident.classification == classification)
    total = query.count()
    rows = query.order_by(Incident.last_seen.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [incident_to_dict(row) for row in rows]}


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_to_dict(incident, include_alerts=True)


@app.patch(
    "/api/v1/incidents/{incident_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_RESPONDER))],
)
async def update_incident(
    incident_id: int,
    request: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN, ROLE_RESPONDER)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = _dump_model(request)
    if data.get("status") and data["status"] not in INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(INCIDENT_STATUSES)}")
    if data.get("priority") and data["priority"] not in PRIORITIES:
        raise HTTPException(status_code=422, detail=f"priority must be one of {sorted(PRIORITIES)}")
    for field, value in data.items():
        if value is not None:
            setattr(incident, field, value)
    audit_event(db, "incident_updated", "incident", str(incident.id), data, user=user)
    db.commit()
    db.refresh(incident)
    payload = incident_to_dict(incident, include_alerts=True)
    await manager.broadcast({"type": "incident.updated", "incident": payload})
    return payload


@app.get("/api/v1/metrics")
def metrics(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    false_positive = db.query(Alert).filter(Alert.status == "false_positive").count()
    alerts_by_severity = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
    top_attack_classes = dict(
        db.query(Alert.classification, func.count(Alert.id))
        .group_by(Alert.classification)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    active_incidents = db.query(Incident).filter(Incident.status.in_(["new", "triaged", "investigating", "contained"])).count()
    detections = db.query(Detection).all()
    detection_sources = {
        "hybrid": len(detections),
        "rules": sum(1 for detection in detections if detection.triggered_rules),
        "ml_model": sum(1 for detection in detections if (detection.confidence or 0) > 0),
        "anomaly": sum(1 for detection in detections if (detection.anomaly_score or 0) >= 0.6),
    }
    governance = _model_governance_status(db)
    return {
        "active_incidents": active_incidents,
        "total_alerts": total_alerts,
        "alerts_by_severity": alerts_by_severity,
        "top_attack_classes": top_attack_classes,
        "top_targeted_assets": dict(
            db.query(Alert.destination_ip, func.count(Alert.id))
            .filter(Alert.destination_ip.isnot(None))
            .group_by(Alert.destination_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
            .all()
        ),
        "detection_sources": detection_sources,
        "false_positive_rate": round(false_positive / total_alerts, 4) if total_alerts else 0.0,
        "model_monitoring": {
            "model": model_detector.status(),
            "anomaly": anomaly_detector.status(),
            "rules": rule_engine.status(),
            "prediction_distribution": top_attack_classes,
            "inference_latency_ms_latest": db.query(func.avg(Detection.latency_ms)).scalar() or 0.0,
            "drift": governance["drift"],
            "governance": governance,
        },
    }


@app.get("/api/v1/model/status")
def model_status(db: Session = Depends(get_db)):
    governance = _model_governance_status(db)
    return {
        "model": model_detector.status(),
        "anomaly": anomaly_detector.status(),
        "rules": rule_engine.status(),
        "governance": governance,
    }


@app.get("/api/v1/models", dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_AUDITOR))])
def list_model_versions(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    task: Optional[str] = None,
    db: Session = Depends(get_db),
):
    return list_models(db, limit=limit, offset=offset, task=task)


@app.get("/api/v1/models/active", dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_AUDITOR))])
def get_active_model(task: str = "network_detection", db: Session = Depends(get_db)):
    row = active_model(db, task=task)
    return {"item": model_version_to_public(row) if row else None}


@app.get("/api/v1/models/{version}", dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_AUDITOR))])
def get_model_version(version: str, db: Session = Depends(get_db)):
    row = db.query(ModelVersion).filter(ModelVersion.version == version).first()
    if not row:
        raise HTTPException(status_code=404, detail="Model version not found")
    return model_version_to_public(row)


@app.post("/api/v1/models/{version}/validate")
def validate_model_version(
    version: str,
    request: Optional[ModelValidationRequest] = None,
    db: Session = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    try:
        row = validate_registered_model(
            db,
            version,
            quality_gates=request.quality_gates if request else None,
            actor=user.username,
        )
        db.commit()
        db.refresh(row)
        return model_version_to_public(row)
    except GovernanceError as exc:
        _governance_http_error(db, exc)


@app.post("/api/v1/models/{version}/promote")
def promote_model_version(
    version: str,
    db: Session = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    try:
        row = promote_model(db, version, actor=user.username)
        db.commit()
        db.refresh(row)
        return model_version_to_public(row)
    except GovernanceError as exc:
        _governance_http_error(db, exc)


@app.post("/api/v1/models/{version}/archive")
def archive_model_version(
    version: str,
    db: Session = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    try:
        row = archive_model(db, version, actor=user.username)
        db.commit()
        db.refresh(row)
        return model_version_to_public(row)
    except GovernanceError as exc:
        _governance_http_error(db, exc)


@app.post(
    "/api/v1/threat-intel/lookup",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def threat_intel_lookup(request: ThreatIntelLookupRequest, db: Session = Depends(get_db)):
    return {
        "indicator": request.indicator,
        "indicator_type": request.indicator_type,
        "results": threat_intel_service.lookup(request.indicator, request.indicator_type, db=db),
        "external_enabled": settings.threat_intel_external_enabled,
    }


@app.get("/api/v1/audit-events", dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_AUDITOR))])
def list_audit_events(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    rows = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": db.query(AuditEvent).count(),
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": row.id,
                "username": row.username,
                "action": row.action,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "details": row.details,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }


@app.websocket("/api/v1/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    token = websocket.query_params.get("token")
    authorization = websocket.headers.get("authorization")
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        await websocket.close(code=1008)
        return

    db = SessionLocal()
    try:
        user = authenticate_token(db, token)
        if user.role not in ALL_ROLES:
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return
    finally:
        db.close()

    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "message": "Subscribed to alert and incident updates."})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
