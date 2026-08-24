"""Guardian v2 Phase 1 — Backend API endpoints.

Provides:
    POST /api/v1/guardian/agents/register   — Agent registration
    POST /api/v1/guardian/heartbeat         — Agent heartbeat
    POST /api/v1/guardian/events            — Event ingestion (batch)
    GET  /api/v1/guardian/events            — Event query (paginated)
    GET  /api/v1/guardian/agents            — List agents
    GET  /api/v1/guardian/agents/{id}       — Agent detail
    GET  /api/v1/guardian/stats             — Guardian statistics

All endpoints require authentication.
RBAC: admin, analyst, responder for writes; auditor for reads.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    audit_event,
    get_current_user,
    require_roles,
)
from .database import get_db
from .models import (
    GuardianAgent,
    GuardianEvent,
    GuardianHeartbeat,
    User,
    utcnow,
)
from guardian.detection.dispatcher import DetectionDispatcher

router = APIRouter(prefix="/api/v1/guardian", tags=["guardian"])

# ── Rate limiting for guardian endpoints ───────────────────────────────
from .auth import RateLimiter

guardian_rate_limiter = RateLimiter(120)  # 120 requests per minute


# ── Request / Response schemas ─────────────────────────────────────────


class AgentRegisterRequest(BaseModel):
    agent_key: str = Field(..., max_length=128)
    hostname: str = Field(..., max_length=255)
    host_id: Optional[str] = Field(None, max_length=128)
    os_name: Optional[str] = Field(None, max_length=128)
    os_version: Optional[str] = Field(None, max_length=128)
    agent_version: Optional[str] = Field(None, max_length=64)
    metadata: Optional[Dict[str, Any]] = None


class AgentHeartbeatRequest(BaseModel):
    agent_key: Optional[str] = Field(None, max_length=128)
    timestamp: Optional[float] = None
    agent_version: Optional[str] = None
    uptime_seconds: Optional[int] = None
    cpu_usage_pct: Optional[float] = None
    memory_usage_pct: Optional[float] = None
    events_queued: Optional[int] = None
    events_processed: Optional[int] = None
    detections_pending: Optional[int] = None
    queue_stats: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class GuardianEventIngestItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str = Field(..., max_length=128)
    schema_version: str = Field(default="guardian.event.v1", max_length=32)
    event_category: str = Field(default="process", max_length=32)
    timestamp: Any = None
    host_id: Optional[str] = None
    host_hostname: Optional[str] = None
    agent_version: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_exe_path: Optional[str] = None
    process_exe_hash_sha256: Optional[str] = None
    process_command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_pid: Optional[int] = None
    parent_process_exe_path: Optional[str] = None
    user_name: Optional[str] = None
    user_sid: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[float] = None
    bytes_received: Optional[float] = None
    file_path: Optional[str] = None
    file_operation: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    persistence_type: Optional[str] = None
    persistence_path: Optional[str] = None
    persistence_data: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    raw_event: Optional[Dict[str, Any]] = None


class GuardianEventIngestRequest(BaseModel):
    agent_key: Optional[str] = Field(None, max_length=128)
    events: List[GuardianEventIngestItem] = Field(..., max_length=1000)


class EventResult(BaseModel):
    event_id: str
    status: str  # "created" | "duplicate"


class GuardianEventIngestResponse(BaseModel):
    total: int
    created: int
    duplicate: int
    results: List[EventResult]


def _agent_to_dict(agent: GuardianAgent) -> Dict[str, Any]:
    return {
        "id": agent.id,
        "agent_key": agent.agent_key,
        "hostname": agent.hostname,
        "host_id": agent.host_id,
        "os_name": agent.os_name,
        "os_version": agent.os_version,
        "agent_version": agent.agent_version,
        "status": agent.status,
        "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
        "last_heartbeat_at": agent.last_heartbeat_at.isoformat() if agent.last_heartbeat_at else None,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


def _event_to_dict(event: GuardianEvent) -> Dict[str, Any]:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "schema_version": event.schema_version,
        "event_category": event.event_category,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ingestion_timestamp": event.ingestion_timestamp.isoformat() if event.ingestion_timestamp else None,
        "process_name": event.process_name,
        "process_pid": event.process_pid,
        "process_exe_path": event.process_exe_path,
        "process_exe_hash_sha256": event.process_exe_hash_sha256,
        "process_command_line": event.process_command_line,
        "parent_process_name": event.parent_process_name,
        "parent_process_pid": event.parent_process_pid,
        "parent_process_exe_path": event.parent_process_exe_path,
        "user_name": event.user_name,
        "user_sid": event.user_sid,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "bytes_sent": event.bytes_sent,
        "bytes_received": event.bytes_received,
        "file_path": event.file_path,
        "file_operation": event.file_operation,
        "file_hash_sha256": event.file_hash_sha256,
        "evidence": event.evidence,
        "status": event.status,
    }


# ── Agent Registration ────────────────────────────────────────────────


@router.post(
    "/agents/register",
    dependencies=[
        Depends(guardian_rate_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def register_agent(
    request: AgentRegisterRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Register a Guardian agent.

    Registration is idempotent: re-registering the same agent_key
    updates metadata and returns the existing agent.
    """
    existing = db.query(GuardianAgent).filter(
        GuardianAgent.agent_key == request.agent_key
    ).first()

    if existing:
        # Update existing agent
        existing.hostname = request.hostname
        if request.host_id:
            existing.host_id = request.host_id
        if request.os_name:
            existing.os_name = request.os_name
        if request.os_version:
            existing.os_version = request.os_version
        if request.agent_version:
            existing.agent_version = request.agent_version
        if request.metadata:
            existing.metadata_json = request.metadata
        existing.updated_at = utcnow()
        db.commit()
        db.refresh(existing)
        audit_event(db, "guardian_agent_reregistered", "guardian_agent", existing.agent_key, user=user)
        db.commit()
        return {"status": "registered", "agent": _agent_to_dict(existing)}

    # Create new agent
    agent = GuardianAgent(
        agent_key=request.agent_key,
        hostname=request.hostname,
        host_id=request.host_id,
        os_name=request.os_name,
        os_version=request.os_version,
        agent_version=request.agent_version,
        status="active",
        metadata_json=request.metadata or {},
    )
    db.add(agent)
    db.flush()
    audit_event(db, "guardian_agent_registered", "guardian_agent", agent.agent_key, user=user)
    db.commit()
    db.refresh(agent)
    return {"status": "registered", "agent": _agent_to_dict(agent)}


# ── Heartbeat ─────────────────────────────────────────────────────────


@router.post(
    "/heartbeat",
    dependencies=[
        Depends(guardian_rate_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def agent_heartbeat(
    request: AgentHeartbeatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Accept a heartbeat from the agent.

    The agent is identified by agent_key in the request body.
    Falls back to the most recently registered agent for backward compatibility.
    """
    agent = None
    if request.agent_key:
        agent = db.query(GuardianAgent).filter(
            GuardianAgent.agent_key == request.agent_key
        ).first()
    if agent is None:
        # Fallback: most recently registered agent
        agent = db.query(GuardianAgent).order_by(
            GuardianAgent.created_at.desc()
        ).first()

    if not agent:
        raise HTTPException(status_code=404, detail="No registered Guardian agent found")

    # Create heartbeat record
    heartbeat = GuardianHeartbeat(
        agent_id=agent.id,
        agent_version=request.agent_version or agent.agent_version,
        uptime_seconds=request.uptime_seconds,
        cpu_usage_pct=request.cpu_usage_pct,
        memory_usage_pct=request.memory_usage_pct,
        events_queued=request.events_queued or (request.queue_stats or {}).get("pending", 0),
        events_processed=request.events_processed or (request.queue_stats or {}).get("sent", 0),
        detections_pending=request.detections_pending,
        metadata_json={
            k: v for k, v in (request.metadata or {}).items()
            if k not in ("queue_stats",)
        },
    )
    db.add(heartbeat)

    # Update agent's last heartbeat
    agent.last_heartbeat_at = utcnow()
    if request.agent_version:
        agent.agent_version = request.agent_version

    db.commit()
    return {"status": "ok", "agent_id": agent.id}


# ── Event Ingestion ───────────────────────────────────────────────────


@router.post(
    "/events",
    response_model=GuardianEventIngestResponse,
    dependencies=[
        Depends(guardian_rate_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def ingest_guardian_events(
    request: GuardianEventIngestRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> GuardianEventIngestResponse:
    """Ingest a batch of Guardian events.

    Events are idempotent: duplicate event_ids are silently ignored.
    """
    if not request.events:
        raise HTTPException(status_code=422, detail="events list must not be empty")

    # Find the agent by agent_key if provided, else fallback to most recent
    agent = None
    if request.agent_key:
        agent = db.query(GuardianAgent).filter(
            GuardianAgent.agent_key == request.agent_key
        ).first()
    if agent is None:
        agent = db.query(GuardianAgent).order_by(
            GuardianAgent.created_at.desc()
        ).first()

    if not agent:
        raise HTTPException(status_code=404, detail="No registered Guardian agent found")

    results: List[EventResult] = []
    created_count = 0
    duplicate_count = 0

    for item in request.events:
        # Check for existing event
        existing = db.query(GuardianEvent).filter(
            GuardianEvent.event_id == item.event_id
        ).first()

        if existing:
            results.append(EventResult(event_id=item.event_id, status="duplicate"))
            duplicate_count += 1
            continue

        # Parse timestamp
        timestamp = utcnow()
        if item.timestamp:
            if isinstance(item.timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(
                        item.timestamp.replace("Z", "+00:00")
                    ).replace(tzinfo=None)
                except (ValueError, TypeError):
                    timestamp = utcnow()
            elif isinstance(item.timestamp, (int, float)):
                try:
                    timestamp = datetime.fromtimestamp(
                        float(item.timestamp), tz=timezone.utc
                    ).replace(tzinfo=None)
                except (ValueError, OSError):
                    timestamp = utcnow()

        event = GuardianEvent(
            event_id=item.event_id,
            schema_version=item.schema_version,
            agent_id=agent.id,
            event_category=item.event_category,
            timestamp=timestamp,
            process_name=item.process_name,
            process_pid=item.process_pid,
            process_exe_path=item.process_exe_path,
            process_exe_hash_sha256=item.process_exe_hash_sha256,
            process_command_line=item.process_command_line,
            parent_process_name=item.parent_process_name,
            parent_process_pid=item.parent_process_pid,
            parent_process_exe_path=item.parent_process_exe_path,
            user_name=item.user_name,
            user_sid=item.user_sid,
            source_ip=item.source_ip,
            source_port=item.source_port,
            destination_ip=item.destination_ip,
            destination_port=item.destination_port,
            protocol=item.protocol,
            bytes_sent=item.bytes_sent,
            bytes_received=item.bytes_received,
            file_path=item.file_path,
            file_operation=item.file_operation,
            file_hash_sha256=item.file_hash_sha256,
            persistence_type=item.persistence_type,
            persistence_path=item.persistence_path,
            persistence_data=item.persistence_data,
            evidence=item.evidence or {},
            raw_event=item.raw_event or {},
            status="ingested",
        )
        db.add(event)
        results.append(EventResult(event_id=item.event_id, status="created"))
        created_count += 1

    db.commit()

    # ── Detection pipeline dispatch ────────────────────────────────
    dispatcher = DetectionDispatcher()
    for item in request.events:
        if item.event_id not in [r.event_id for r in results if r.status == "created"]:
            continue
        # Build event dict for the dispatcher
        event_row = db.query(GuardianEvent).filter(
            GuardianEvent.event_id == item.event_id
        ).first()
        if event_row:
            event_dict = {
                "event_id": event_row.event_id,
                "event_category": event_row.event_category,
                "host_id": str(event_row.agent_id),
                "process_name": event_row.process_name,
                "process_pid": event_row.process_pid,
                "process_exe_path": event_row.process_exe_path,
                "process_exe_hash_sha256": event_row.process_exe_hash_sha256,
                "process_command_line": event_row.process_command_line,
                "parent_process_name": event_row.parent_process_name,
                "parent_process_pid": event_row.parent_process_pid,
                "parent_process_exe_path": event_row.parent_process_exe_path,
                "user_name": event_row.user_name,
                "source_ip": event_row.source_ip,
                "source_port": event_row.source_port,
                "destination_ip": event_row.destination_ip,
                "destination_port": event_row.destination_port,
                "protocol": event_row.protocol,
                "file_path": event_row.file_path,
                "file_operation": event_row.file_operation,
                "persistence_type": event_row.persistence_type,
                "persistence_path": event_row.persistence_path,
                "persistence_data": event_row.persistence_data,
                "evidence": event_row.evidence or {},
            }
            try:
                dispatcher.dispatch(db, event_dict)
            except Exception:
                # Pipeline failure must not break ingestion
                logger.error("Detection pipeline failed for event %s", item.event_id, exc_info=True)

    return GuardianEventIngestResponse(
        total=len(request.events),
        created=created_count,
        duplicate=duplicate_count,
        results=results,
    )


# ── Event Query ───────────────────────────────────────────────────────


@router.get(
    "/events",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def list_guardian_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_category: Optional[str] = None,
    agent_id: Optional[int] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Query Guardian events with pagination and filtering."""
    query = db.query(GuardianEvent)
    if event_category:
        query = query.filter(GuardianEvent.event_category == event_category)
    if agent_id:
        query = query.filter(GuardianEvent.agent_id == agent_id)
    if start:
        query = query.filter(GuardianEvent.timestamp >= start)
    if end:
        query = query.filter(GuardianEvent.timestamp <= end)

    total = query.count()
    rows = query.order_by(GuardianEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_event_to_dict(row) for row in rows],
    }


# ── Agent List / Detail ───────────────────────────────────────────────


@router.get(
    "/agents",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def list_agents(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List all registered Guardian agents."""
    agents = db.query(GuardianAgent).order_by(GuardianAgent.created_at.desc()).all()
    return {
        "total": len(agents),
        "items": [_agent_to_dict(a) for a in agents],
    }


@router.get(
    "/agents/{agent_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def get_agent(
    agent_id: int,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get details for a specific Guardian agent."""
    agent = db.query(GuardianAgent).filter(GuardianAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Guardian agent not found")
    return _agent_to_dict(agent)


# ── Statistics ────────────────────────────────────────────────────────


@router.get(
    "/stats",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def guardian_stats(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return Guardian Phase 1 statistics."""
    agent_count = db.query(GuardianAgent).count()
    active_agents = db.query(GuardianAgent).filter(
        GuardianAgent.status == "active"
    ).count()
    event_count = db.query(GuardianEvent).count()
    events_by_category = dict(
        db.query(GuardianEvent.event_category, func.count(GuardianEvent.id))
        .group_by(GuardianEvent.event_category)
        .all()
    )
    heartbeat_count = db.query(GuardianHeartbeat).count()

    return {
        "agents": {"total": agent_count, "active": active_agents},
        "events": {"total": event_count, "by_category": events_by_category},
        "heartbeats": {"total": heartbeat_count},
    }
