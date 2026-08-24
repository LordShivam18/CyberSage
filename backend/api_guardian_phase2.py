"""Guardian v2 Phase 2 — Backend API endpoints.

Provides:
    GET  /api/v1/guardian/detections          — List detections
    GET  /api/v1/guardian/detections/{id}     — Get detection detail
    GET  /api/v1/guardian/incidents           — List incidents
    GET  /api/v1/guardian/incidents/{id}      — Get incident detail
    GET  /api/v1/guardian/risk/{incident_id}  — Get risk explanation
    GET  /api/v1/guardian/policy/{incident_id} — Get response recommendation

All endpoints require authentication.
RBAC: admin, analyst, responder, auditor for reads.

No endpoint may execute an action.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    get_current_user,
    require_roles,
)
from .database import get_db
from .models import (
    GuardianDetection,
    GuardianIncident,
    GuardianResponseDecision,
    GuardianRiskScore,
    User,
    utcnow,
)

router = APIRouter(prefix="/api/v1/guardian", tags=["guardian-phase2"])

# ── Rate limiting ──────────────────────────────────────────────────────
from .auth import RateLimiter

guardian_read_limiter = RateLimiter(200)  # 200 reads per minute


# ── Serialization helpers ──────────────────────────────────────────────


def _detection_to_dict(det: GuardianDetection) -> Dict[str, Any]:
    return {
        "id": det.id,
        "detection_id": det.detection_id,
        "event_id": det.event_id,
        "detector_id": det.detector_id,
        "severity": det.severity,
        "confidence": det.confidence,
        "title": det.title,
        "description": det.description,
        "evidence": det.evidence,
        "mitre_technique": det.mitre_technique,
        "mitre_tactic": det.mitre_tactic,
        "created_at": det.created_at.isoformat() if det.created_at else None,
    }


def _incident_to_dict(inc: GuardianIncident) -> Dict[str, Any]:
    return {
        "id": inc.id,
        "candidate_id": inc.candidate_id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "confidence": inc.confidence,
        "status": inc.status,
        "evidence_ids": inc.evidence_ids,
        "event_ids": inc.event_ids,
        "host_ids": inc.host_ids,
        "mitre_techniques": inc.mitre_techniques,
        "mitre_tactics": inc.mitre_tactics,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
    }


def _risk_to_dict(risk: GuardianRiskScore) -> Dict[str, Any]:
    return {
        "id": risk.id,
        "score": risk.score,
        "severity": risk.severity,
        "confidence": risk.confidence,
        "factors": risk.factors,
        "explanation": risk.explanation,
        "detection_ids": risk.detection_ids,
        "incident_id": risk.incident_id,
        "created_at": risk.created_at.isoformat() if risk.created_at else None,
    }


def _decision_to_dict(dec: GuardianResponseDecision) -> Dict[str, Any]:
    return {
        "id": dec.id,
        "decision_id": dec.decision_id,
        "incident_id": dec.incident_id,
        "severity": dec.severity,
        "confidence": dec.confidence,
        "recommended_action": dec.recommended_action,
        "rationale": dec.rationale,
        "evidence": dec.evidence,
        "expected_effect": dec.expected_effect,
        "risk": dec.risk,
        "requires_approval": dec.requires_approval,
        "rollback_available": dec.rollback_available,
        "verification_plan": dec.verification_plan,
        "created_at": dec.created_at.isoformat() if dec.created_at else None,
    }


# ── Detections ─────────────────────────────────────────────────────────


@router.get(
    "/detections",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def list_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    detector_id: Optional[str] = None,
    event_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List Guardian detections with pagination and filtering."""
    query = db.query(GuardianDetection)
    if severity:
        query = query.filter(GuardianDetection.severity == severity)
    if detector_id:
        query = query.filter(GuardianDetection.detector_id == detector_id)
    if event_id:
        query = query.filter(GuardianDetection.event_id == event_id)

    total = query.count()
    rows = query.order_by(GuardianDetection.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_detection_to_dict(row) for row in rows],
    }


@router.get(
    "/detections/{detection_id}",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_detection(
    detection_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get details for a specific Guardian detection."""
    det = db.query(GuardianDetection).filter(
        GuardianDetection.detection_id == detection_id
    ).first()
    if not det:
        raise HTTPException(status_code=404, detail="Guardian detection not found")
    return _detection_to_dict(det)


# ── Incidents ──────────────────────────────────────────────────────────


@router.get(
    "/incidents",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List Guardian incidents with pagination and filtering."""
    query = db.query(GuardianIncident)
    if severity:
        query = query.filter(GuardianIncident.severity == severity)
    if status:
        query = query.filter(GuardianIncident.status == status)

    total = query.count()
    rows = query.order_by(GuardianIncident.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_incident_to_dict(row) for row in rows],
    }


@router.get(
    "/incidents/{candidate_id}",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_incident(
    candidate_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get details for a specific Guardian incident."""
    inc = db.query(GuardianIncident).filter(
        GuardianIncident.candidate_id == candidate_id
    ).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Guardian incident not found")
    return _incident_to_dict(inc)


# ── Risk ───────────────────────────────────────────────────────────────


@router.get(
    "/risk/{incident_id}",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_risk(
    incident_id: int,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get risk explanation for an incident."""
    risk = db.query(GuardianRiskScore).filter(
        GuardianRiskScore.incident_id == incident_id
    ).order_by(GuardianRiskScore.created_at.desc()).first()
    if not risk:
        raise HTTPException(status_code=404, detail="No risk score found for this incident")
    return _risk_to_dict(risk)


# ── Policy ─────────────────────────────────────────────────────────────


@router.get(
    "/policy/{incident_id}",
    dependencies=[
        Depends(guardian_read_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_response_recommendation(
    incident_id: int,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get response recommendation for an incident."""
    decision = db.query(GuardianResponseDecision).filter(
        GuardianResponseDecision.incident_id == incident_id
    ).order_by(GuardianResponseDecision.created_at.desc()).first()
    if not decision:
        raise HTTPException(status_code=404, detail="No response recommendation found for this incident")
    return _decision_to_dict(decision)
