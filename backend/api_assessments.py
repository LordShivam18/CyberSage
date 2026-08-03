import hashlib
import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

from .auth import ROLE_ADMIN, ROLE_ANALYST, get_current_user, require_roles, audit_event
from .database import get_db
from .models import AssessmentFinding, AssessmentRun, User, Alert, utcnow
from .schemas import AssessmentImportRequest

from shared.report_contract import (
    MAX_REPORT_SIZE_BYTES,
    verify_checksum,
    compute_coverage,
    compute_posture_score,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])

@router.post("/import")
async def import_assessment(
    raw_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST)),
):
    # 1. Raw HTTP request-size enforcement before parsing
    content_length = raw_request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")
    
    body = await raw_request.body()
    if len(body) > MAX_REPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")

    # 2. Strict validation of decoded report structure
    try:
        request = AssessmentImportRequest.model_validate_json(body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=f"Structural validation failed: {str(e)}")
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON payload")

    report_dict = request.report.model_dump(mode='json')
    assessment_id = request.report.assessment_id

    # 3. Canonical checksum verification
    if not verify_checksum(report_dict):
        raise HTTPException(status_code=422, detail="Report checksum verification failed")

    # 4. Independent posture score and coverage recomputation
    findings_dicts = [f.model_dump(mode='json') for f in request.report.findings]
    
    expected_coverage = compute_coverage(
        request.report.coverage.attempted,
        request.report.coverage.unavailable,
        request.report.coverage.permission_required,
        request.report.coverage.errors
    )
    if expected_coverage != request.report.coverage.coverage_pct:
        raise HTTPException(status_code=422, detail="Tampered coverage detected")

    expected_score = compute_posture_score(findings_dicts)
    if expected_score["score"] != request.report.posture_score.score:
        raise HTTPException(status_code=422, detail="Tampered posture score detected")

    # 5. Idempotency and Conflict Check BEFORE creating rows
    existing_run = db.query(AssessmentRun).filter(AssessmentRun.assessment_id == assessment_id).first()
    if existing_run:
        if existing_run.report_checksum != request.report.checksum:
            raise HTTPException(status_code=409, detail="Assessment conflict: different checksum")
        return {
            "status": "success", 
            "message": "Assessment already imported", 
            "assessment_id": assessment_id, 
            "id": existing_run.id
        }

    # Transactional DB Insert
    try:
        run = AssessmentRun(
            assessment_id=assessment_id,
            scanner_version=request.report.scanner_version,
            schema_version=request.report.schema_version,
            score_algorithm=request.report.score_algorithm,
            privacy_mode=request.report.privacy_mode,
            privilege_level=request.report.privilege_level,
            started_at=request.report.started_at,
            completed_at=request.report.completed_at,
            imported_by=current_user.username,
            host_hostname=request.report.host.hostname,
            host_os_name=request.report.host.os_name,
            host_os_version=request.report.host.os_version,
            host_os_build=request.report.host.os_build,
            host_architecture=request.report.host.architecture,
            checks_attempted=request.report.checks_attempted,
            coverage_pct=request.report.coverage.coverage_pct,
            coverage_failed=request.report.coverage.failed,
            coverage_unavailable=request.report.coverage.unavailable,
            coverage_permission_required=request.report.coverage.permission_required,
            coverage_errors=request.report.coverage.errors,
            posture_score=request.report.posture_score.score,
            posture_score_components=request.report.posture_score.components,
            posture_score_caveat=request.report.posture_score.caveat,
            report_checksum=request.report.checksum,
            report_checksum_algorithm=request.report.checksum_algorithm,
            checksum_verified=True,
            full_report=report_dict
        )
        
        db.add(run)
        db.flush()

        can_create_alerts = request.create_alerts and current_user.role in [ROLE_ADMIN, ROLE_ANALYST]
        alerts_created = 0

        for f in request.report.findings:
            finding = AssessmentFinding(
                assessment_run_id=run.id,
                check_id=f.check_id,
                finding_id=f.finding_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                confidence=f.confidence,
                status=f.status,
                evidence=f.evidence,
                explanation=f.explanation,
                remediation=f.remediation,
                device_impact=f.device_impact,
                admin_required=f.admin_required,
                may_disrupt=f.may_disrupt,
                references_json=f.references,
                collected_at=f.collected_at,
                collector_version=f.collector_version
            )
            db.add(finding)
            
            # Synthesize alert
            if can_create_alerts and finding.status == "fail" and finding.severity in ["high", "critical"]:
                alert_key = f"portable_assessment_{run.assessment_id}_{finding.finding_id}"
                existing_alert = db.query(Alert).filter(Alert.alert_key == alert_key).first()
                if not existing_alert:
                    alert = Alert(
                        timestamp=utcnow(),
                        prediction=finding.title,
                        probability=1.0 if finding.confidence == "high" else 0.5,
                        details=finding.explanation or finding.title,
                        alert_key=alert_key,
                        status="new",
                        severity=finding.severity,
                        classification=finding.category,
                        confidence=1.0 if finding.confidence == "high" else 0.5,
                        detection_source="portable_assessment",
                        raw_evidence_reference=f"Assessment {run.assessment_id}",
                        priority="high" if finding.severity == "critical" else "medium"
                    )
                    db.add(alert)
                    alerts_created += 1

        db.commit()

        audit_event(
            db=db,
            action="assessment_imported",
            target_type="assessment",
            target_id=assessment_id,
            details={"findings_imported": len(request.report.findings), "alerts_created": alerts_created},
            user=current_user,
        )

    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Assessment conflict: database constraint violation")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to import assessment: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during import transaction")

    return {
        "status": "success", 
        "message": "Assessment imported successfully",
        "assessment_id": run.assessment_id,
        "id": run.id,
        "findings_imported": len(request.report.findings),
        "alerts_created": alerts_created
    }

@router.get("/")
def list_assessments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    runs = db.query(AssessmentRun).order_by(AssessmentRun.imported_at.desc()).limit(100).all()
    return [{
        "id": run.id,
        "assessment_id": run.assessment_id,
        "imported_at": run.imported_at,
        "hostname": run.host_hostname,
        "score": run.posture_score,
        "coverage": run.coverage_pct,
        "privacy_mode": run.privacy_mode
    } for run in runs]

@router.get("/{assessment_id}")
def get_assessment(assessment_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(AssessmentRun).filter(AssessmentRun.assessment_id == assessment_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    findings = db.query(AssessmentFinding).filter(AssessmentFinding.assessment_run_id == run.id).all()
    
    return {
        "id": run.id,
        "assessment_id": run.assessment_id,
        "scanner_version": run.scanner_version,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "imported_at": run.imported_at,
        "imported_by": run.imported_by,
        "host": {
            "hostname": run.host_hostname,
            "os_name": run.host_os_name,
            "os_version": run.host_os_version,
            "os_build": run.host_os_build,
            "architecture": run.host_architecture
        },
        "score": run.posture_score,
        "coverage": run.coverage_pct,
        "privacy_mode": run.privacy_mode,
        "findings": [{
            "check_id": f.check_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "status": f.status,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "admin_required": f.admin_required,
            "evidence": f.evidence
        } for f in findings]
    }
