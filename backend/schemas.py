from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class NetworkFlow(BaseModel):
    flow_duration: float
    tot_fwd_pkts: float
    tot_bwd_pkts: float
    totlen_fwd_pkts: float
    fwd_pkt_len_max: float
    fwd_pkt_len_min: float
    fwd_pkt_len_mean: float
    bwd_pkt_len_max: float
    flow_iat_mean: float
    flow_iat_max: float
    fwd_iat_tot: float


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    prediction: str
    probability: float
    details: str

class TelemetryIngestRequest(BaseModel):
    payload: dict
    source_hint: Optional[str] = None
    raw_reference: Optional[str] = None


class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    priority: Optional[str] = None
    analyst_notes: Optional[str] = None
    resolution_reason: Optional[str] = None


class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    priority: Optional[str] = None
    analyst_notes: Optional[str] = None
    resolution_reason: Optional[str] = None


class ThreatIntelLookupRequest(BaseModel):
    indicator: str
    indicator_type: str = "ip"


class ModelValidationRequest(BaseModel):
    quality_gates: Optional[dict] = None

from pydantic import BaseModel, ConfigDict, Field
from typing import Any, Dict, List, Optional
import sys
import os

try:
    from shared.report_contract import (
        MAX_ASSESSMENT_ID_LEN,
        MAX_FINDING_ID_LEN,
        MAX_CHECK_ID_LEN,
        MAX_LABEL_LEN,
        MAX_TITLE_LEN,
        MAX_EXPLANATION_LEN,
        MAX_REMEDIATION_LEN,
        MAX_FINDINGS,
        MAX_EVIDENCE_KEYS,
        MAX_EVIDENCE_KEY_LEN,
        MAX_EVIDENCE_VAL_LEN,
        SUPPORTED_SCHEMA_VERSIONS,
        SUPPORTED_CHECKSUM_ALGORITHMS
    )
except ImportError:
    # Handle the case where we run from backend root vs repo root
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from shared.report_contract import (
        MAX_ASSESSMENT_ID_LEN,
        MAX_FINDING_ID_LEN,
        MAX_CHECK_ID_LEN,
        MAX_LABEL_LEN,
        MAX_TITLE_LEN,
        MAX_EXPLANATION_LEN,
        MAX_REMEDIATION_LEN,
        MAX_FINDINGS,
        MAX_EVIDENCE_KEYS,
        MAX_EVIDENCE_KEY_LEN,
        MAX_EVIDENCE_VAL_LEN,
        SUPPORTED_SCHEMA_VERSIONS,
        SUPPORTED_CHECKSUM_ALGORITHMS
    )


class StrictEvidenceDict(BaseModel):
    model_config = ConfigDict(extra='forbid')
    # Actually Pydantic v2 allows validating dict keys/values with RootModel or Dict.
    # We will just define a generic structure and validate it later or rely on strict dict bounds.
    pass


class ReportHost(BaseModel):
    model_config = ConfigDict(extra='forbid')
    hostname: str = Field(..., max_length=MAX_LABEL_LEN)
    os_name: str = Field(..., max_length=MAX_LABEL_LEN)
    os_version: str = Field(..., max_length=MAX_LABEL_LEN)
    os_build: str = Field(..., max_length=MAX_LABEL_LEN)
    architecture: str = Field(..., max_length=MAX_LABEL_LEN)


class ReportCoverage(BaseModel):
    model_config = ConfigDict(extra='forbid')
    attempted: int = Field(..., ge=0)
    passed: int = Field(..., ge=0)
    failed: int = Field(..., ge=0)
    warned: int = Field(..., ge=0)
    unavailable: int = Field(..., ge=0)
    permission_required: int = Field(..., ge=0)
    errors: int = Field(..., ge=0)
    coverage_pct: float = Field(..., ge=0.0, le=100.0)


class ReportPostureScore(BaseModel):
    model_config = ConfigDict(extra='forbid')
    score: int = Field(..., ge=0, le=100)
    algorithm: str = Field(..., max_length=128)
    caveat: str = Field(..., max_length=1024)
    components: Dict[str, int] = Field(..., max_length=50)


class ReportFinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    check_id: str = Field(..., max_length=MAX_CHECK_ID_LEN)
    finding_id: str = Field(..., max_length=MAX_FINDING_ID_LEN)
    title: str = Field(..., max_length=MAX_TITLE_LEN)
    category: str = Field(..., pattern="^(operating_system|security_controls|accounts|processes|persistence|network|browser|certificates|other)$")
    severity: str = Field(..., pattern="^(critical|high|medium|low|informational)$")
    confidence: str = Field(..., pattern="^(high|medium|low)$")
    status: str = Field(..., pattern="^(pass|informational|warning|fail|unavailable|permission_required|error)$")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(..., max_length=MAX_EXPLANATION_LEN)
    remediation: str = Field(..., max_length=MAX_REMEDIATION_LEN)
    device_impact: str = Field(..., max_length=MAX_EXPLANATION_LEN)
    admin_required: bool
    may_disrupt: bool
    references: List[str] = Field(default_factory=list, max_length=20)
    collected_at: str = Field(..., max_length=64)
    collector_version: str = Field(..., max_length=64)


class AssessmentReport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: str = Field(..., pattern="^assessment.v1$")
    assessment_id: str = Field(..., max_length=MAX_ASSESSMENT_ID_LEN)
    scanner_version: str = Field(..., max_length=MAX_LABEL_LEN)
    score_algorithm: str = Field(..., max_length=128)
    privacy_mode: str = Field(..., pattern="^(standard|redacted|minimal)$")
    started_at: str = Field(..., max_length=64)
    completed_at: str = Field(..., max_length=64)
    host: ReportHost
    privilege_level: str = Field(..., max_length=64)
    checks_attempted: int = Field(..., ge=0)
    coverage: ReportCoverage
    posture_score: ReportPostureScore
    findings: List[ReportFinding] = Field(..., max_length=MAX_FINDINGS)
    checksum_algorithm: str = Field(..., pattern="^sha256$")
    checksum: str = Field(..., max_length=128)


class AssessmentImportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    report: AssessmentReport
    create_alerts: bool = False
