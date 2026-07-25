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
