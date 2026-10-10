"""Pilot configuration schema and validation (explicit, no enrollment).

A pilot configuration names objectives, scope, owner, duration, endpoint
inventory, eligible operating systems, modes, baseline period, workloads,
test scenarios, exclusions, change control, contacts, evidence rules, and
stop conditions. The default inventory is EMPTY: writing a config never
enrolls or alters an endpoint.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

PILOT_SCHEMA_VERSION = 1

PILOT_MODES = ("monitoring", "approved_manual")
FUTURE_PREAUTH_MODE = "bounded_preauth_future"

SUPPORTED_OS = ("Windows 10", "Windows 11", "Windows Server 2016",
                "Windows Server 2019", "Windows Server 2022")

PROHIBITED_ACTIONS = (
    "production enrollment",
    "unrestricted execution",
    "global autonomy",
    "destructive testing on non-disposable hosts",
)


@dataclass
class PilotConfig:
    objectives: List[str] = field(default_factory=list)
    scope: str = ""
    owner: str = ""
    duration_days: int = 14
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    eligible_os: List[str] = field(default_factory=list)
    modes: List[str] = field(default_factory=lambda: ["monitoring"])
    baseline_days: int = 7
    benign_workloads: List[str] = field(default_factory=list)
    test_scenarios: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    change_control: str = ""
    operator_responsibilities: List[str] = field(default_factory=list)
    escalation_contacts: List[str] = field(default_factory=list)
    evidence_rules: List[str] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    schema_version: int = PILOT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_pilot_config(data: Dict[str, Any]) -> PilotConfig:
    """Validate a pilot configuration dict. Fail closed on any gap."""
    if not isinstance(data, dict):
        raise ValueError("Pilot config must be an object")
    if data.get("schema_version", 1) != PILOT_SCHEMA_VERSION:
        raise ValueError(f"Unsupported pilot schema_version (want {PILOT_SCHEMA_VERSION})")
    for field_name in ("objectives", "scope", "owner", "change_control"):
        if not data.get(field_name):
            raise ValueError(f"Pilot config requires '{field_name}'")
    duration = data.get("duration_days", 14)
    if not isinstance(duration, int) or not 1 <= duration <= 90:
        raise ValueError("duration_days must be an integer 1-90")
    baseline = data.get("baseline_days", 7)
    if not isinstance(baseline, int) or not 1 <= baseline <= duration:
        raise ValueError("baseline_days must be an integer within duration_days")
    modes = data.get("modes", ["monitoring"])
    if not isinstance(modes, list) or not modes:
        raise ValueError("modes must be a non-empty list")
    for mode in modes:
        if mode not in PILOT_MODES:
            raise ValueError(
                f"Pilot mode {mode!r} is not permitted for this pilot. "
                f"Allowed: {list(PILOT_MODES)}. "
                f"{FUTURE_PREAUTH_MODE!r} requires a separate future authorization.")
    for endpoint in data.get("endpoints", []):
        if not isinstance(endpoint, dict) or not endpoint.get("hostname") or not endpoint.get("os"):
            raise ValueError("Each endpoint needs hostname and os")
        if endpoint["os"] not in SUPPORTED_OS:
            raise ValueError(f"Unsupported endpoint OS: {endpoint['os']!r}")
    if not data.get("stop_conditions"):
        raise ValueError("Pilot config requires explicit stop_conditions")
    if not data.get("benign_workloads"):
        raise ValueError("Pilot config requires known-good benign workloads")
    kwargs = {key: data.get(key, default) for key, default in (
        ("objectives", []), ("scope", ""), ("owner", ""), ("duration_days", 14),
        ("endpoints", []), ("eligible_os", []), ("modes", ["monitoring"]),
        ("baseline_days", 7), ("benign_workloads", []), ("test_scenarios", []),
        ("exclusions", []), ("change_control", ""), ("operator_responsibilities", []),
        ("escalation_contacts", []), ("evidence_rules", []), ("stop_conditions", []))}
    kwargs["schema_version"] = PILOT_SCHEMA_VERSION
    return PilotConfig(**kwargs)


def default_pilot_config() -> Dict[str, Any]:
    """Blank template: no endpoints enrolled, monitoring only."""
    return {
        "objectives": [], "scope": "", "owner": "", "duration_days": 14,
        "endpoints": [], "eligible_os": list(SUPPORTED_OS), "modes": ["monitoring"],
        "baseline_days": 7, "benign_workloads": [], "test_scenarios": [],
        "exclusions": list(PROHIBITED_ACTIONS), "change_control": "",
        "operator_responsibilities": [], "escalation_contacts": [],
        "evidence_rules": [], "stop_conditions": [], "schema_version": PILOT_SCHEMA_VERSION,
    }
