"""Phase 7 deterministic validation corpus (grounded in real detectors).

Every scenario names the detectors, severities, and policy behavior it
exercises. Nothing here invents detector capabilities: names, ports,
parent/child pairs, and persistence paths mirror
guardian/detectors/{process,network,persistence}_detectors.py.

Benign cases assert false-positive boundaries (what must NOT happen).
Suspicious cases use deliberately benign-but-matching fixtures (e.g. a
test file named mimikatz.exe in an isolated temp dir, a loopback-safe
documentation IP, a non-privileged test port) so the corpus never
touches production systems.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Scenario inventory. scenario_id values are stable correlation keys:
# e2e-<slug>. Fixture events carry the scenario id in evidence so the
# backend path (detections/incidents/evaluations/executions/audit) can be
# correlated per scenario.
SCENARIOS: List[Dict[str, Any]] = [
    {
        "scenario_id": "e2e-benign-process",
        "kind": "benign",
        "description": "Ordinary notepad.exe launch from System32 with benign parent.",
        "event": {
            "event_category": "process", "process_name": "notepad.exe",
            "process_exe_path": "C:\\Windows\\System32\\notepad.exe",
            "parent_process_name": "explorer.exe",
            "user_name": "test-user", "host_id": "host-e2e",
        },
        "expected": {
            "detections": [], "incident": False, "risk": "low (0-20)",
            "policy": "require_approval default (no match)", "execution": "not permitted",
            "must_not_happen": ["suspicious_process detection", "incident", "approval", "execution"],
        },
    },
    {
        "scenario_id": "e2e-benign-parent-child",
        "kind": "benign",
        "description": "Expected explorer.exe -> notepad.exe relationship.",
        "event": {
            "event_category": "process", "process_name": "notepad.exe",
            "parent_process_name": "explorer.exe", "host_id": "host-e2e",
        },
        "expected": {
            "detections": [], "incident": False, "policy": "require_approval default",
            "execution": "not permitted",
            "must_not_happen": ["suspicious_parent_child detection", "incident", "execution"],
        },
    },
    {
        "scenario_id": "e2e-benign-location",
        "kind": "benign",
        "description": "Known benign executable in its expected location.",
        "event": {
            "event_category": "process", "process_name": "svchost.exe",
            "process_exe_path": "C:\\Windows\\System32\\svchost.exe", "host_id": "host-e2e",
        },
        "expected": {
            "detections": [], "incident": False,
            "must_not_happen": ["unusual location detection", "incident", "execution"],
        },
    },
    {
        "scenario_id": "e2e-suspicious-process",
        "kind": "suspicious",
        "description": "Benign fixture matching SuspiciousProcessDetector (mimikatz name).",
        "event": {
            "event_category": "process", "process_name": "mimikatz.exe",
            "process_exe_path": "C:\\isolated\\mimikatz.exe", "user_name": "test-user",
            "host_id": "host-e2e",
        },
        "expected": {
            "detections": ["suspicious_process"], "severity": "high", "confidence": 0.9,
            "mitre": "T1059", "incident": "candidate when >= 2 detections aggregated",
            "risk": "elevated (severity high base 70 + bonuses)",
            "policy": "depends on persisted v5 policy; high risk does NOT imply authorization",
            "execution": "approval-required unless an eligible bounded grant exists",
        },
    },
    {
        "scenario_id": "e2e-suspicious-parent-child",
        "kind": "suspicious",
        "description": "svchost.exe -> cmd.exe (SUSPICIOUS_PARENT_CHILD).",
        "event": {
            "event_category": "process", "process_name": "cmd.exe",
            "parent_process_name": "svchost.exe", "host_id": "host-e2e",
        },
        "expected": {
            "detections": ["suspicious_parent_child"], "severity": "high", "confidence": 0.85,
            "execution": "approval-required unless bounded grant",
        },
    },
    {
        "scenario_id": "e2e-suspicious-port",
        "kind": "suspicious",
        "description": "Outbound connection to documentation IP on backdoor port 4444.",
        "event": {
            "event_category": "network", "destination_ip": "203.0.113.66",
            "destination_port": 4444, "protocol": "TCP", "host_id": "host-e2e",
        },
        "expected": {
            "detections": ["suspicious_port"], "severity": "high", "mitre": "T1571",
            "execution": "approval-required unless bounded grant",
        },
    },
    {
        "scenario_id": "e2e-persistence-run-key",
        "kind": "suspicious",
        "description": "Run-key persistence modification (supported type + path).",
        "event": {
            "event_category": "persistence", "persistence_type": "registry_run_key",
            "persistence_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\IsolatedTest",
            "host_id": "host-e2e",
        },
        "expected": {
            "detections": ["persistence_modification"], "severity": "high",
            "execution": "approval-required unless bounded grant",
        },
    },
    {
        "scenario_id": "e2e-malformed-missing-fields",
        "kind": "boundary",
        "description": "Event with missing optional attributes and empty names.",
        "event": {"event_category": "process", "host_id": "host-e2e"},
        "expected": {
            "detections": [], "incident": False,
            "must_not_happen": ["detection", "incident", "execution", "pipeline corruption"],
        },
    },
    {
        "scenario_id": "e2e-duplicate-event",
        "kind": "boundary",
        "description": "Same event_id submitted twice in different batches.",
        "event": {
            "event_category": "process", "process_name": "mimikatz.exe", "host_id": "host-e2e",
        },
        "expected": {
            "detections": "idempotent (same detection_id, no duplicate rows)",
            "incident": "no duplicate incident rows",
            "execution": "replay returns the original record without repeating the side effect",
        },
    },
    {
        "scenario_id": "e2e-benign-port-boundary",
        "kind": "boundary",
        "description": "Outbound HTTPS to documentation IP on benign port 443.",
        "event": {
            "event_category": "network", "destination_ip": "203.0.113.66",
            "destination_port": 443, "protocol": "TCP", "host_id": "host-e2e",
        },
        "expected": {
            "detections": [], "incident": False,
            "must_not_happen": ["suspicious_port detection", "incident", "execution"],
        },
    },
]


def get_scenario(scenario_id: str) -> Dict[str, Any]:
    """Return one scenario by id (raises KeyError for unknown ids)."""
    for scenario in SCENARIOS:
        if scenario["scenario_id"] == scenario_id:
            return scenario
    raise KeyError(f"unknown scenario: {scenario_id}")


def benign_scenarios() -> List[Dict[str, Any]]:
    """Benign + boundary cases for false-positive testing."""
    return [s for s in SCENARIOS if s["kind"] in ("benign", "boundary")]
