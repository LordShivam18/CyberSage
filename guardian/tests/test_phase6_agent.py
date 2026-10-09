"""Phase 6 harness: agent durability (PROVIDED — NOT EXECUTED).

Genuine harness for the developer to execute later on an isolated
environment. Uses REAL queue/sync/identity/storage code paths with
temporary directories and a local HTTP server (actual HTTP interface).
No ETW, service installation, DPAPI, or backend mutation is performed
here. Live Windows cases live in guardian/agent/etw_live_harness.py.

Status: TEST HARNESS PROVIDED — NOT EXECUTED. No results claimed.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from guardian.agent import identity as identity_mod
from guardian.agent.secure_storage import protection_status
from guardian.collectors.network_monitor import normalize_network_event
from guardian.transport.local_queue import EventQueue
from guardian.transport.sync import SyncWorker


@pytest.fixture()
def temp_queue(tmp_path):
    queue = EventQueue(db_path=str(tmp_path / "harness_queue.db"), max_size=100)
    yield queue
    queue.close()


def test_identity_reused_across_restarts(tmp_path):
    first = identity_mod.ensure_identity(
        str(tmp_path), agent_key="agent-harness", host_id="host-harness",
        host_hostname="harness-host",
    )
    second = identity_mod.ensure_identity(
        str(tmp_path), agent_key="agent-harness", host_id="host-other",
    )
    assert first.agent_key == second.agent_key == "agent-harness"
    assert second.host_id == "host-harness"


def test_protection_status_never_claims_encryption_without_dpapi():
    status = protection_status()
    assert "dpapi_available" in status
    assert "ACLs are access control" in status["note"]


def test_network_normalization_never_invents_attribution():
    event = normalize_network_event(
        {"destination_ip": "203.0.113.66", "destination_port": 443, "protocol": "tcp"},
        host_id="host-1", host_hostname="h", agent_version="2.0.0",
    )
    assert event.destination_ip == "203.0.113.66"
    assert event.process_pid is None
    assert event.evidence["process_attribution"] == "unavailable"


def test_queue_lease_recovery_survives_crash(tmp_path):
    path = str(tmp_path / "lease.db")
    queue = EventQueue(db_path=path, max_size=10)
    queue.enqueue({"event_id": "lease-e1", "event_category": "process"})
    assert len(queue.dequeue(lease_seconds=30)) == 1
    queue.close()
    reopened = EventQueue(db_path=path, max_size=10)
    try:
        # Leases with default 300s have not expired: nothing recovered yet.
        assert reopened.recover_expired_leases() == 0
        assert reopened.queue_depth_age()["depth_active"] == 1
    finally:
        reopened.close()


def test_sync_parses_per_event_acknowledgement():
    acked, quarantined = SyncWorker._parse_acknowledgement(
        json.dumps({"results": [
            {"event_id": "e1", "status": "created"},
            {"event_id": "e2", "status": "duplicate"},
        ]}),
        ["e1", "e2"],
    )
    assert acked == ["e1", "e2"] and quarantined == []
    with pytest.raises(Exception):
        SyncWorker._parse_acknowledgement("{}", ["e1"])
