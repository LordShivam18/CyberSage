"""Tests for GuardianEvent model and schema (Phase 1)."""

import hashlib
from datetime import datetime, timezone

import pytest

from guardian.models.event import (
    GuardianEvent,
    _compute_event_id,
    create_guardian_event,
)


class TestEventId:
    """Deterministic, idempotent, collision-resistant event IDs."""

    def test_same_inputs_produce_same_event_id(self):
        """Event ID must be deterministic for identical inputs."""
        ts = datetime(2026, 1, 15, 12, 0, 0)
        id1 = _compute_event_id(
            host_id="host-abc",
            process_name="cmd.exe",
            process_exe_path="C:\\Windows\\System32\\cmd.exe",
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        id2 = _compute_event_id(
            host_id="host-abc",
            process_name="cmd.exe",
            process_exe_path="C:\\Windows\\System32\\cmd.exe",
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        assert id1 == id2
        assert id1.startswith("guardian-")
        assert len(id1) == len("guardian-") + 32

    def test_different_inputs_produce_different_ids(self):
        """Different events must have different IDs."""
        ts = datetime(2026, 1, 15, 12, 0, 0)
        id1 = _compute_event_id(
            host_id="host-abc",
            process_name="cmd.exe",
            process_exe_path="C:\\cmd.exe",
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        id2 = _compute_event_id(
            host_id="host-abc",
            process_name="powershell.exe",
            process_exe_path="C:\\powershell.exe",
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        assert id1 != id2

    def test_pid_exclusion_from_event_id(self):
        """PID must NOT be part of event ID (it is ephemeral)."""
        ts = datetime(2026, 1, 15, 12, 0, 0)
        base_kwargs = dict(
            host_id="host-abc",
            process_name="cmd.exe",
            process_exe_path="C:\\cmd.exe",
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        # Same event with different "PID" (PID is not in the function signature)
        id1 = _compute_event_id(**base_kwargs)
        id2 = _compute_event_id(**base_kwargs)
        assert id1 == id2

    def test_event_ids_are_prefixed(self):
        """All event IDs must start with 'guardian-'."""
        ts = datetime(2026, 1, 15, 12, 0, 0)
        event_id = _compute_event_id(
            host_id="h",
            process_name="test.exe",
            process_exe_path=None,
            process_exe_hash=None,
            file_path=None,
            destination_ip=None,
            destination_port=None,
            persistence_path=None,
            timestamp=ts,
            event_category="process",
        )
        assert event_id.startswith("guardian-")


class TestGuardianEvent:
    """GuardianEvent dataclass behavior."""

    def test_create_guardian_event_computes_event_id(self):
        """create_guardian_event factory computes a deterministic event_id."""
        event = create_guardian_event(
            host_id="host-abc",
            host_hostname="DESKTOP-01",
            agent_version="2.0.0",
            event_category="process",
            process_name="cmd.exe",
            process_exe_path="C:\\Windows\\System32\\cmd.exe",
        )
        assert event.event_id.startswith("guardian-")
        assert event.schema_version == "guardian.event.v1"
        assert event.host_id == "host-abc"
        assert event.host_hostname == "DESKTOP-01"
        assert event.agent_version == "2.0.0"
        assert event.event_category == "process"

    def test_to_dict_serializes_datetime(self):
        """to_dict must serialize datetime fields to ISO format."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
        )
        d = event.to_dict()
        assert isinstance(d["timestamp"], str)
        assert isinstance(d["ingestion_timestamp"], str)

    def test_to_dict_contains_all_fields(self):
        """to_dict must include all declared fields."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
            process_name="test.exe",
            process_pid=1234,
        )
        d = event.to_dict()
        assert d["process_name"] == "test.exe"
        assert d["process_pid"] == 1234
        assert d["process_exe_path"] is None

    def test_from_dict_roundtrip(self):
        """from_dict must reconstruct a GuardianEvent from to_dict output."""
        event = create_guardian_event(
            host_id="host-abc",
            host_hostname="DESKTOP-01",
            agent_version="2.0.0",
            event_category="process",
            process_name="cmd.exe",
            process_exe_path="C:\\cmd.exe",
        )
        d = event.to_dict()
        restored = GuardianEvent.from_dict(d)
        assert restored.event_id == event.event_id
        assert restored.host_id == event.host_id
        assert restored.process_name == event.process_name
        assert restored.process_exe_path == event.process_exe_path

    def test_minimal_event(self):
        """Event creation with only required fields."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
        )
        assert event.event_id
        assert event.process_name is None
        assert event.file_path is None

    def test_network_fields(self):
        """Event with network context."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
            event_category="network",
            destination_ip="192.168.1.100",
            destination_port=443,
            protocol="TCP",
        )
        assert event.destination_ip == "192.168.1.100"
        assert event.destination_port == 443
        assert event.protocol == "TCP"

    def test_file_fields(self):
        """Event with file activity context."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
            event_category="file",
            file_path="C:\\Users\\test\\malware.exe",
            file_operation="create",
        )
        assert event.file_path == "C:\\Users\\test\\malware.exe"
        assert event.file_operation == "create"

    def test_persistence_fields(self):
        """Event with persistence context."""
        event = create_guardian_event(
            host_id="h",
            host_hostname="test",
            agent_version="1.0",
            event_category="persistence",
            persistence_type="registry_run_key",
            persistence_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        assert event.persistence_type == "registry_run_key"
