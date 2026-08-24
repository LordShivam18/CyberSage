"""Tests for process collector normalization (Phase 1)."""

from datetime import datetime

import pytest

from guardian.collectors.process_monitor import (
    ProcessMonitorCollector,
    normalize_process_event,
)


def _base_host_kwargs():
    return {
        "host_id": "host-test-001",
        "host_hostname": "DESKTOP-TEST",
        "agent_version": "2.0.0",
    }


class TestNormalizeProcessEvent:
    def test_basic_process_creation(self):
        raw = {
            "timestamp": "2026-01-15T12:00:00Z",
            "event_type": "CreateProcess",
            "process_name": "cmd.exe",
            "process_id": 1234,
            "executable_path": None,
            "command_line": "cmd.exe /c echo test",
            "parent_process_name": "explorer.exe",
            "parent_process_id": 5678,
            "user_name": "testuser",
        }
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.event_category == "process"
        assert event.process_name == "cmd.exe"
        assert event.process_pid == 1234
        assert event.process_command_line == "cmd.exe /c echo test"
        assert event.parent_process_name == "explorer.exe"
        assert event.parent_process_pid == 5678
        assert event.user_name == "testuser"
        assert event.evidence == {"event_type": "CreateProcess"}

    def test_timestamp_parsing_iso(self):
        raw = {"timestamp": "2026-01-15T12:30:45Z"}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 1
        assert event.timestamp.hour == 12

    def test_timestamp_parsing_unix_epoch(self):
        raw = {"timestamp": 1705312200.0}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert isinstance(event.timestamp, datetime)

    def test_timestamp_parsing_none_falls_back(self):
        raw = {}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert isinstance(event.timestamp, datetime)

    def test_missing_fields_are_none(self):
        raw = {}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.process_name is None
        assert event.process_pid is None
        assert event.process_exe_path is None

    def test_host_fields_populated(self):
        raw = {}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.host_id == "host-test-001"
        assert event.host_hostname == "DESKTOP-TEST"
        assert event.agent_version == "2.0.0"

    def test_raw_event_preserved(self):
        raw = {"some_key": "some_value", "nested": {"a": 1}}
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.raw_event == raw

    def test_event_id_deterministic(self):
        raw = {
            "process_name": "test.exe",
            "executable_path": "C:\\test.exe",
            "timestamp": "2026-01-15T12:00:00Z",
        }
        e1 = normalize_process_event(raw, **_base_host_kwargs())
        e2 = normalize_process_event(raw, **_base_host_kwargs())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_for_different_data(self):
        raw1 = {"process_name": "a.exe", "timestamp": "2026-01-15T12:00:00Z"}
        raw2 = {"process_name": "b.exe", "timestamp": "2026-01-15T12:00:00Z"}
        e1 = normalize_process_event(raw1, **_base_host_kwargs())
        e2 = normalize_process_event(raw2, **_base_host_kwargs())
        assert e1.event_id != e2.event_id

    def test_alternative_field_names(self):
        """Support flexible field naming from different ETW sources."""
        raw = {
            "exe_path": "C:\\test.exe",
            "pid": 9999,
            "ppid": 1111,
            "username": "admin",
            "cmdline": "test.exe --flag",
        }
        event = normalize_process_event(raw, **_base_host_kwargs())
        assert event.process_exe_path == "C:\\test.exe"
        assert event.process_pid == 9999
        assert event.parent_process_pid == 1111
        assert event.user_name == "admin"
        assert event.process_command_line == "test.exe --flag"


class TestProcessMonitorCollector:
    def test_collector_type(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        assert collector.collector_type == "process_monitor"

    def test_collect_empty_by_default(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        events = collector.collect()
        assert events == []

    def test_inject_event(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        raw = {"process_name": "injected.exe", "process_id": 42}
        collector.inject_event(raw)
        events = collector.collect()
        assert len(events) == 1
        assert events[0].process_name == "injected.exe"

    def test_inject_multiple_events(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        for i in range(5):
            collector.inject_event({"process_name": f"proc{i}.exe", "process_id": i})
        events = collector.collect()
        assert len(events) == 5

    def test_collect_drains_pending(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        collector.inject_event({"process_name": "test.exe"})
        first = collector.collect()
        second = collector.collect()
        assert len(first) == 1
        assert len(second) == 0

    def test_start_stop_lifecycle(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        collector.start()
        assert collector._running is True
        collector.stop()
        assert collector._running is False

    def test_stop_idempotent(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        collector.start()
        collector.stop()
        collector.stop()  # Should not raise

    def test_context_manager(self):
        with ProcessMonitorCollector(**_base_host_kwargs()) as collector:
            assert collector._running is True
        assert collector._running is False

    def test_on_etw_event_normalizes(self):
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        raw = {"process_name": "etw_event.exe", "process_id": 100}
        collector.on_etw_event(raw)
        events = collector.collect()
        assert len(events) == 1
        assert events[0].process_name == "etw_event.exe"

    def test_on_etw_event_error_does_not_crash(self):
        """A single bad event must not crash the collector."""
        collector = ProcessMonitorCollector(**_base_host_kwargs())
        # Pass something that will cause normalization issues
        collector.on_etw_event(None)
        collector.on_etw_event({})
        # Collector should still work
        collector.on_etw_event({"process_name": "ok.exe"})
        events = collector.collect()
        assert len(events) >= 1
