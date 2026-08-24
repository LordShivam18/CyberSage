"""Tests for Guardian Phase 2 detectors."""

import pytest

from guardian.detectors.base import BaseDetector, Detection
from guardian.detectors.process_detectors import (
    SuspiciousProcessDetector,
    SuspiciousParentChildDetector,
    UnusualProcessLocationDetector,
)
from guardian.detectors.network_detectors import SuspiciousPortDetector, UnusualProtocolDetector
from guardian.detectors.persistence_detectors import PersistenceModificationDetector
from guardian.detectors.recurrence_detector import RecurrenceDetector


def _make_event(**overrides):
    base = {
        "event_id": "test-event-001",
        "event_category": "process",
        "process_name": "test.exe",
        "host_id": "host-001",
    }
    base.update(overrides)
    return base


class TestSuspiciousProcessDetector:
    def test_detects_known_suspicious_process(self):
        det = SuspiciousProcessDetector()
        event = _make_event(process_name="mimikatz.exe")
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "high"
        assert results[0].confidence == 0.9
        assert "mimikatz.exe" in results[0].title
        assert results[0].mitre_technique == "T1059"

    def test_ignores_benign_process(self):
        det = SuspiciousProcessDetector()
        event = _make_event(process_name="notepad.exe")
        results = det.detect(event)
        assert len(results) == 0

    def test_ignores_non_process_events(self):
        det = SuspiciousProcessDetector()
        event = _make_event(event_category="network")
        results = det.detect(event)
        assert len(results) == 0

    def test_case_insensitive_matching(self):
        det = SuspiciousProcessDetector()
        event = _make_event(process_name="MIMIKATZ.EXE")
        results = det.detect(event)
        assert len(results) == 1

    def test_no_process_name_returns_empty(self):
        det = SuspiciousProcessDetector()
        event = _make_event(process_name=None)
        results = det.detect(event)
        assert len(results) == 0

    def test_detector_id(self):
        det = SuspiciousProcessDetector()
        assert det.detector_id == "suspicious_process"


class TestSuspiciousParentChildDetector:
    def test_detects_suspicious_relationship(self):
        det = SuspiciousParentChildDetector()
        event = _make_event(
            parent_process_name="svchost.exe",
            process_name="cmd.exe",
        )
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "high"
        assert "svchost.exe -> cmd.exe" in results[0].title

    def test_ignores_benign_relationship(self):
        det = SuspiciousParentChildDetector()
        event = _make_event(
            parent_process_name="explorer.exe",
            process_name="notepad.exe",
        )
        results = det.detect(event)
        assert len(results) == 0

    def test_ignores_non_process_events(self):
        det = SuspiciousParentChildDetector()
        event = _make_event(event_category="file")
        results = det.detect(event)
        assert len(results) == 0

    def test_missing_parent_returns_empty(self):
        det = SuspiciousParentChildDetector()
        event = _make_event(parent_process_name=None)
        results = det.detect(event)
        assert len(results) == 0


class TestUnusualProcessLocationDetector:
    def test_detects_temp_location(self):
        det = UnusualProcessLocationDetector()
        event = _make_event(process_exe_path="C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe")
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "medium"

    def test_ignores_system_location(self):
        det = UnusualProcessLocationDetector()
        event = _make_event(process_exe_path="C:\\Windows\\System32\\cmd.exe")
        results = det.detect(event)
        assert len(results) == 0

    def test_ignores_non_process_events(self):
        det = UnusualProcessLocationDetector()
        event = _make_event(event_category="persistence")
        results = det.detect(event)
        assert len(results) == 0


class TestSuspiciousPortDetector:
    def test_detects_suspicious_dest_port(self):
        det = SuspiciousPortDetector()
        event = _make_event(
            event_category="network",
            destination_ip="192.168.1.100",
            destination_port=4444,
            source_port=51234,
            protocol="TCP",
        )
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "high"
        assert "4444" in results[0].title

    def test_ignores_benign_port(self):
        det = SuspiciousPortDetector()
        event = _make_event(
            event_category="network",
            destination_port=443,
            source_port=51234,
        )
        results = det.detect(event)
        assert len(results) == 0

    def test_ignores_non_network_events(self):
        det = SuspiciousPortDetector()
        event = _make_event(event_category="process")
        results = det.detect(event)
        assert len(results) == 0


class TestPersistenceModificationDetector:
    def test_detects_persistence_event(self):
        det = PersistenceModificationDetector()
        event = _make_event(
            event_category="persistence",
            persistence_type="registry_run_key",
            persistence_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "high"  # suspicious path

    def test_detects_non_suspicious_persistence(self):
        det = PersistenceModificationDetector()
        event = _make_event(
            event_category="persistence",
            persistence_type="scheduled_task",
            persistence_path="\\Microsoft\\Windows\\Task\\MyTask",
        )
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "medium"  # not a known suspicious path


class TestRecurrenceDetector:
    def test_detects_process_recurrence(self):
        det = RecurrenceDetector()
        event = _make_event(process_name="suspicious.exe")
        # First 4 events — no detection
        for _ in range(4):
            results = det.detect(event)
            assert len(results) == 0
        # 5th event — detection
        results = det.detect(event)
        assert len(results) == 1
        assert results[0].severity == "medium"
        assert "5" in results[0].title

    def test_reset_clears_counters(self):
        det = RecurrenceDetector()
        event = _make_event(process_name="test.exe")
        for _ in range(4):
            det.detect(event)
        det.reset()
        # After reset, should not detect until threshold again
        for _ in range(4):
            results = det.detect(event)
            assert len(results) == 0


class TestDetectionModel:
    def test_detection_to_dict(self):
        det = Detection(
            event_id="e1",
            detector_id="test",
            severity="high",
            confidence=0.9,
            title="Test detection",
        )
        d = det.to_dict()
        assert d["event_id"] == "e1"
        assert d["severity"] == "high"
        assert d["confidence"] == 0.9
        assert "created_at" in d

    def test_detection_from_dict(self):
        data = {
            "detection_id": "det-123",
            "event_id": "e1",
            "detector_id": "test",
            "severity": "medium",
        }
        det = Detection.from_dict(data)
        assert det.detection_id == "det-123"
        assert det.severity == "medium"

    def test_base_detector_raises(self):
        det = BaseDetector()
        with pytest.raises(NotImplementedError):
            det.detect({})
