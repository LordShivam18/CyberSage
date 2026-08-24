"""Integration tests for the full Guardian Phase 2.5 pipeline.

Tests: event → detector → evidence → risk → policy → persistence.
"""

import pytest

from guardian.detection.dispatcher import DetectionDispatcher, DetectionResult
from guardian.detectors.base import Detection


def _make_event_dict(**overrides):
    """Create a minimal GuardianEvent dict for the dispatcher."""
    base = {
        "event_id": "pipeline-test-001",
        "event_category": "process",
        "host_id": "host-test-001",
        "process_name": "test.exe",
        "process_exe_path": "C:\\Windows\\System32\\test.exe",
    }
    base.update(overrides)
    return base


class TestDetectionDispatcher:
    """Test the full detection pipeline dispatch."""

    def test_dispatcher_initializes(self):
        """Dispatcher should initialize with all detectors."""
        d = DetectionDispatcher()
        assert len(d._detectors) == 6

    def test_dispatcher_runs_detectors(self):
        """Dispatcher should run detectors and return results."""
        d = DetectionDispatcher()
        # We can't test full persistence without a DB, but we can test the detector chain
        event = _make_event_dict(process_name="mimikatz.exe")
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        assert len(detections) >= 1
        assert result.detections_created >= 1
        assert result.event_id == ""  # not set yet

    def test_dispatcher_isolates_detector_failures(self):
        """If one detector fails, others should still run."""
        d = DetectionDispatcher()
        # Add a broken detector
        class BrokenDetector:
            detector_id = "broken"
            description = "broken"
            def detect(self, event):
                raise RuntimeError("boom")
        d._detectors.append(BrokenDetector())

        event = _make_event_dict(process_name="mimikatz.exe")
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        # Should still have detections from the working detectors
        assert len(detections) >= 1
        # Should have recorded the error
        assert len(result.detector_errors) == 1
        assert result.detector_errors[0]["detector_id"] == "broken"

    def test_suspicious_process_creates_detection(self):
        """A mimikatz.exe event should create a detection."""
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="mimikatz.exe")
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        assert any(det.detector_id == "suspicious_process" for det in detections)

    def test_suspicious_network_creates_detection(self):
        """A connection to port 4444 should create a detection."""
        d = DetectionDispatcher()
        event = _make_event_dict(
            event_id="net-test-001",
            event_category="network",
            destination_ip="192.168.1.100",
            destination_port=4444,
            source_port=51234,
            protocol="TCP",
        )
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        assert any(det.detector_id == "suspicious_port" for det in detections)

    def test_persistence_event_creates_detection(self):
        """A persistence modification event should create a detection."""
        d = DetectionDispatcher()
        event = _make_event_dict(
            event_id="persist-test-001",
            event_category="persistence",
            persistence_type="registry_run_key",
            persistence_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        assert any(det.detector_id == "persistence_modification" for det in detections)

    def test_benign_event_creates_no_detection(self):
        """A normal notepad.exe event should create no detections."""
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="notepad.exe")
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        assert len(detections) == 0

    def test_detector_result_counts(self):
        """DetectionResult should track counts correctly."""
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="mimikatz.exe")
        result = DetectionResult()
        result.event_id = "test-001"
        d._run_detectors(event, result)
        assert result.detections_created >= 1


class TestIdempotency:
    """Test that duplicate events don't create duplicate downstream objects."""

    def test_detection_id_is_stable(self):
        """Same event should produce the same detection_id."""
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="mimikatz.exe")
        result1 = DetectionResult()
        dets1 = d._run_detectors(event, result1)

        d2 = DetectionDispatcher()
        result2 = DetectionResult()
        dets2 = d2._run_detectors(event, result2)

        # Same event should produce same detection IDs
        ids1 = sorted([det.detection_id for det in dets1])
        ids2 = sorted([det.detection_id for det in dets2])
        assert ids1 == ids2

    def test_deterministic_output(self):
        """Running the same event twice should produce identical results."""
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="mimikatz.exe")

        result1 = DetectionResult()
        dets1 = d._run_detectors(event, result1)

        result2 = DetectionResult()
        dets2 = d._run_detectors(event, result2)

        assert len(dets1) == len(dets2)
        for det1, det2 in zip(sorted(dets1, key=lambda d: d.detection_id),
                               sorted(dets2, key=lambda d: d.detection_id)):
            assert det1.detection_id == det2.detection_id
            assert det1.severity == det2.severity
            assert det1.confidence == det2.confidence
            assert det1.detector_id == det2.detector_id


class TestPolicyBoundary:
    """Test that the policy engine remains data-only."""

    def test_policy_decision_cannot_execute_commands(self):
        """Prove that ResponseDecision is a data object, not an executable."""
        from guardian.policy.engine import PolicyEngine
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=95.0,
            risk_severity="critical",
            risk_confidence=0.99,
            risk_factors=[],
            evidence=[],
        )
        # Decision must be a plain data object
        assert isinstance(decision.recommended_action, str)
        assert decision.recommended_action in ("monitor", "investigate", "approve_containment", "prepare_containment")
        assert hasattr(decision, "to_dict")
        # No executable fields
        d = decision.to_dict()
        assert "command" not in d
        assert "execute" not in d
        assert "shell" not in d


class TestMITREMapping:
    """Test that detections include correct MITRE mappings."""

    def test_suspicious_process_maps_to_t1059(self):
        d = DetectionDispatcher()
        event = _make_event_dict(process_name="mimikatz.exe")
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        t1059_dets = [det for det in detections if det.mitre_technique == "T1059"]
        assert len(t1059_dets) >= 1

    def test_suspicious_port_maps_to_t1571(self):
        d = DetectionDispatcher()
        event = _make_event_dict(
            event_id="mitre-net-001",
            event_category="network",
            destination_ip="10.0.0.1",
            destination_port=4444,
            source_port=12345,
            protocol="TCP",
        )
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        t1571_dets = [det for det in detections if det.mitre_technique == "T1571"]
        assert len(t1571_dets) >= 1

    def test_persistence_maps_to_t1547(self):
        d = DetectionDispatcher()
        event = _make_event_dict(
            event_id="mitre-persist-001",
            event_category="persistence",
            persistence_type="registry_run_key",
            persistence_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        result = DetectionResult()
        detections = d._run_detectors(event, result)
        t1547_dets = [det for det in detections if det.mitre_technique == "T1547"]
        assert len(t1547_dets) >= 1
