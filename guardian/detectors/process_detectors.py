"""Host-level process behavior detectors.

Detects suspicious process execution and parent-child relationships.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from guardian.detectors.base import BaseDetector, Detection, compute_detection_id

# Known suspicious process names (lowercase)
SUSPICIOUS_PROCESS_NAMES = frozenset({
    "mimikatz.exe", "lazagne.exe", "procdump.exe", "psexec.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "meterpreter.exe",
    "cobaltstrike.exe", "ovenant.exe", "sliver.exe",
    "rubeus.exe", "bloodhound.py", "sharpup.exe",
})

# Known suspicious parent-child relationships
# (parent, child) — child should not be spawned by parent
SUSPICIOUS_PARENT_CHILD = {
    ("svchost.exe", "cmd.exe"),
    ("svchost.exe", "powershell.exe"),
    ("services.exe", "cmd.exe"),
    ("lsass.exe", "cmd.exe"),
    ("winlogon.exe", "cmd.exe"),
    ("explorer.exe", "net.exe"),
    ("explorer.exe", "net1.exe"),
    ("explorer.exe", "whoami.exe"),
}

# Processes that are suspicious when run from unusual locations
UNUSUAL_LOCATION_INDICATORS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\desktop\\",
)


class SuspiciousProcessDetector(BaseDetector):
    """Detect execution of known suspicious processes."""

    @property
    def detector_id(self) -> str:
        return "suspicious_process"

    @property
    def description(self) -> str:
        return "Detects execution of known suspicious process names"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "process":
            return []

        process_name = (event.get("process_name") or "").lower()
        if not process_name:
            return []

        if process_name not in SUSPICIOUS_PROCESS_NAMES:
            return []

        return [Detection(
            detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
            event_id=event.get("event_id", ""),
            detector_id=self.detector_id,
            severity="high",
            confidence=0.9,
            title=f"Suspicious process execution: {process_name}",
            description=(
                f"Process '{process_name}' is associated with offensive security "
                f"tools or known malware. Executed by user "
                f"{event.get('user_name', 'unknown')}."
            ),
            evidence={
                "process_name": process_name,
                "process_exe_path": event.get("process_exe_path"),
                "process_command_line": event.get("process_command_line"),
                "parent_process_name": event.get("parent_process_name"),
                "user_name": event.get("user_name"),
            },
            mitre_technique="T1059",
            mitre_tactic="execution",
        )]


class SuspiciousParentChildDetector(BaseDetector):
    """Detect suspicious parent-child process relationships."""

    @property
    def detector_id(self) -> str:
        return "suspicious_parent_child"

    @property
    def description(self) -> str:
        return "Detects suspicious parent-child process relationships"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "process":
            return []

        parent = (event.get("parent_process_name") or "").lower()
        child = (event.get("process_name") or "").lower()

        if not parent or not child:
            return []

        if (parent, child) not in SUSPICIOUS_PARENT_CHILD:
            return []

        return [Detection(
            detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
            event_id=event.get("event_id", ""),
            detector_id=self.detector_id,
            severity="high",
            confidence=0.85,
            title=f"Suspicious parent-child: {parent} -> {child}",
            description=(
                f"Process '{child}' was spawned by '{parent}', which is an "
                f"unusual and suspicious relationship often seen in post-exploitation."
            ),
            evidence={
                "parent_process_name": parent,
                "child_process_name": child,
                "parent_process_pid": event.get("parent_process_pid"),
                "process_pid": event.get("process_pid"),
                "process_exe_path": event.get("process_exe_path"),
                "process_command_line": event.get("process_command_line"),
            },
            mitre_technique="T1059",
            mitre_tactic="execution",
        )]


class UnusualProcessLocationDetector(BaseDetector):
    """Detect processes executing from unusual file system locations."""

    @property
    def detector_id(self) -> str:
        return "unusual_process_location"

    @property
    def description(self) -> str:
        return "Detects processes executing from temp, downloads, or desktop locations"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "process":
            return []

        exe_path = (event.get("process_exe_path") or "").lower()
        if not exe_path:
            return []

        for indicator in UNUSUAL_LOCATION_INDICATORS:
            if indicator in exe_path:
                return [Detection(
                    detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
                    event_id=event.get("event_id", ""),
                    detector_id=self.detector_id,
                    severity="medium",
                    confidence=0.6,
                    title=f"Process from unusual location: {exe_path}",
                    description=(
                        f"Process '{event.get('process_name')}' is executing from "
                        f"'{exe_path}', which is an unusual location for executables."
                    ),
                    evidence={
                        "process_name": event.get("process_name"),
                        "process_exe_path": exe_path,
                        "parent_process_name": event.get("parent_process_name"),
                        "user_name": event.get("user_name"),
                    },
                    mitre_technique="T1059",
                    mitre_tactic="execution",
                )]
        return []
