"""Network behavior detectors.

Detects suspicious network connections and destinations.
"""

from __future__ import annotations

from typing import Any, Dict, List

from guardian.detectors.base import BaseDetector, Detection, compute_detection_id

# Ports commonly associated with C2, exfiltration, or lateral movement
SUSPICIOUS_PORTS = frozenset({
    4444,  # Metasploit default
    5555,  # Common C2
    8443,  # Alternate HTTPS (common C2)
    1234,  # Common backdoor
    31337, # Back Orifice
    6666,  # IRC backdoor
    6667,  # IRC backdoor
    9001,  # Common C2
})

# Well-known ports that are generally benign when outbound
BENIGN_OUTBOUND_PORTS = frozenset({
    80, 443, 53, 993, 995, 587, 465, 143, 110, 21, 22,
})


class SuspiciousPortDetector(BaseDetector):
    """Detect connections to/from suspicious ports."""

    @property
    def detector_id(self) -> str:
        return "suspicious_port"

    @property
    def description(self) -> str:
        return "Detects network connections to/from suspicious ports"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "network":
            return []

        dest_port = event.get("destination_port")
        src_port = event.get("source_port")

        detections = []

        if dest_port and dest_port in SUSPICIOUS_PORTS:
            detections.append(Detection(
                detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
                event_id=event.get("event_id", ""),
                detector_id=self.detector_id,
                severity="high",
                confidence=0.8,
                title=f"Connection to suspicious port {dest_port}",
                description=(
                    f"Outbound connection to destination "
                    f"{event.get('destination_ip')}:{dest_port} uses a port "
                    f"commonly associated with C2 or backdoor traffic."
                ),
                evidence={
                    "destination_ip": event.get("destination_ip"),
                    "destination_port": dest_port,
                    "source_ip": event.get("source_ip"),
                    "source_port": src_port,
                    "protocol": event.get("protocol"),
                },
                mitre_technique="T1571",
                mitre_tactic="command-and-control",
            ))

        if src_port and src_port in SUSPICIOUS_PORTS and src_port != dest_port:
            detections.append(Detection(
                detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id + "_src"),
                event_id=event.get("event_id", ""),
                detector_id=self.detector_id,
                severity="medium",
                confidence=0.7,
                title=f"Connection from suspicious port {src_port}",
                description=(
                    f"Inbound connection from source "
                    f"{event.get('source_ip')}:{src_port} uses a port "
                    f"commonly associated with backdoor traffic."
                ),
                evidence={
                    "source_ip": event.get("source_ip"),
                    "source_port": src_port,
                    "destination_ip": event.get("destination_ip"),
                    "destination_port": dest_port,
                    "protocol": event.get("protocol"),
                },
                mitre_technique="T1571",
                mitre_tactic="command-and-control",
            ))

        return detections


class UnusualProtocolDetector(BaseDetector):
    """Detect network traffic using unexpected protocols on non-standard ports."""

    @property
    def detector_id(self) -> str:
        return "unusual_protocol"

    @property
    def description(self) -> str:
        return "Detects protocol/port mismatches suggesting tunneling or C2"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "network":
            return []

        protocol = (event.get("protocol") or "").upper()
        dest_port = event.get("destination_port")

        if not protocol or not dest_port:
            return []

        # Detect DNS over non-standard port (possible tunneling)
        if dest_port == 53 and protocol not in ("UDP", "TCP"):
            return [Detection(
                detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
                event_id=event.get("event_id", ""),
                detector_id=self.detector_id,
                severity="medium",
                confidence=0.65,
                title=f"DNS on non-standard protocol: {protocol}",
                description=(
                    f"DNS traffic (port 53) using protocol {protocol} instead of "
                    f"UDP/TCP may indicate DNS tunneling or C2 communication."
                ),
                evidence={
                    "destination_ip": event.get("destination_ip"),
                    "destination_port": dest_port,
                    "protocol": protocol,
                    "source_ip": event.get("source_ip"),
                },
                mitre_technique="T1071.004",
                mitre_tactic="command-and-control",
            )]

        return []
