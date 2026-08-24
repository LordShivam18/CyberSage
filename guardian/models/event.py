"""GuardianEvent schema — host-level security event normalization.

Schema version: guardian.event.v1

Follows CyberSage ndr.event.v1 conventions for network fields.
PID is ephemeral and must NOT be the sole identity component.
Event IDs are deterministic, idempotent, and collision-resistant.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SCHEMA_VERSION = "guardian.event.v1"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _compute_event_id(
    *,
    host_id: str,
    process_name: Optional[str],
    process_exe_path: Optional[str],
    process_exe_hash: Optional[str],
    file_path: Optional[str],
    destination_ip: Optional[str],
    destination_port: Optional[int],
    persistence_path: Optional[str],
    timestamp: datetime,
    event_category: str,
) -> str:
    """Generate a deterministic, collision-resistant event ID.

    Uses only non-volatile fields. PID is deliberately excluded because
    it is ephemeral and would make the ID non-idempotent across retries.
    """
    key_parts = [
        host_id or "",
        event_category,
        process_name or "",
        process_exe_path or "",
        process_exe_hash or "",
        file_path or "",
        destination_ip or "",
        str(destination_port) if destination_port is not None else "",
        persistence_path or "",
        timestamp.isoformat() if timestamp else "",
    ]
    payload = "|".join(key_parts)
    return f"guardian-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:32]}"


@dataclass
class GuardianEvent:
    """Normalized host-level security event.

    All fields are optional except the identity fields. Collectors populate
    what they can; missing metadata is represented as None.
    """

    # ── Identity ──────────────────────────────────────────────────────
    event_id: str
    schema_version: str = SCHEMA_VERSION
    timestamp: datetime = field(default_factory=_now_utc)
    ingestion_timestamp: datetime = field(default_factory=_now_utc)

    # ── Host ──────────────────────────────────────────────────────────
    host_id: str = ""
    host_hostname: str = ""
    agent_version: str = ""

    # ── Event category ────────────────────────────────────────────────
    event_category: str = "process"  # process | file | network | persistence

    # ── Process context ───────────────────────────────────────────────
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_exe_path: Optional[str] = None
    process_exe_hash_sha256: Optional[str] = None
    process_command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_pid: Optional[int] = None
    parent_process_exe_path: Optional[str] = None

    # ── User context ──────────────────────────────────────────────────
    user_name: Optional[str] = None
    user_sid: Optional[str] = None

    # ── Network (reuses ndr.event.v1 conventions) ────────────────────
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[float] = None
    bytes_received: Optional[float] = None

    # ── File activity ─────────────────────────────────────────────────
    file_path: Optional[str] = None
    file_operation: Optional[str] = None  # create | modify | delete | rename
    file_hash_sha256: Optional[str] = None

    # ── Persistence ───────────────────────────────────────────────────
    persistence_type: Optional[str] = None  # registry_run_key | scheduled_task | startup_folder
    persistence_path: Optional[str] = None
    persistence_data: Optional[Dict[str, Any]] = None

    # ── Evidence ──────────────────────────────────────────────────────
    evidence: Optional[Dict[str, Any]] = None
    raw_event: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data

    def to_db_dict(self) -> Dict[str, Any]:
        """Produce a dict suitable for database insertion.

        Mirrors the NormalizedEvent.to_db_dict() convention from ndr.event.v1.
        """
        data = self.to_dict()
        data["normalized"] = data.copy()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardianEvent:
        """Deserialize from a dict (e.g., JSON from the wire)."""
        kwargs: Dict[str, Any] = {}
        for f_name, f_type in cls.__dataclass_fields__.items():
            if f_name not in data:
                continue
            value = data[f_name]
            if f_type.type == "datetime" or (
                hasattr(f_type.type, "__origin__") is False
                and f_type.type is datetime
            ):
                if isinstance(value, str):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
                elif isinstance(value, (int, float)):
                    value = datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
            kwargs[f_name] = value
        return cls(**kwargs)


def create_guardian_event(
    *,
    host_id: str,
    host_hostname: str,
    agent_version: str,
    event_category: str = "process",
    timestamp: Optional[datetime] = None,
    **kwargs: Any,
) -> GuardianEvent:
    """Factory that computes a deterministic event_id."""
    ts = timestamp or _now_utc()
    event_id = _compute_event_id(
        host_id=host_id,
        process_name=kwargs.get("process_name"),
        process_exe_path=kwargs.get("process_exe_path"),
        process_exe_hash=kwargs.get("process_exe_hash_sha256"),
        file_path=kwargs.get("file_path"),
        destination_ip=kwargs.get("destination_ip"),
        destination_port=kwargs.get("destination_port"),
        persistence_path=kwargs.get("persistence_path"),
        timestamp=ts,
        event_category=event_category,
    )
    return GuardianEvent(
        event_id=event_id,
        timestamp=ts,
        ingestion_timestamp=_now_utc(),
        host_id=host_id,
        host_hostname=host_hostname,
        agent_version=agent_version,
        event_category=event_category,
        **kwargs,
    )
