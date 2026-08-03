import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "ndr.event.v1"


LEGACY_FEATURES = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_max",
    "flow_iat_mean",
    "flow_iat_max",
    "fwd_iat_tot",
]


class NormalizedNetworkEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    sensor_type: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    duration: Optional[float] = None
    bytes_sent: Optional[float] = None
    bytes_received: Optional[float] = None
    packets_sent: Optional[float] = None
    packets_received: Optional[float] = None
    tcp_flags: Optional[str] = None
    flow_id: Optional[str] = None
    host_id: Optional[str] = None
    device_id: Optional[str] = None
    raw_event_reference: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    ingestion_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    raw_event: Dict[str, Any] = Field(default_factory=dict)

    def to_db_dict(self) -> Dict[str, Any]:
        data = _model_dump(self)
        data["normalized"] = _json_ready(data)
        return data


def _model_dump(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _json_ready(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _parse_datetime(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(value, datetime):
        if value.tzinfo:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
    text = str(value).strip()
    if not text:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


def _number(value: Any) -> Optional[float]:
    if value is None or value == "-":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _integer(value: Any) -> Optional[int]:
    number = _number(value)
    return int(number) if number is not None else None


def _protocol(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).upper()


def _ip(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def _event_hash(payload: Dict[str, Any], prefix: str) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:32]}"


def detect_sensor_type(payload: Dict[str, Any], source_hint: Optional[str] = None) -> str:
    if source_hint:
        return source_hint
    if "id.orig_h" in payload or "uid" in payload:
        return "zeek"
    if payload.get("event_type") or "flow_id" in payload or "src_ip" in payload:
        return "suricata"
    return "synthetic"


def normalize_synthetic_event(
    payload: Dict[str, Any], raw_reference: Optional[str] = None
) -> NormalizedNetworkEvent:
    event_id = str(payload.get("event_id") or _event_hash(payload, "synthetic"))
    duration = _number(payload.get("duration", payload.get("flow_duration")))
    bytes_sent = _number(payload.get("bytes_sent", payload.get("totlen_fwd_pkts")))
    bytes_received = _number(payload.get("bytes_received", payload.get("totlen_bwd_pkts")))
    packets_sent = _number(payload.get("packets_sent", payload.get("tot_fwd_pkts")))
    packets_received = _number(payload.get("packets_received", payload.get("tot_bwd_pkts")))

    return NormalizedNetworkEvent(
        event_id=event_id,
        timestamp=_parse_datetime(payload.get("timestamp")),
        sensor_type=str(payload.get("sensor_type") or "synthetic"),
        source_ip=_ip(payload.get("source_ip") or payload.get("src_ip")),
        source_port=_integer(payload.get("source_port") or payload.get("src_port")),
        destination_ip=_ip(payload.get("destination_ip") or payload.get("dest_ip") or payload.get("dst_ip")),
        destination_port=_integer(
            payload.get("destination_port") or payload.get("dest_port") or payload.get("dst_port")
        ),
        protocol=_protocol(payload.get("protocol")),
        duration=duration,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        packets_sent=packets_sent,
        packets_received=packets_received,
        tcp_flags=payload.get("tcp_flags"),
        flow_id=payload.get("flow_id") or payload.get("session_id"),
        host_id=payload.get("host_id"),
        device_id=payload.get("device_id"),
        raw_event_reference=raw_reference or payload.get("raw_event_reference"),
        raw_event=payload,
    )


def normalize_zeek_conn_event(
    payload: Dict[str, Any], raw_reference: Optional[str] = None
) -> NormalizedNetworkEvent:
    event_id = str(payload.get("event_id") or payload.get("uid") or _event_hash(payload, "zeek"))
    return NormalizedNetworkEvent(
        event_id=event_id,
        timestamp=_parse_datetime(payload.get("ts") or payload.get("timestamp")),
        sensor_type="zeek",
        source_ip=_ip(payload.get("id.orig_h") or payload.get("source_ip")),
        source_port=_integer(payload.get("id.orig_p") or payload.get("source_port")),
        destination_ip=_ip(payload.get("id.resp_h") or payload.get("destination_ip")),
        destination_port=_integer(payload.get("id.resp_p") or payload.get("destination_port")),
        protocol=_protocol(payload.get("proto")),
        duration=_number(payload.get("duration")),
        bytes_sent=_number(payload.get("orig_bytes")),
        bytes_received=_number(payload.get("resp_bytes")),
        packets_sent=_number(payload.get("orig_pkts")),
        packets_received=_number(payload.get("resp_pkts")),
        tcp_flags=payload.get("history") or payload.get("conn_state"),
        flow_id=payload.get("uid"),
        host_id=payload.get("host") or payload.get("host_id"),
        device_id=payload.get("sensor_id") or payload.get("device_id"),
        raw_event_reference=raw_reference or payload.get("_path") or payload.get("raw_event_reference"),
        raw_event=payload,
    )


def normalize_suricata_eve_event(
    payload: Dict[str, Any], raw_reference: Optional[str] = None
) -> NormalizedNetworkEvent:
    flow = payload.get("flow") or {}
    tcp = payload.get("tcp") or {}
    event_id = str(payload.get("event_id") or payload.get("flow_id") or _event_hash(payload, "suricata"))
    return NormalizedNetworkEvent(
        event_id=event_id,
        timestamp=_parse_datetime(payload.get("timestamp")),
        sensor_type="suricata",
        source_ip=_ip(payload.get("src_ip") or payload.get("source_ip")),
        source_port=_integer(payload.get("src_port") or payload.get("source_port")),
        destination_ip=_ip(payload.get("dest_ip") or payload.get("dst_ip") or payload.get("destination_ip")),
        destination_port=_integer(
            payload.get("dest_port") or payload.get("dst_port") or payload.get("destination_port")
        ),
        protocol=_protocol(payload.get("proto") or payload.get("protocol")),
        duration=_number(flow.get("age") or payload.get("duration")),
        bytes_sent=_number(flow.get("bytes_toserver") or payload.get("bytes_sent")),
        bytes_received=_number(flow.get("bytes_toclient") or payload.get("bytes_received")),
        packets_sent=_number(flow.get("pkts_toserver") or payload.get("packets_sent")),
        packets_received=_number(flow.get("pkts_toclient") or payload.get("packets_received")),
        tcp_flags=tcp.get("tcp_flags") or tcp.get("state") or payload.get("tcp_flags"),
        flow_id=str(payload.get("flow_id")) if payload.get("flow_id") is not None else None,
        host_id=payload.get("host_id"),
        device_id=payload.get("sensor_id") or payload.get("device_id"),
        raw_event_reference=raw_reference or payload.get("raw_event_reference"),
        raw_event=payload,
    )


def normalize_event(
    payload: Dict[str, Any],
    source_hint: Optional[str] = None,
    raw_reference: Optional[str] = None,
) -> NormalizedNetworkEvent:
    if not isinstance(payload, dict):
        raise ValueError("Network telemetry message must be a JSON object")
    sensor_type = detect_sensor_type(payload, source_hint)
    if sensor_type == "zeek":
        return normalize_zeek_conn_event(payload, raw_reference)
    if sensor_type == "suricata":
        return normalize_suricata_eve_event(payload, raw_reference)
    if sensor_type == "pcap":
        raise ValueError("PCAP files must be converted with parse_pcap_flows before ingestion")
    return normalize_synthetic_event(payload, raw_reference)


def parse_json_lines(lines: Iterable[str], source_hint: Optional[str] = None) -> List[NormalizedNetworkEvent]:
    events = []
    for line_number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        payload = json.loads(text)
        events.append(
            normalize_event(payload, source_hint=source_hint, raw_reference=f"jsonl:{line_number}")
        )
    return events


def parse_pcap_flows(path: str) -> List[NormalizedNetworkEvent]:
    try:
        import scapy.all as scapy  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "PCAP-derived flow parsing is optional. Install scapy in a lab environment "
            "or convert PCAPs to Zeek/Suricata JSON before ingestion."
        ) from exc

    flows: Dict[str, Dict[str, Any]] = {}
    for packet in scapy.PcapReader(path):
        if not packet.haslayer("IP"):
            continue
        ip = packet["IP"]
        proto = "TCP" if packet.haslayer("TCP") else "UDP" if packet.haslayer("UDP") else str(ip.proto)
        sport = packet["TCP"].sport if packet.haslayer("TCP") else packet["UDP"].sport if packet.haslayer("UDP") else None
        dport = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport if packet.haslayer("UDP") else None
        key = f"{ip.src}:{sport}-{ip.dst}:{dport}-{proto}"
        flow = flows.setdefault(
            key,
            {
                "timestamp": datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat(),
                "source_ip": ip.src,
                "source_port": sport,
                "destination_ip": ip.dst,
                "destination_port": dport,
                "protocol": proto,
                "bytes_sent": 0,
                "packets_sent": 0,
                "flow_id": key,
            },
        )
        flow["bytes_sent"] += len(packet)
        flow["packets_sent"] += 1
    return [
        normalize_synthetic_event({**payload, "sensor_type": "pcap"}, raw_reference=path)
        for payload in flows.values()
    ]


def features_from_event(event: NormalizedNetworkEvent) -> Dict[str, float]:
    raw = event.raw_event or {}
    features = {name: _number(raw.get(name)) or 0.0 for name in LEGACY_FEATURES}
    if not any(features.values()):
        features.update(
            {
                "flow_duration": event.duration or 0.0,
                "tot_fwd_pkts": event.packets_sent or 0.0,
                "tot_bwd_pkts": event.packets_received or 0.0,
                "totlen_fwd_pkts": event.bytes_sent or 0.0,
                "fwd_pkt_len_max": event.bytes_sent or 0.0,
                "fwd_pkt_len_min": 0.0,
                "fwd_pkt_len_mean": (event.bytes_sent or 0.0) / max(event.packets_sent or 1.0, 1.0),
                "bwd_pkt_len_max": event.bytes_received or 0.0,
                "flow_iat_mean": 0.0,
                "flow_iat_max": 0.0,
                "fwd_iat_tot": event.duration or 0.0,
            }
        )
    return features
