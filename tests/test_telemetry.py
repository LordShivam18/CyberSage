import json
from pathlib import Path

import pytest

from backend.telemetry import (
    features_from_event,
    normalize_event,
    normalize_suricata_eve_event,
    normalize_synthetic_event,
    normalize_zeek_conn_event,
    parse_json_lines,
    parse_pcap_flows,
)


FIXTURES = Path(__file__).parent / "fixtures"


def test_synthetic_event_normalizes_legacy_features():
    payload = json.loads((FIXTURES / "synthetic_events.jsonl").read_text().splitlines()[0])
    event = normalize_synthetic_event(payload)

    assert event.sensor_type == "synthetic"
    assert event.source_ip == "10.0.0.10"
    assert event.destination_ip == "203.0.113.66"
    assert event.bytes_sent == 75000
    assert features_from_event(event)["totlen_fwd_pkts"] == 75000


def test_zeek_conn_event_normalizes_network_tuple():
    payload = json.loads((FIXTURES / "zeek_conn.jsonl").read_text().splitlines()[0])
    event = normalize_zeek_conn_event(payload)

    assert event.sensor_type == "zeek"
    assert event.event_id == "C8demo1"
    assert event.source_port == 49152
    assert event.destination_port == 22
    assert event.protocol == "TCP"


def test_suricata_eve_event_normalizes_flow_fields():
    payload = json.loads((FIXTURES / "suricata_eve.jsonl").read_text().splitlines()[0])
    event = normalize_suricata_eve_event(payload)

    assert event.sensor_type == "suricata"
    assert event.flow_id == "123456"
    assert event.bytes_sent == 90000
    assert event.packets_received == 10


def test_json_lines_parser_accepts_source_hint():
    lines = (FIXTURES / "zeek_conn.jsonl").read_text().splitlines()
    events = parse_json_lines(lines, source_hint="zeek")

    assert len(events) == 1
    assert events[0].sensor_type == "zeek"


def test_unknown_payload_must_be_json_object():
    with pytest.raises(ValueError):
        normalize_event(["not", "an", "object"])


def test_pcap_parser_fails_gracefully_without_optional_dependency():
    with pytest.raises((RuntimeError, FileNotFoundError, OSError)) as exc_info:
        parse_pcap_flows("missing.pcap")
    assert str(exc_info.value)
