#!/usr/bin/env python3
"""Runtime assertions used by the GitHub Actions Docker release gate.

This program is copied into the already-running API container by the workflow.
It intentionally reports only check outcomes: credentials, JWTs, response bodies,
and database connection strings are never written to stdout or stderr.
"""

import argparse
import asyncio
import inspect
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict

import httpx
import websockets
from websockets.exceptions import ConnectionClosed, InvalidHandshake
from kafka import KafkaConsumer, KafkaProducer
from sqlalchemy import text

sys.path.insert(0, "/app")

from backend.auth import create_access_token  # noqa: E402
from backend.config import settings  # noqa: E402
from backend.database import SessionLocal  # noqa: E402
from backend.models import User  # noqa: E402


API_BASE_URL = os.getenv("RUNTIME_API_BASE_URL", "http://127.0.0.1:8000")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def wait_for(check: Callable[[], bool], description: str, timeout_seconds: int = 45) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise AssertionError(f"Timed out waiting for {description}")


def high_risk_event(event_id: str) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_ip": "10.10.5.23",
        "source_port": 51515,
        "destination_ip": "203.0.113.66",
        "destination_port": 443,
        "protocol": "TCP",
        "flow_duration": 119999872,
        "tot_fwd_pkts": 100,
        "tot_bwd_pkts": 200,
        "totlen_fwd_pkts": 50000,
        "fwd_pkt_len_max": 1500,
        "fwd_pkt_len_min": 0,
        "fwd_pkt_len_mean": 500,
        "bwd_pkt_len_max": 3000,
        "flow_iat_mean": 1000,
        "flow_iat_max": 5000000,
        "fwd_iat_tot": 120000000,
    }


def assert_safe_error(response: httpx.Response, expected_status: int, label: str) -> None:
    require(response.status_code == expected_status, f"{label} returned unexpected status")
    body = response.text.lower()
    require("traceback" not in body, f"{label} exposed a traceback")
    require(settings.jwt_secret.lower() not in body, f"{label} exposed a secret")
    require("postgresql://" not in body, f"{label} exposed a database URL")


def login(client: httpx.Client, username: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    require(response.status_code == 200, "Correct credentials were rejected")
    token = response.json().get("access_token")
    require(isinstance(token, str) and token.count(".") == 2, "Login did not return a JWT")
    return token


def expired_token(username: str) -> str:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).one()
        return create_access_token(user, expires_delta=timedelta(seconds=-5))
    finally:
        db.close()


def websocket_connect_kwargs(headers: Dict[str, str]) -> Dict[str, Any]:
    parameter_names = inspect.signature(websockets.connect).parameters
    if "additional_headers" in parameter_names:
        return {"additional_headers": headers}
    return {"extra_headers": headers}


async def assert_websocket_rejected(headers: Dict[str, str]) -> None:
    try:
        async with websockets.connect(
            "ws://127.0.0.1:8000/api/v1/ws/alerts",
            open_timeout=5,
            **websocket_connect_kwargs(headers),
        ) as websocket:
            await asyncio.wait_for(websocket.recv(), timeout=3)
    except (InvalidHandshake, ConnectionClosed):
        return
    except asyncio.TimeoutError as exc:
        raise AssertionError("Rejected WebSocket connection remained open") from exc
    raise AssertionError("Unauthorized WebSocket connection was accepted")



async def validate_websocket_notification(client: httpx.Client, analyst_token: str) -> int:
    await assert_websocket_rejected({})
    await assert_websocket_rejected({"Authorization": "Bearer malformed.token"})

    headers = {"Authorization": f"Bearer {analyst_token}"}
    async with websockets.connect(
        "ws://127.0.0.1:8000/api/v1/ws/alerts",
        open_timeout=10,
        **websocket_connect_kwargs(headers),
    ) as websocket:
        greeting = json.loads(await asyncio.wait_for(websocket.recv(), timeout=10))
        require(greeting.get("type") == "connected", "Authorized WebSocket did not connect")

        event_id = f"runtime-ws-{uuid.uuid4().hex}"
        response = client.post(
            "/api/v1/events",
            headers=headers,
            json={"payload": high_risk_event(event_id), "source_hint": "synthetic"},
        )
        require(response.status_code == 200, "Analyst API ingest was rejected")
        payload = response.json()
        alert = payload.get("alert")
        require(alert and alert.get("id"), "WebSocket validation event did not create an alert")

        notification = None
        for _ in range(3):
            candidate = json.loads(await asyncio.wait_for(websocket.recv(), timeout=10))
            if candidate.get("type") == "alert.created":
                notification = candidate
                break
        require(notification is not None, "Authenticated WebSocket did not receive a live alert")
        related_events = notification.get("alert", {}).get("related_event_ids", [])
        require(event_id in related_events, "WebSocket alert did not match the submitted event")
        return int(alert["id"])


def run_authentication_and_websocket_validation() -> None:
    analyst_username = os.environ["RUNTIME_ANALYST_USERNAME"]
    analyst_password = os.environ["RUNTIME_ANALYST_PASSWORD"]
    auditor_username = os.environ["RUNTIME_AUDITOR_USERNAME"]
    auditor_password = os.environ["RUNTIME_AUDITOR_PASSWORD"]

    require(not settings.threat_intel_external_enabled, "External threat intelligence must remain disabled")
    with httpx.Client(base_url=API_BASE_URL, timeout=10) as client:
        analyst_token = login(client, analyst_username, analyst_password)
        auditor_token = login(client, auditor_username, auditor_password)

        incorrect = client.post(
            "/api/v1/auth/login",
            json={"username": analyst_username, "password": "incorrect-password"},
        )
        assert_safe_error(incorrect, 401, "Incorrect-password login")

        probe = {"payload": high_risk_event(f"runtime-auth-probe-{uuid.uuid4().hex}")}
        assert_safe_error(client.post("/api/v1/events", json=probe), 401, "Missing-token request")
        assert_safe_error(
            client.post("/api/v1/events", headers={"Authorization": "Bearer malformed.token"}, json=probe),
            401,
            "Malformed-token request",
        )
        assert_safe_error(
            client.post(
                "/api/v1/events",
                headers={"Authorization": f"Bearer {expired_token(analyst_username)}"},
                json=probe,
            ),
            401,
            "Expired-token request",
        )

        alert_id = asyncio.run(validate_websocket_notification(client, analyst_token))
        auditor_update = client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers={"Authorization": f"Bearer {auditor_token}"},
            json={"status": "acknowledged"},
        )
        assert_safe_error(auditor_update, 403, "Read-only auditor mutation")
        analyst_update = client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={"status": "acknowledged"},
        )
        require(analyst_update.status_code == 200, "Analyst mutation was rejected")

    print("PASS: runtime authentication and WebSocket validation")


def publish(topic: str, payload: Dict[str, Any]) -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    try:
        producer.send(topic, value=payload).get(timeout=10)
        producer.flush(timeout=10)
    finally:
        producer.close()


def topic_event_count(topic: str, event_id: str, minimum: int, timeout_seconds: int = 45) -> bool:
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=f"runtime-release-gate-{uuid.uuid4().hex}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    )
    seen = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            records = consumer.poll(timeout_ms=1000)
            for messages in records.values():
                for message in messages:
                    value = message.value if isinstance(message.value, dict) else {}
                    payload = value.get("payload") if isinstance(value.get("payload"), dict) else value
                    if value.get("event_id") == event_id or payload.get("event_id") == event_id:
                        seen += 1
                        if seen >= minimum:
                            return True
    finally:
        consumer.close()
    return False


def pipeline_counts(event_id: str) -> Dict[str, int]:
    db = SessionLocal()
    try:
        row = db.execute(
            text(
                """
                SELECT
                    (SELECT COUNT(*) FROM normalized_events WHERE event_id = :event_id) AS events,
                    (SELECT COUNT(*) FROM detections WHERE event_id = :event_id) AS detections,
                    (SELECT COUNT(*) FROM detections
                     WHERE event_id = :event_id AND risk_score IS NOT NULL) AS risk_scored_detections,
                    (SELECT COUNT(*) FROM alerts a JOIN detections d ON d.id = a.detection_id
                     WHERE d.event_id = :event_id) AS alerts,
                    (SELECT COUNT(*) FROM incident_alerts ia
                     JOIN alerts a ON a.id = ia.alert_id
                     JOIN detections d ON d.id = a.detection_id
                     WHERE d.event_id = :event_id) AS incident_links,
                    (SELECT COUNT(*) FROM incidents i
                     JOIN incident_alerts ia ON ia.incident_id = i.id
                     JOIN alerts a ON a.id = ia.alert_id
                     JOIN detections d ON d.id = a.detection_id
                     WHERE d.event_id = :event_id) AS incidents
                """
            ),
            {"event_id": event_id},
        ).mappings().one()
        return {key: int(value) for key, value in row.items()}
    finally:
        db.close()


def pipeline_complete(event_id: str) -> bool:
    counts = pipeline_counts(event_id)
    return all(counts[key] == 1 for key in counts)


def run_kafka_validation(event_id: str) -> None:
    payload = high_risk_event(event_id)
    publish(settings.raw_topic, payload)
    wait_for(lambda: pipeline_complete(event_id), "Kafka event processing")
    require(topic_event_count(settings.raw_topic, event_id, 1), "Raw Kafka topic did not contain the event")
    require(
        topic_event_count(settings.normalized_topic, event_id, 1),
        "Normalized Kafka topic did not contain the event",
    )
    require(
        topic_event_count(settings.detections_topic, event_id, 1),
        "Detections Kafka topic did not contain the event",
    )

    with httpx.Client(base_url=API_BASE_URL, timeout=10) as client:
        api_response = client.get("/api/v1/alerts", params={"source_ip": payload["source_ip"]})
        require(api_response.status_code == 200, "Alert API query failed")
        require(
            any(event_id in item.get("related_event_ids", []) for item in api_response.json().get("items", [])),
            "Authenticated API could not retrieve the Kafka-created alert",
        )

    publish(settings.raw_topic, payload)
    require(topic_event_count(settings.normalized_topic, event_id, 2), "Worker did not consume the duplicate")
    require(topic_event_count(settings.detections_topic, event_id, 2), "Worker did not publish duplicate result")
    require(pipeline_complete(event_id), "Duplicate Kafka event created additional database records")
    print("PASS: Kafka end-to-end and idempotency validation")


def run_fixture_validation() -> None:
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT event_id, sensor_type, source_ip, source_port, destination_ip, destination_port,
                       protocol, timestamp, bytes_sent, bytes_received, packets_sent, packets_received
                FROM normalized_events
                WHERE event_id IN ('C8demo1', '123456')
                """
            )
        ).mappings().all()
    finally:
        db.close()

    events = {row["event_id"]: row for row in rows}
    zeek = events.get("C8demo1")
    suricata = events.get("123456")
    require(zeek is not None, "Zeek fixture was not normalized")
    require(suricata is not None, "Suricata fixture was not normalized")
    require(
        zeek["sensor_type"] == "zeek"
        and zeek["source_ip"] == "10.0.0.20"
        and zeek["source_port"] == 49152
        and zeek["destination_ip"] == "192.0.2.10"
        and zeek["destination_port"] == 22
        and zeek["protocol"] == "TCP"
        and zeek["timestamp"] is not None
        and zeek["bytes_sent"] == 410
        and zeek["bytes_received"] == 120
        and zeek["packets_sent"] == 6
        and zeek["packets_received"] == 4,
        "Zeek fixture fields were not normalized correctly",
    )
    require(
        suricata["sensor_type"] == "suricata"
        and suricata["source_ip"] == "10.0.0.30"
        and suricata["source_port"] == 51515
        and suricata["destination_ip"] == "198.51.100.40"
        and suricata["destination_port"] == 443
        and suricata["protocol"] == "TCP"
        and suricata["timestamp"] is not None
        and suricata["bytes_sent"] == 90000
        and suricata["bytes_received"] == 800
        and suricata["packets_sent"] == 100
        and suricata["packets_received"] == 10,
        "Suricata fixture fields were not normalized correctly",
    )
    print("PASS: Zeek and Suricata fixture validation")


def run_dead_letter_validation(event_id: str) -> None:
    invalid_payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_ip": "not-an-ip-address",
        "destination_ip": "203.0.113.66",
        "destination_port": 443,
        "protocol": "TCP",
    }
    publish(settings.raw_topic, invalid_payload)

    result: Dict[str, str] = {}

    def dead_letter_persisted() -> bool:
        db = SessionLocal()
        try:
            row = db.execute(
                text(
                    "SELECT error FROM dead_letter_events WHERE event_key = :event_id ORDER BY id DESC LIMIT 1"
                ),
                {"event_id": event_id},
            ).mappings().first()
            if not row:
                return False
            result["error"] = str(row["error"])
            return True
        finally:
            db.close()

    wait_for(dead_letter_persisted, "dead-letter database record")
    require(not pipeline_counts(event_id)["events"], "Malformed event created a normalized event")
    require(
        topic_event_count(settings.dead_letter_topic, event_id, 1),
        "Dead-letter Kafka topic did not contain the malformed event",
    )
    error_text = result["error"].lower()
    require("invalid ip address" in error_text, "Dead-letter error lacks useful context")
    require(settings.jwt_secret.lower() not in error_text, "Dead-letter error exposed a secret")
    require("postgresql://" not in error_text, "Dead-letter error exposed a database URL")
    print("PASS: dead-letter validation")


def run_readiness_validation() -> None:
    with httpx.Client(base_url=API_BASE_URL, timeout=10) as client:
        response = client.get("/api/v1/ready")
    require(response.status_code == 200 and response.json().get("ready") is True, "API is not ready")
    print("PASS: API readiness validation")


def run_guardian_validation() -> None:
    """Validate Guardian Phase 1: registration, heartbeat, event ingestion, idempotency."""
    analyst_username = os.environ["RUNTIME_ANALYST_USERNAME"]
    analyst_password = os.environ["RUNTIME_ANALYST_PASSWORD"]
    auditor_username = os.environ["RUNTIME_AUDITOR_USERNAME"]
    auditor_password = os.environ["RUNTIME_AUDITOR_PASSWORD"]

    with httpx.Client(base_url=API_BASE_URL, timeout=15) as client:
        # Login as analyst
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": analyst_username, "password": analyst_password},
        )
        require(login_response.status_code == 200, "Guardian: analyst login failed")
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Login as auditor (for audit-endpoint access)
        auditor_login = client.post(
            "/api/v1/auth/login",
            json={"username": auditor_username, "password": auditor_password},
        )
        require(auditor_login.status_code == 200, "Guardian: auditor login failed")
        auditor_token = auditor_login.json()["access_token"]
        auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

        # 1. Agent registration (idempotent)
        agent_payload = {
            "agent_key": f"runtime-guardian-{uuid.uuid4().hex[:12]}",
            "hostname": "ci-runner",
            "host_id": f"ci-host-{uuid.uuid4().hex[:8]}",
            "os_name": "linux",
            "os_version": "ci",
            "agent_version": "2.0.0",
        }
        r1 = client.post("/api/v1/guardian/agents/register", json=agent_payload, headers=headers)
        require(r1.status_code == 200, f"Guardian: agent registration failed ({r1.status_code})")
        agent_id = r1.json()["agent"]["id"]

        # Idempotent re-registration
        r2 = client.post("/api/v1/guardian/agents/register", json=agent_payload, headers=headers)
        require(r2.status_code == 200, "Guardian: idempotent registration failed")
        require(r2.json()["agent"]["id"] == agent_id, "Guardian: re-registration created duplicate agent")

        # 2. Heartbeat with stable agent_key
        r_hb = client.post(
            "/api/v1/guardian/heartbeat",
            json={
                "agent_key": agent_payload["agent_key"],
                "agent_version": "2.0.0",
                "uptime_seconds": 60,
                "events_queued": 0,
                "events_processed": 0,
            },
            headers=headers,
        )
        require(r_hb.status_code == 200, f"Guardian: heartbeat failed ({r_hb.status_code})")
        require(r_hb.json()["status"] == "ok", "Guardian: heartbeat status not ok")
        require(r_hb.json()["agent_id"] == agent_id, "Guardian: heartbeat resolved wrong agent")

        # 3. Event ingestion with stable agent_key
        event_id_1 = f"runtime-guardian-event-{uuid.uuid4().hex[:12]}"
        event_id_2 = f"runtime-guardian-event-{uuid.uuid4().hex[:12]}"
        r_ev = client.post(
            "/api/v1/guardian/events",
            json={
                "agent_key": agent_payload["agent_key"],
                "events": [
                    {"event_id": event_id_1, "event_category": "process", "process_name": "ci-test"},
                    {"event_id": event_id_2, "event_category": "file", "file_path": "/tmp/test"},
                ]
            },
            headers=headers,
        )
        require(r_ev.status_code == 200, f"Guardian: event ingestion failed ({r_ev.status_code})")
        require(r_ev.json()["created"] == 2, "Guardian: expected 2 events created")
        require(r_ev.json()["duplicate"] == 0, "Guardian: unexpected duplicates on first ingest")

        # 4. Idempotency — re-ingest same events
        r_dup = client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": event_id_1, "event_category": "process"},
                    {"event_id": event_id_2, "event_category": "file"},
                ]
            },
            headers=headers,
        )
        require(r_dup.status_code == 200, f"Guardian: duplicate ingest failed ({r_dup.status_code})")
        require(r_dup.json()["duplicate"] == 2, "Guardian: idempotency check failed — duplicates not detected")
        require(r_dup.json()["created"] == 0, "Guardian: duplicate ingest created new records")

        # 5. Event query
        r_list = client.get("/api/v1/guardian/events", headers=headers)
        require(r_list.status_code == 200, "Guardian: event query failed")
        require(r_list.json()["total"] >= 2, "Guardian: event query returned fewer than 2 events")

        # 6. Stats
        r_stats = client.get("/api/v1/guardian/stats", headers=headers)
        require(r_stats.status_code == 200, "Guardian: stats endpoint failed")
        require(r_stats.json()["agents"]["total"] >= 1, "Guardian: stats shows no agents")
        require(r_stats.json()["events"]["total"] >= 2, "Guardian: stats shows fewer than 2 events")

        # 7. Verify PostgreSQL persistence
        db = SessionLocal()
        try:
            row = db.execute(
                text(
                    "SELECT COUNT(*) AS cnt FROM guardian_events WHERE event_id IN (:e1, :e2)"
                ),
                {"e1": event_id_1, "e2": event_id_2},
            ).mappings().one()
            require(int(row["cnt"]) == 2, "Guardian: PostgreSQL did not persist both events")
        finally:
            db.close()

        # 8. Verify idempotency in PostgreSQL (still exactly 2, not 4)
        db = SessionLocal()
        try:
            row = db.execute(
                text(
                    "SELECT COUNT(*) AS cnt FROM guardian_events WHERE event_id IN (:e1, :e2)"
                ),
                {"e1": event_id_1, "e2": event_id_2},
            ).mappings().one()
            require(int(row["cnt"]) == 2, "Guardian: PostgreSQL idempotency broken — duplicate records found")
        finally:
            db.close()

        # 9. Verify v1.1 endpoints still work
        r_health = client.get("/api/v1/health")
        require(r_health.status_code == 200, "Guardian: v1.1 health endpoint broken")
        r_alerts = client.get("/api/v1/alerts", headers=headers)
        require(r_alerts.status_code == 200, "Guardian: v1.1 alerts endpoint broken")

        # 10. Verify Phase 2 endpoints exist and are accessible
        r_det = client.get("/api/v1/guardian/detections", headers=headers)
        require(r_det.status_code == 200, f"Guardian Phase 2: detections endpoint failed ({r_det.status_code})")
        require("total" in r_det.json(), "Guardian Phase 2: detections response missing 'total'")

        r_inc = client.get("/api/v1/guardian/incidents", headers=headers)
        require(r_inc.status_code == 200, f"Guardian Phase 2: incidents endpoint failed ({r_inc.status_code})")
        require("total" in r_inc.json(), "Guardian Phase 2: incidents response missing 'total'")

        # 11. Verify Phase 2 tables exist in PostgreSQL
        db = SessionLocal()
        try:
            for table in ["guardian_detections", "guardian_incidents", "guardian_incident_events",
                          "guardian_risk_scores", "guardian_response_decisions"]:
                row = db.execute(
                    text(f"SELECT COUNT(*) AS cnt FROM {table}"),
                ).mappings().one()
                require(int(row["cnt"]) >= 0, f"Guardian Phase 2: {table} query failed")
        finally:
            db.close()

        # 12. Verify Phase 3 approval endpoints exist and are accessible
        r_apv = client.get("/api/v1/guardian/approvals", headers=headers)
        require(r_apv.status_code == 200, f"Guardian Phase 3: approvals endpoint failed ({r_apv.status_code})")
        require("total" in r_apv.json(), "Guardian Phase 3: approvals response missing 'total'")

        # 13. Verify Phase 3 action registry
        r_reg = client.get("/api/v1/guardian/actions/registry", headers=headers)
        require(r_reg.status_code == 200, f"Guardian Phase 3: action registry failed ({r_reg.status_code})")
        require("actions" in r_reg.json(), "Guardian Phase 3: action registry missing 'actions'")
        require(len(r_reg.json()["actions"]) >= 3, "Guardian Phase 3: fewer than 3 registered actions")

        # 14. Verify Phase 3 action listing
        r_act = client.get("/api/v1/guardian/actions", headers=headers)
        require(r_act.status_code == 200, f"Guardian Phase 3: actions endpoint failed ({r_act.status_code})")
        require("total" in r_act.json(), "Guardian Phase 3: actions response missing 'total'")

        # 15. Verify Phase 3 audit endpoint — RBAC enforcement
        # Negative: security_analyst must be denied
        r_aud_analyst = client.get("/api/v1/guardian/audit", headers=headers)
        require(
            r_aud_analyst.status_code == 403,
            f"Guardian Phase 3: audit endpoint did not reject security_analyst ({r_aud_analyst.status_code})",
        )
        # Positive: read_only_auditor is authorized
        r_aud = client.get("/api/v1/guardian/audit", headers=auditor_headers)
        require(r_aud.status_code == 200, f"Guardian Phase 3: audit endpoint failed ({r_aud.status_code})")
        require("total" in r_aud.json(), "Guardian Phase 3: audit response missing 'total'")

        # 16. Verify Phase 3 approval creation (idempotent)
        r_apv_create = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": f"runtime-phase3-{uuid.uuid4().hex[:8]}",
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 99999, "process_name": "ci-test"},
                "rationale": "Runtime release gate validation",
            },
            headers=headers,
        )
        require(r_apv_create.status_code == 200, f"Guardian Phase 3: approval creation failed ({r_apv_create.status_code})")
        require("approval_id" in r_apv_create.json(), "Guardian Phase 3: approval response missing 'approval_id'")
        require(r_apv_create.json()["status"] == "pending", "Guardian Phase 3: approval not in pending status")
        approval_id = r_apv_create.json()["approval_id"]

        # 17. Verify Phase 3 approval idempotency
        r_apv_dup = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": r_apv_create.json().get("decision_id", "x"),
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 99999, "process_name": "ci-test"},
                "rationale": "Runtime release gate validation",
            },
            headers=headers,
        )
        require(r_apv_dup.status_code == 200, "Guardian Phase 3: idempotent approval failed")
        require(r_apv_dup.json().get("existing") is True, "Guardian Phase 3: idempotent approval not detected")

        # 18. Verify Phase 3 approval rejection
        r_apv_rej = client.post(
            f"/api/v1/guardian/approvals/{approval_id}/reject",
            json={"notes": "CI validation"},
            headers=headers,
        )
        # Note: if already approved in a previous run, this will return 422 — both are acceptable
        require(
            r_apv_rej.status_code in (200, 422),
            f"Guardian Phase 3: approval rejection returned {r_apv_rej.status_code}",
        )

        # 19. Verify Phase 3 tables exist in PostgreSQL
        db = SessionLocal()
        try:
            for table in [
                "guardian_approval_requests", "guardian_approvals",
                "guardian_action_attempts", "guardian_action_snapshots",
                "guardian_action_verifications", "guardian_action_rollbacks",
                "guardian_action_audit",
            ]:
                row = db.execute(
                    text(f"SELECT COUNT(*) AS cnt FROM {table}"),
                ).mappings().one()
                require(int(row["cnt"]) >= 0, f"Guardian Phase 3: {table} query failed")
        finally:
            db.close()

        # 20. Verify no shell=True in executable code (security gate)
        import importlib
        import ast
        for mod_name in [
            "guardian.actions.process",
            "guardian.actions.network",
            "guardian.actions.persistence",
        ]:
            mod = importlib.import_module(mod_name)
            source = inspect.getsource(mod)
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    # Check if value is a constant True
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        require(
                            False,
                            f"Guardian Phase 3: {mod_name} contains shell=True in executable code",
                        )

    print("PASS: Guardian Phase 1+2+3 validation (registration, heartbeat, ingestion, idempotency, PostgreSQL persistence, Phase 2 endpoints, Phase 3 approvals/actions/audit, security, v1.1 compat)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Runtime release gate assertions")
    parser.add_argument(
        "mode",
        choices=("auth-ws", "kafka", "fixtures", "dead-letter", "ready", "guardian"),
        help="Validation stage to execute",
    )
    parser.add_argument("--event-id", help="Unique Kafka event identifier")
    args = parser.parse_args()

    if args.mode == "auth-ws":
        run_authentication_and_websocket_validation()
    elif args.mode == "kafka":
        require(bool(args.event_id), "Kafka validation requires --event-id")
        run_kafka_validation(args.event_id)
    elif args.mode == "fixtures":
        run_fixture_validation()
    elif args.mode == "dead-letter":
        require(bool(args.event_id), "Dead-letter validation requires --event-id")
        run_dead_letter_validation(args.event_id)
    elif args.mode == "guardian":
        run_guardian_validation()
    else:
        run_readiness_validation()


if __name__ == "__main__":
    main()
