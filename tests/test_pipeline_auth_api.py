from datetime import timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import backend.main as main_module
from backend.auth import (
    ROLE_ANALYST,
    ROLE_AUDITOR,
    create_access_token,
    decode_access_token,
    create_user,
    hash_password,
    verify_password,
)
from backend.database import Base, get_db
from backend.migrations.runner import run_migrations
from backend.models import Alert, Incident, ThreatIntelCache
from backend.pipeline import process_payload


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_password_hashing_and_jwt_round_trip():
    password_hash = hash_password("correct-horse-battery")
    assert verify_password("correct-horse-battery", password_hash)
    assert not verify_password("wrong-password", password_hash)

    SessionTesting = make_session()
    db = SessionTesting()
    try:
        user = create_user(db, "analyst", "correct-horse-battery", ROLE_ANALYST)
        token = create_access_token(user)
        payload = decode_access_token(token)
        assert payload["sub"] == "analyst"
        assert payload["role"] == ROLE_ANALYST
        expired = create_access_token(user, expires_delta=timedelta(seconds=-1))
        with pytest.raises(Exception):
            decode_access_token(expired)
        with pytest.raises(Exception):
            decode_access_token("malformed.token")
    finally:
        db.close()


def test_pipeline_creates_alert_and_incident_idempotently():
    SessionTesting = make_session()
    db = SessionTesting()
    payload = {
        "event_id": "idem-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source_ip": "10.0.0.5",
        "destination_ip": "203.0.113.66",
        "destination_port": 443,
        "protocol": "TCP",
        "flow_duration": 119999872,
        "tot_fwd_pkts": 100,
        "tot_bwd_pkts": 200,
        "totlen_fwd_pkts": 50000,
    }
    try:
        first = process_payload(payload, db)
        second = process_payload(payload, db)
        db.commit()

        assert first["alert"] is not None
        assert first["incident"] is not None
        assert second["created"] is False
        assert db.query(Alert).count() == 1
        assert db.query(ThreatIntelCache).count() >= 1
    finally:
        db.close()


def test_incident_correlation_separates_distant_activity():
    SessionTesting = make_session()
    db = SessionTesting()
    base_payload = {
        "source_ip": "10.0.0.5",
        "destination_ip": "203.0.113.66",
        "destination_port": 443,
        "protocol": "TCP",
        "flow_duration": 119999872,
        "tot_fwd_pkts": 100,
        "tot_bwd_pkts": 200,
        "totlen_fwd_pkts": 50000,
    }
    try:
        process_payload({**base_payload, "event_id": "sep-1", "timestamp": "2026-01-01T00:00:00Z"}, db)
        process_payload({**base_payload, "event_id": "sep-2", "timestamp": "2026-01-01T03:00:00Z"}, db)
        db.commit()

        assert db.query(Incident).count() == 2
    finally:
        db.close()


def test_legacy_alert_preserved_during_migration():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY,
                    timestamp TIMESTAMP,
                    prediction VARCHAR,
                    probability FLOAT,
                    details TEXT
                )
                """
            )
        )
        connection.execute(
            text(
                "INSERT INTO alerts (id, timestamp, prediction, probability, details) "
                "VALUES (1, '2026-01-01 00:00:00', 'ATTACK', 0.95, '{\"legacy\": true}')"
            )
        )

    run_migrations(engine)

    with engine.begin() as connection:
        row = connection.execute(text("SELECT prediction, probability, status, severity FROM alerts WHERE id = 1")).first()
    assert tuple(row) == ("ATTACK", 0.95, "new", "high")


def test_api_alert_pagination_and_filtering(monkeypatch):
    object.__setattr__(main_module.settings, "auto_migrate", False)
    SessionTesting = make_session()
    db = SessionTesting()
    db.add(Alert(prediction="ATTACK", probability=0.9, details="{}", severity="high", status="new", classification="ATTACK"))
    db.add(Alert(prediction="ATTACK", probability=0.5, details="{}", severity="low", status="resolved", classification="BENIGN"))
    db.commit()
    db.close()

    def override_get_db():
        session = SessionTesting()
        try:
            yield session
        finally:
            session.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main_module.app) as client:
            response = client.get("/api/v1/alerts?severity=high")
            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert data["items"][0]["severity"] == "high"

            predict_response = client.post(
                "/predict",
                json={
                    "flow_duration": 83,
                    "tot_fwd_pkts": 2,
                    "tot_bwd_pkts": 2,
                    "totlen_fwd_pkts": 12,
                    "fwd_pkt_len_max": 6,
                    "fwd_pkt_len_min": 6,
                    "fwd_pkt_len_mean": 6.0,
                    "bwd_pkt_len_max": 6,
                    "flow_iat_mean": 27.6,
                    "flow_iat_max": 80,
                    "fwd_iat_tot": 83.0,
                },
            )
            assert predict_response.status_code == 200
            assert {"prediction", "probability", "degraded", "model_available"}.issubset(predict_response.json())
    finally:
        main_module.app.dependency_overrides.clear()


def test_api_role_permissions_for_alert_updates(monkeypatch):
    object.__setattr__(main_module.settings, "auto_migrate", False)
    SessionTesting = make_session()
    db = SessionTesting()
    analyst = create_user(db, "role-analyst", "correct-horse-battery", ROLE_ANALYST)
    auditor = create_user(db, "role-auditor", "correct-horse-battery", ROLE_AUDITOR)
    alert = Alert(
        prediction="ATTACK",
        probability=0.9,
        details="{}",
        severity="high",
        status="new",
        classification="ATTACK",
    )
    db.add(alert)
    db.commit()
    alert_id = alert.id
    analyst_token = create_access_token(analyst)
    auditor_token = create_access_token(auditor)
    db.close()

    def override_get_db():
        session = SessionTesting()
        try:
            yield session
        finally:
            session.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main_module.app) as client:
            auditor_response = client.patch(
                f"/api/v1/alerts/{alert_id}",
                json={"status": "acknowledged"},
                headers={"Authorization": f"Bearer {auditor_token}"},
            )
            assert auditor_response.status_code == 403

            analyst_response = client.patch(
                f"/api/v1/alerts/{alert_id}",
                json={"status": "acknowledged"},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )
            assert analyst_response.status_code == 200
            assert analyst_response.json()["status"] == "acknowledged"
    finally:
        main_module.app.dependency_overrides.clear()


def test_model_unavailable_predict_response_is_not_silent(monkeypatch):
    object.__setattr__(main_module.settings, "auto_migrate", False)
    SessionTesting = make_session()

    class FakeModelDetector:
        def status(self):
            return {
                "available": False,
                "model_name": "fake-fallback",
                "model_version": "fallback",
                "fallback_reason": "test missing model",
            }

    monkeypatch.setattr(main_module, "model_detector", FakeModelDetector())
    monkeypatch.setattr(main_module, "run_prediction", lambda _flow: ("BENIGN", 0.6))

    def override_get_db():
        session = SessionTesting()
        try:
            yield session
        finally:
            session.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main_module.app) as client:
            response = client.post(
                "/predict",
                json={
                    "flow_duration": 1,
                    "tot_fwd_pkts": 1,
                    "tot_bwd_pkts": 1,
                    "totlen_fwd_pkts": 1,
                    "fwd_pkt_len_max": 1,
                    "fwd_pkt_len_min": 0,
                    "fwd_pkt_len_mean": 1,
                    "bwd_pkt_len_max": 1,
                    "flow_iat_mean": 1,
                    "flow_iat_max": 1,
                    "fwd_iat_tot": 1,
                },
            )
        assert response.json()["degraded"] is True
        assert response.json()["warning"] == "test missing model"
    finally:
        main_module.app.dependency_overrides.clear()


def test_unauthorized_websocket_connection_is_rejected():
    object.__setattr__(main_module.settings, "auto_migrate", False)
    SessionTesting = make_session()

    def override_get_db():
        session = SessionTesting()
        try:
            yield session
        finally:
            session.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main_module.app) as client:
            with pytest.raises(Exception):
                with client.websocket_connect("/api/v1/ws/alerts"):
                    pass
    finally:
        main_module.app.dependency_overrides.clear()
