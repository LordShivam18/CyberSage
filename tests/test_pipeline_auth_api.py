from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import backend.main as main_module
from backend.auth import (
    ROLE_ANALYST,
    ROLE_AUDITOR,
    create_access_token,
    create_user,
    decode_access_token,
    hash_password,
    verify_password,
)
from backend.database import Base, get_db
from backend.models import Alert, ThreatIntelCache
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
            assert set(predict_response.json()) == {"prediction", "probability"}
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
