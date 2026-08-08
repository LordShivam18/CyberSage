from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_docker_compose_static_configuration():
    compose_path = ROOT / "docker-compose.yml"
    compose_text = compose_path.read_text()
    compose = yaml.safe_load(compose_text)
    services = compose["services"]

    assert "zookeeper" not in services
    assert {"kafka", "db", "migrate", "backend-api", "detection-worker", "frontend"}.issubset(services)
    assert (ROOT / services["backend-api"]["build"]["dockerfile"]).exists()
    assert (ROOT / services["frontend"]["build"]["dockerfile"]).exists()

    kafka = services["kafka"]
    kafka_env = kafka["environment"]
    assert kafka["image"] == "apache/kafka:3.9.2"
    assert kafka["hostname"] == "kafka"
    assert kafka_env["KAFKA_NODE_ID"] == 1
    assert kafka_env["KAFKA_PROCESS_ROLES"] == "broker,controller"
    assert kafka_env["KAFKA_CONTROLLER_QUORUM_VOTERS"] == "1@kafka:29093"
    assert kafka_env["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"] == (
        "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT"
    )
    assert kafka_env["KAFKA_LISTENERS"] == "CONTROLLER://:29093,PLAINTEXT://:9092,PLAINTEXT_HOST://:9094"
    assert kafka_env["KAFKA_ADVERTISED_LISTENERS"] == "PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:9094"
    assert kafka_env["KAFKA_INTER_BROKER_LISTENER_NAME"] == "PLAINTEXT"
    assert kafka_env["KAFKA_CONTROLLER_LISTENER_NAMES"] == "CONTROLLER"
    assert kafka_env["CLUSTER_ID"] == "4L6g3nShT-eMCtK--X86sw"
    assert kafka_env["KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR"] == 1
    assert kafka_env["KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR"] == 1
    assert kafka_env["KAFKA_TRANSACTION_STATE_LOG_MIN_ISR"] == 1
    assert kafka_env["KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS"] == 0
    assert kafka_env["KAFKA_AUTO_CREATE_TOPICS_ENABLE"] == "true"
    assert kafka_env["KAFKA_LOG_DIRS"] == "/tmp/kraft-combined-logs"
    assert kafka["healthcheck"]["test"] == [
        "CMD-SHELL",
        "/opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list >/dev/null 2>&1",
    ]
    assert kafka["healthcheck"]["retries"] == 15
    assert kafka["healthcheck"]["start_period"] == "20s"
    assert "volumes" not in kafka
    assert "zookeeper" not in compose_text.lower()
    assert "bitnami/kafka" not in compose_text
    assert "/bitnami/kafka" not in compose_text
    assert "KAFKA_CFG_" not in compose_text
    assert "ALLOW_PLAINTEXT_LISTENER" not in compose_text

    frontend = services["frontend"]
    frontend_healthcheck = frontend["healthcheck"]
    frontend_probe = frontend_healthcheck["test"]
    assert frontend_healthcheck["interval"] == "5s"
    assert frontend_healthcheck["timeout"] == "3s"
    assert frontend_healthcheck["retries"] == 30
    assert frontend_healthcheck["start_period"] == "20s"
    assert frontend_probe[0] == "CMD-SHELL"
    assert "node -e" in frontend_probe[1]
    assert "http://127.0.0.1:3000/" in frontend_probe[1]
    assert "curl" not in frontend_probe[1]
    assert "wget" not in frontend_probe[1]

    api_env = "\n".join(services["backend-api"]["environment"])
    worker_env = "\n".join(services["detection-worker"]["environment"])
    assert "KAFKA_BOOTSTRAP_SERVERS=kafka:9092" in api_env
    assert "KAFKA_BOOTSTRAP_SERVERS=kafka:9092" in worker_env
    assert "JWT_SECRET=${JWT_SECRET:?set JWT_SECRET}" in api_env
    readme = (ROOT / "README.md").read_text()
    assert "`kafka:9092`" in readme
    assert "`localhost:9094`" in readme
    assert "change-me" not in compose_text
    assert services["migrate"]["command"] == "python -m backend.cli migrate"

    workflow_text = (ROOT / ".github" / "workflows" / "runtime-release-gate.yml").read_text()
    assert "wait_for_service frontend healthy" in workflow_text
    assert "wait_for_service frontend running" not in workflow_text
    assert "frontend_ready=false" in workflow_text
    assert "curl --fail --silent --show-error --max-time 5 http://127.0.0.1:3000/" in workflow_text

def test_backend_dockerfile_contains_shared():
    dockerfile_path = ROOT / "backend" / "Dockerfile"
    content = dockerfile_path.read_text()
    assert "COPY shared /app/shared" in content
    
    dockerignore_path = ROOT / "backend" / ".dockerignore"
    if dockerignore_path.exists():
        assert "shared" not in dockerignore_path.read_text().splitlines()

    api_assessments = (ROOT / "backend" / "api_assessments.py").read_text()
    assert "from shared.report_contract import" in api_assessments
    assert not (ROOT / "backend" / "report_contract.py").exists()


def test_runtime_release_gate_schema_assertions():
    workflow_text = (ROOT / ".github" / "workflows" / "runtime-release-gate.yml").read_text()
    assert "('detections', 'score_components')" in workflow_text
    assert "('detections', 'risk_components')" not in workflow_text
    assert "('alerts', 'risk_components')" in workflow_text
    assert "'assessment_runs'" in workflow_text
    assert "'assessment_findings'" in workflow_text
    assert "001_platform_schema" in workflow_text
    assert "002_model_governance" in workflow_text
    assert "003_portable_assessment" in workflow_text
    assert "uq_assessment_run_finding" in workflow_text
    assert "ux_assessment_runs_assessment_id" in workflow_text
    assert "'jsonb'::regtype" in workflow_text


def test_migration_003_static_assertions():
    migration_path = ROOT / "backend" / "migrations" / "versions" / "portable_assessment_003.py"
    content = migration_path.read_text(encoding="utf-8")
    assert "conn.rollback()" not in content
    assert "except Exception:" not in content
    assert "CREATE INDEX IF NOT EXISTS" in content
    assert 'unique_sql = "UNIQUE " if unique else ""' in content
    assert 'f"CREATE {unique_sql}INDEX IF NOT EXISTS' in content
    assert '("ux_assessment_runs_assessment_id", "assessment_id", True)' in content


def test_migration_003_execution_idempotency():
    from sqlalchemy import create_engine, inspect
    from backend.database import Base
    from backend.migrations.versions import portable_assessment_003

    engine = create_engine("sqlite:///:memory:")
    # Pre-existing assessment table created via SQLAlchemy metadata
    Base.metadata.create_all(bind=engine)

    # First upgrade execution
    portable_assessment_003.upgrade(engine)

    insp = inspect(engine)
    indexes = {
        idx["name"]: idx
        for idx in insp.get_indexes("assessment_runs")
    }

    assert "ux_assessment_runs_assessment_id" in indexes
    assessment_index = indexes["ux_assessment_runs_assessment_id"]
    assert assessment_index["column_names"] == ["assessment_id"]
    assert assessment_index.get("unique") in (True, 1)

    # Verify assessment_findings indexes behaviorally
    findings_indexes = {
        idx["name"]: idx
        for idx in insp.get_indexes("assessment_findings")
    }
    required_findings_indexes = [
        "ix_assessment_findings_run_id",
        "ix_assessment_findings_check_id",
        "ix_assessment_findings_status",
        "ix_assessment_findings_severity",
        "ix_assessment_findings_category",
    ]
    for idx_name in required_findings_indexes:
        assert idx_name in findings_indexes

    # Re-running migration 003 must be idempotent and succeed without exception
    portable_assessment_003.upgrade(engine)


def test_legacy_migration_idempotency_workflow_assertions():
    workflow_text = (ROOT / ".github" / "workflows" / "runtime-release-gate.yml").read_text(encoding="utf-8")

    start = workflow_text.index(
        "- name: Validate legacy migration against temporary PostgreSQL database"
    )
    end = workflow_text.index(
        "- name: Create temporary runtime users through the CLI",
        start,
    )
    legacy_section = workflow_text[start:end]

    assert "1 / 0" not in legacy_section
    assert "RAISE EXCEPTION '001_platform_schema migration tracking is not idempotent'" in legacy_section
    assert "RAISE EXCEPTION '002_model_governance migration tracking is not idempotent'" in legacy_section
    assert "RAISE EXCEPTION '003_portable_assessment migration tracking is not idempotent'" in legacy_section

    assert legacy_section.count("docker compose run --rm --no-deps") >= 2

    assert "DROP DATABASE" in legacy_section
    assert "${LEGACY_DB}" in legacy_section
    assert "WITH (FORCE)" in legacy_section

    second_run = legacy_section.rfind("docker compose run --rm --no-deps")
    drop_db = legacy_section.rfind("DROP DATABASE")
    assert drop_db > second_run


def test_runtime_release_gate_script_assertions_and_unit_behavior(monkeypatch):
    import asyncio
    import importlib.util
    import inspect
    from unittest.mock import AsyncMock, MagicMock
    import pytest
    from websockets.exceptions import ConnectionClosed, InvalidHandshake

    script_path = ROOT / "scripts" / "runtime_release_gate.py"
    content = script_path.read_text(encoding="utf-8")

    # 1. Imports public exceptions from websockets.exceptions
    assert "from websockets.exceptions import ConnectionClosed, InvalidHandshake" in content

    # 2. Does not access websockets.exceptions as a top-level attribute
    assert "websockets.exceptions." not in content

    spec = importlib.util.spec_from_file_location("runtime_release_gate_mod", script_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    # 7. websocket_connect_kwargs supports both additional_headers and extra_headers
    mock_connect_new = MagicMock()
    mock_connect_new.__signature__ = inspect.Signature([
        inspect.Parameter("additional_headers", inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ])
    monkeypatch.setattr(gate.websockets, "connect", mock_connect_new)
    assert gate.websocket_connect_kwargs({"a": "b"}) == {"additional_headers": {"a": "b"}}

    mock_connect_old = MagicMock()
    mock_connect_old.__signature__ = inspect.Signature([
        inspect.Parameter("extra_headers", inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ])
    monkeypatch.setattr(gate.websockets, "connect", mock_connect_old)
    assert gate.websocket_connect_kwargs({"a": "b"}) == {"extra_headers": {"a": "b"}}

    # 3. InvalidHandshake subclass treated as successful rejection
    class _TestInvalidHandshake(InvalidHandshake):
        pass

    mock_cm_handshake = MagicMock()
    mock_cm_handshake.__aenter__ = AsyncMock(side_effect=_TestInvalidHandshake("test rejection"))
    mock_cm_handshake.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(gate.websockets, "connect", MagicMock(return_value=mock_cm_handshake))
    asyncio.run(gate.assert_websocket_rejected({}))

    # 4. ConnectionClosed treated as successful rejection
    mock_cm_closed = MagicMock()
    mock_cm_closed.__aenter__ = AsyncMock(side_effect=ConnectionClosed(None, None))
    mock_cm_closed.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(gate.websockets, "connect", MagicMock(return_value=mock_cm_closed))
    asyncio.run(gate.assert_websocket_rejected({}))

    # 5. asyncio.TimeoutError remains a failure
    mock_cm_timeout = MagicMock()
    mock_cm_timeout.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_cm_timeout.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(gate.websockets, "connect", MagicMock(return_value=mock_cm_timeout))
    with pytest.raises(AssertionError, match="Rejected WebSocket connection remained open"):
        asyncio.run(gate.assert_websocket_rejected({}))

    # 6. Accepted connection raises AssertionError
    mock_ws = MagicMock()
    mock_ws.recv = AsyncMock(return_value="hello")
    mock_cm_open = MagicMock()
    mock_cm_open.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_cm_open.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(gate.websockets, "connect", MagicMock(return_value=mock_cm_open))
    with pytest.raises(AssertionError, match="Unauthorized WebSocket connection was accepted"):
        asyncio.run(gate.assert_websocket_rejected({}))


def test_dead_letter_step_self_contained_event_id():
    workflow_text = (ROOT / ".github" / "workflows" / "runtime-release-gate.yml").read_text(encoding="utf-8")

    start = workflow_text.index("- name: Validate dead-letter handling")
    end = workflow_text.index("- name: Validate Kafka, PostgreSQL, and worker recovery", start)
    dead_letter_section = workflow_text[start:end]

    assert "set -euo pipefail" in dead_letter_section
    assert 'event_id="runtime-dead-letter-' in dead_letter_section
    assert "GITHUB_RUN_ID" in dead_letter_section
    assert "GITHUB_RUN_ATTEMPT" in dead_letter_section
    assert '--event-id "${event_id}"' in dead_letter_section
    assert "runtime-kafka-" not in dead_letter_section
    assert "detection-worker" in dead_letter_section
    assert "running" in dead_letter_section

    id_def = dead_letter_section.index('event_id="runtime-dead-letter-')
    id_use = dead_letter_section.index('--event-id "${event_id}"')
    assert id_def < id_use







