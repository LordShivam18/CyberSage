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



