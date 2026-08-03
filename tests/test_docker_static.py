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
