from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_docker_compose_static_configuration():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = compose["services"]

    assert "zookeeper" not in services
    assert {"kafka", "db", "migrate", "backend-api", "detection-worker", "frontend"}.issubset(services)
    assert (ROOT / services["backend-api"]["build"]["dockerfile"]).exists()
    assert (ROOT / services["frontend"]["build"]["dockerfile"]).exists()
    assert services["kafka"]["environment"]
    kafka_env = "\n".join(services["kafka"]["environment"])
    assert "KAFKA_CFG_PROCESS_ROLES=broker,controller" in kafka_env
    assert "CONTROLLER://:9093" in kafka_env
    assert "EXTERNAL://localhost:9094" in kafka_env
    assert "zookeeper" not in kafka_env.lower()

    api_env = "\n".join(services["backend-api"]["environment"])
    worker_env = "\n".join(services["detection-worker"]["environment"])
    assert "KAFKA_BOOTSTRAP_SERVERS=kafka:9092" in api_env
    assert "KAFKA_BOOTSTRAP_SERVERS=kafka:9092" in worker_env
    assert "JWT_SECRET=${JWT_SECRET:?set JWT_SECRET}" in api_env
    assert "change-me" not in (ROOT / "docker-compose.yml").read_text()
    assert services["migrate"]["command"] == "python -m backend.cli migrate"
