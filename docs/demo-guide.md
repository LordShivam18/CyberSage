# Demo Guide

All demo actions are for authorized lab use only.

## Docker Demo

```powershell
docker compose up -d --build
docker compose exec backend-api python -m backend.cli create-user --username analyst --role security_analyst
python -m backend.kafka_producer
```

Open `http://localhost:3000`, sign in with the user you created, and inspect the generated alert and incident.

## JSONL Demo Without Kafka

```powershell
python -m backend.cli migrate
python -m backend.cli process-jsonl tests\fixtures\zeek_conn.jsonl --source-hint zeek
python -m backend.cli process-jsonl tests\fixtures\suricata_eve.jsonl --source-hint suricata
```

## Useful API Calls

```powershell
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/model/status
curl "http://localhost:8000/api/v1/alerts?limit=10"
curl "http://localhost:8000/api/v1/incidents?limit=10"
```

## Notes

If model artifacts are missing, the API reports fallback mode and still supports the synthetic demo. External threat-intelligence calls are disabled unless you implement and enable a provider explicitly.
