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

## Local Governance Demo

Use only an authorized local dataset, then point a manifest at it. The checked-in manifest is an example and deliberately resolves no committed data.

```powershell
.\.venv\Scripts\python.exe -m backend.model_benchmark --manifest datasets\manifests\cic_ids2017.example.yaml --output results\benchmarks --split-strategy group
.\.venv\Scripts\python.exe -m backend.cli register-model results\benchmarks\<run>\artifacts\transformer.metadata.json
.\.venv\Scripts\python.exe -m backend.cli validate-model <model-version>
.\.venv\Scripts\python.exe -m backend.cli promote-model <model-version>
```

The dashboard's Model view exposes serving state, registry validation, held-out quality, calibration signals, known limitations, and drift status. It does not claim a candidate or fallback model is active.

## Notes

If model artifacts are missing, invalid, ungoverned, or inactive, the API reports fallback mode and still supports the synthetic demo. External threat-intelligence calls are disabled unless you implement and enable a provider explicitly.
