# Contributing

Thanks for helping improve this defensive lab platform.

## Ground Rules

- Work only with authorized lab telemetry.
- Do not add offensive automation, autonomous blocking, malware execution, persistence, credential attacks, or exploit workflows.
- Do not commit API keys, `.env` files, datasets, PCAPs, trained model artifacts, or credentials.
- Keep legacy `/predict` and `/alerts` behavior compatible unless a versioned replacement is added.
- Add migrations for database changes.

## Local Checks

```powershell
pytest -q
npm test --prefix frontend -- --watchAll=false
npm run build --prefix frontend
docker compose config
```

Document any check that cannot run in your environment.
