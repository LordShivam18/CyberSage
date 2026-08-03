import argparse
import getpass
import json
from pathlib import Path

from .auth import ALL_ROLES, ROLE_ANALYST, create_user
from .config import settings
from .database import SessionLocal
from .migrations.runner import current_revision, run_migrations
from .model_registry import archive_model, model_version_to_public, promote_model, register_model, validate_registered_model
from .pipeline import process_payload


def migrate(_args):
    run_migrations()
    print(f"Database migrated to {current_revision()}")


def bootstrap_user(args):
    password = args.password or getpass.getpass("Development user password: ")
    db = SessionLocal()
    try:
        user = create_user(db, args.username, password, args.role)
        db.commit()
        print(f"Created user '{user.username}' with role '{user.role}'")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def process_jsonl(args):
    path = Path(args.path)
    db = SessionLocal()
    created_alerts = 0
    processed = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                payload = json.loads(text)
                result = process_payload(
                    payload,
                    db,
                    source_hint=args.source_hint,
                    raw_reference=f"{path}:{line_number}",
                )
                processed += 1
                if result["alert"]:
                    created_alerts += 1
        db.commit()
        print(f"Processed {processed} events; {created_alerts} alerts are represented.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _quality_gates(value):
    if not value:
        return None
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("--quality-gates must be a JSON object")
    return parsed


def register_trained_model(args):
    run_migrations()
    db = SessionLocal()
    try:
        row = register_model(db, args.metadata, actor="cli")
        db.commit()
        print(json.dumps(model_version_to_public(row), indent=2, sort_keys=True, default=str))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def validate_trained_model(args):
    run_migrations()
    db = SessionLocal()
    try:
        row = validate_registered_model(db, args.version, _quality_gates(args.quality_gates), actor="cli")
        db.commit()
        print(json.dumps(model_version_to_public(row), indent=2, sort_keys=True, default=str))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def promote_trained_model(args):
    run_migrations()
    db = SessionLocal()
    try:
        row = promote_model(db, args.version, actor="cli")
        db.commit()
        print(json.dumps(model_version_to_public(row), indent=2, sort_keys=True, default=str))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def archive_trained_model(args):
    run_migrations()
    db = SessionLocal()
    try:
        row = archive_model(db, args.version, actor="cli")
        db.commit()
        print(json.dumps(model_version_to_public(row), indent=2, sort_keys=True, default=str))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def build_parser():
    parser = argparse.ArgumentParser(description="AI-assisted NDR platform utilities")
    subcommands = parser.add_subparsers(required=True)

    migrate_parser = subcommands.add_parser("migrate", help="Apply database migrations")
    migrate_parser.set_defaults(func=migrate)

    user_parser = subcommands.add_parser("create-user", help="Create a development user")
    user_parser.add_argument("--username", required=True)
    user_parser.add_argument("--password", help="Password; omit to prompt securely")
    user_parser.add_argument("--role", default=ROLE_ANALYST, choices=sorted(ALL_ROLES))
    user_parser.set_defaults(func=bootstrap_user)

    jsonl_parser = subcommands.add_parser(
        "process-jsonl",
        help="Process authorized lab telemetry from a JSONL file without Kafka",
    )
    jsonl_parser.add_argument("path")
    jsonl_parser.add_argument("--source-hint", choices=["synthetic", "zeek", "suricata"])
    jsonl_parser.set_defaults(func=process_jsonl)

    register_parser = subcommands.add_parser("register-model", help="Register a checksum-verified benchmark artifact")
    register_parser.add_argument("metadata", help="Path to a versioned artifact metadata JSON file")
    register_parser.set_defaults(func=register_trained_model)

    validate_parser = subcommands.add_parser("validate-model", help="Evaluate registry quality gates for a candidate")
    validate_parser.add_argument("version")
    validate_parser.add_argument("--quality-gates", help="Optional JSON object overriding documented development gates")
    validate_parser.set_defaults(func=validate_trained_model)

    promote_parser = subcommands.add_parser("promote-model", help="Promote a validated model after checksum verification")
    promote_parser.add_argument("version")
    promote_parser.set_defaults(func=promote_trained_model)

    archive_parser = subcommands.add_parser("archive-model", help="Archive a registered model version")
    archive_parser.add_argument("version")
    archive_parser.set_defaults(func=archive_trained_model)

    return parser


def main():
    settings.validate_runtime_security()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
