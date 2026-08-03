import argparse
import getpass
import json
from pathlib import Path

from .auth import ALL_ROLES, ROLE_ANALYST, create_user
from .config import settings
from .database import SessionLocal
from .migrations.runner import current_revision, run_migrations
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

    return parser


def main():
    settings.validate_runtime_security()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
