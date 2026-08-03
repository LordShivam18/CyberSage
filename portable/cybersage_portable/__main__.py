"""
CyberSage Portable Assessment — CLI entry point.

Usage
-----
  cybersage-portable scan
  cybersage-portable scan --output reports --privacy-mode redacted
  cybersage-portable show-report <report.json>
  cybersage-portable compare old.json new.json
  cybersage-portable import-report <report.json> --server https://... --token ...

All paths are relative-capable so the tool works from removable storage.
No permanent installation required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import DISCLAIMER, __version__
from .models import PrivacyMode


def _cmd_scan(args: argparse.Namespace) -> int:
    from .runner import AssessmentRunner
    from .report import write_json_report, write_html_report, print_terminal_summary, serialise_run

    try:
        mode = PrivacyMode(args.privacy_mode)
    except ValueError:
        print(f"ERROR: Invalid privacy mode '{args.privacy_mode}'. Choose: standard, redacted, minimal", file=sys.stderr)
        return 2

    output_dir = Path(args.output).resolve()

    print(f"CyberSage Portable Assessment v{__version__}")
    print(f"Privacy mode: {mode.value}")
    print("Starting assessment... (this may take 1–3 minutes)")
    print(DISCLAIMER)
    print()

    runner = AssessmentRunner(privacy_mode=mode)
    run = runner.run()

    report_dict = serialise_run(run)

    json_path = write_json_report(run, output_dir)
    print(f"JSON report: {json_path}")

    html_path = write_html_report(run, output_dir, report_dict=report_dict)
    print(f"HTML report: {html_path}")

    print_terminal_summary(run, report_dict=report_dict)
    return 0


def _cmd_show_report(args: argparse.Namespace) -> int:
    from .models import verify_checksum
    from .report import print_terminal_summary

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"ERROR: Report file not found: {report_path}", file=sys.stderr)
        return 2

    try:
        report_dict = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"ERROR: Cannot parse report: {exc}", file=sys.stderr)
        return 2

    if not verify_checksum(report_dict):
        print("WARNING: Report checksum does not match — the file may have been modified.", file=sys.stderr)

    # Print as a dummy run summary from the dict
    class _FakeRun:
        assessment_id = report_dict.get("assessment_id", "unknown")
        privilege_level = report_dict.get("privilege_level", "unknown")
        privacy_mode = type("M", (), {"value": report_dict.get("privacy_mode", "unknown")})()

    print_terminal_summary(_FakeRun(), report_dict=report_dict)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    from .compare import compare_reports

    old_path = Path(args.old_report)
    new_path = Path(args.new_report)

    for p in (old_path, new_path):
        if not p.exists():
            print(f"ERROR: File not found: {p}", file=sys.stderr)
            return 2

    try:
        old_dict = json.loads(old_path.read_text(encoding="utf-8"))
        new_dict = json.loads(new_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"ERROR: Cannot parse report: {exc}", file=sys.stderr)
        return 2

    diff = compare_reports(old_dict, new_dict)

    print(json.dumps(diff, indent=2, ensure_ascii=True))
    s = diff.get("summary", {})
    print(f"\nSummary: {s.get('new_findings')} new | {s.get('resolved_findings')} resolved | "
          f"{s.get('severity_changes')} severity changes | {s.get('new_exposed_ports')} new exposed ports",
          file=sys.stderr)
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    from .importer import import_to_server

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"ERROR: Report file not found: {report_path}", file=sys.stderr)
        return 2

    if not args.server or not args.token:
        print("ERROR: --server and --token are required for import.", file=sys.stderr)
        return 2

    print(f"Importing {report_path} to {args.server} ...")
    try:
        result = import_to_server(
            args.server,
            args.token,
            report_path,
            create_alerts=args.create_alerts,
        )
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersage-portable",
        description="CyberSage Portable Security Assessment — offline, read-only Windows scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DISCLAIMER,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subs = parser.add_subparsers(dest="command", required=True)

    # scan
    scan = subs.add_parser("scan", help="Run a security assessment of the current device.")
    scan.add_argument("--output", default="reports", help="Directory for output reports (default: reports/)")
    scan.add_argument(
        "--privacy-mode",
        default="standard",
        choices=["standard", "redacted", "minimal"],
        help="Redaction level (default: standard)",
    )

    # show-report
    show = subs.add_parser("show-report", help="Display a previously generated report.")
    show.add_argument("report", help="Path to JSON report file.")

    # compare
    compare = subs.add_parser("compare", help="Compare two assessment reports.")
    compare.add_argument("old_report", help="Path to older JSON report.")
    compare.add_argument("new_report", help="Path to newer JSON report.")

    # import-report
    imp = subs.add_parser("import-report", help="Import a report to the CyberSage backend (requires server access).")
    imp.add_argument("report", help="Path to JSON report file.")
    imp.add_argument("--server", required=True, help="CyberSage backend URL (e.g. https://cybersage.example.com)")
    imp.add_argument("--token", required=True, help="Bearer token for authentication.")
    imp.add_argument(
        "--create-alerts",
        action="store_true",
        default=False,
        help="Request backend alert creation for high-severity findings (requires analyst/admin role).",
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    handlers = {
        "scan": _cmd_scan,
        "show-report": _cmd_show_report,
        "compare": _cmd_compare,
        "import-report": _cmd_import,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(2)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
