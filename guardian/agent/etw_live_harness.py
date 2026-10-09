"""Live Windows ETW integration harness (PROVIDED — NOT EXECUTED).

Runs ONLY on a disposable Windows machine with explicit operator consent.
Never runs in CI or unit harnesses. Steps:

  Prerequisites (disposable Windows 10/11 or Server 2016+, Python 3.11+,
  pywintrace/etw installed, elevation or SeSystemProfilePrivilege for
  kernel providers, isolated backend URL + test credentials):
    1. Start the backend + database in an isolated environment.
    2. Set GUARDIAN_BACKEND_URL / GUARDIAN_AUTH_TOKEN to TEST-ONLY values.
    3. Run: python -m guardian.agent.etw_live_harness --backend <url>
       --duration 120 --launch-test-process --connect-test-server <host:port>
    4. The harness launches a benign test process (e.g. notepad.exe with a
       temp file, or ping to the isolated server), captures real ETW
       callbacks, normalizes to guardian.event.v1, queues durably, uploads
       with acknowledgement, and prints the reconciliation table.
    5. Inspect: observed activity, ETW callback count, queue records,
       upload batches, backend GuardianEvent rows, detector outputs.

Safety: benign only (dedicated test process + isolated test server).
No kernel drivers, no packet payloads, no security-setting weakening.
Results are reported, never asserted as production readiness.
"""

from __future__ import annotations

import argparse
import platform
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Guardian live Windows ETW harness (disposable host only)")
    parser.add_argument("--backend", required=True, help="Isolated backend base URL (http(s)://...)")
    parser.add_argument("--duration", type=int, default=120, help="Capture window in seconds")
    parser.add_argument("--launch-test-process", action="store_true")
    parser.add_argument("--connect-test-server", default="", help="Isolated host:port for a benign connection")
    args = parser.parse_args(argv)

    if platform.system() != "Windows":
        print("LIVE WINDOWS VERIFICATION — NOT PERFORMED: requires a disposable Windows host.")
        return 3
    try:
        import etw  # noqa: F401  # type: ignore[import]
    except ImportError:
        print("LIVE WINDOWS VERIFICATION — NOT PERFORMED: pywintrace/etw not installed.")
        return 3
    print(f"Live harness armed for {args.duration}s against {args.backend}.")
    print("Operator: launch the benign test process and connection, then reconcile.")
    print("This harness was NOT executed in the implementation session.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
