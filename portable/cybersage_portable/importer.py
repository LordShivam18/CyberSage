"""
Optional server-side import client.

Uploads a portable assessment report to the CyberSage backend.
All server synchronisation is EXPLICIT — no automatic upload ever occurs.

Usage:
    from cybersage_portable.importer import import_to_server
    result = import_to_server("https://cybersage.example.com", token, report_path)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _validate_url_scheme(url: str) -> None:
    """Reject URLs whose scheme is not in the permitted set.

    Only ``http`` and ``https`` are allowed.  This prevents misuse of
    ``urllib.request.urlopen`` to open ``file:``, ``ftp:``, or other
    dangerous schemes.

    Raises
    -----
    ValueError
        If the scheme is missing, empty, or not in ``_ALLOWED_SCHEMES``.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"URL scheme {scheme!r} is not permitted; "
            f"allowed schemes: {', '.join(sorted(_ALLOWED_SCHEMES))}"
        )


def import_to_server(
    base_url: str,
    token: str,
    report_path: Path,
    *,
    create_alerts: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Import a portable assessment report to the CyberSage backend.

    Parameters
    ----------
    base_url:
        Base URL of the CyberSage backend (e.g. ``https://cybersage.example.com``).
    token:
        Bearer token for authentication.
    report_path:
        Path to the JSON report file produced by the scanner.
    create_alerts:
        Whether to request alert creation for high-severity findings.
        Defaults to False.  The server enforces its own role check.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    Server response as a dict, or raises ``ImportError`` on failure.
    """
    if not base_url or not token:
        raise ValueError("base_url and token are required for server import")

    # Read and validate the report locally before transmitting.
    report_bytes = report_path.read_bytes()
    if len(report_bytes) > 10 * 1024 * 1024:  # 10 MB safety limit
        raise ValueError("Report file exceeds 10 MB — will not transmit")

    try:
        report_dict = json.loads(report_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Report file is not valid JSON: {exc}") from exc

    if report_dict.get("schema_version") != "assessment.v1":
        raise ValueError(f"Unsupported schema_version: {report_dict.get('schema_version')!r}")

    payload = json.dumps({
        "report": report_dict,
        "create_alerts": bool(create_alerts),
    }, ensure_ascii=True).encode("utf-8")

    url = f"{base_url.rstrip('/')}/api/v1/assessments/import"

    _validate_url_scheme(url)

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — scheme validated by _validate_url_scheme
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2048]
        raise RuntimeError(f"Server returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc
