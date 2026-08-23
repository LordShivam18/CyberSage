"""Validate that buildable CyberSage components use the root VERSION source."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

try:
    from .release_metadata import ReleaseMetadataError, read_version
except ImportError:  # Direct script execution from the repository root.
    from release_metadata import ReleaseMetadataError, read_version


def validate_version_contract(repo_root: str | Path) -> str:
    root = Path(repo_root).resolve()
    version = read_version(root / "VERSION")
    frontend = json.loads((root / "frontend" / "package.json").read_text(encoding="utf-8"))
    if frontend.get("version") != version:
        raise ReleaseMetadataError("frontend/package.json version does not match VERSION")
    pyproject = tomllib.loads((root / "portable" / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    if "version" in project or "version" not in project.get("dynamic", []):
        raise ReleaseMetadataError("portable/pyproject.toml must derive version dynamically from VERSION")
    dynamic = pyproject.get("tool", {}).get("setuptools", {}).get("dynamic", {}).get("version", {})
    if dynamic.get("attr") != "cybersage_portable.__version__":
        raise ReleaseMetadataError("portable package version must resolve through cybersage_portable.__version__")
    sys.path.insert(0, str(root / "portable"))
    try:
        import cybersage_portable
    finally:
        sys.path.pop(0)
    if cybersage_portable.__version__ != version:
        raise ReleaseMetadataError("portable runtime version does not match VERSION")
    return version


if __name__ == "__main__":
    try:
        value = validate_version_contract(Path(__file__).resolve().parent.parent)
    except ReleaseMetadataError as exc:
        raise SystemExit(f"version contract validation failed: {exc}") from exc
    print(f"Validated CyberSage version contract: {value}")
