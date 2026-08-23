"""Read the repository's authoritative CyberSage release version."""

from pathlib import Path


def release_version() -> str:
    version_path = Path(__file__).resolve().parent.parent / "VERSION"
    value = version_path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("VERSION must contain the CyberSage release version")
    return value
