"""Create and validate CyberSage release provenance manifests.

The script intentionally uses only the standard library so a release can be
validated independently of the application environment. It never signs an
artifact and only records a signed status when a release workflow has actually
completed a configured signing operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


MANIFEST_SCHEMA_VERSION = "cybersage.release-manifest.v1"
PRODUCT_NAME = "CyberSage"
SIGNING_STATUSES = {"signed", "unsigned"}
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
DEPENDENCY_FILES = (
    "backend/requirements.txt",
    "frontend/package-lock.json",
    "portable/pyproject.toml",
    "security/requirements.txt",
)


class ReleaseMetadataError(ValueError):
    """Raised when a release artifact or provenance contract is invalid."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_version(path: str | Path) -> str:
    version_path = Path(path)
    if not version_path.is_file():
        raise ReleaseMetadataError(f"Authoritative version file is missing: {version_path}")
    version = version_path.read_text(encoding="utf-8").strip()
    if not SEMVER_PATTERN.fullmatch(version):
        raise ReleaseMetadataError("Authoritative version must use a semantic version such as 1.1.0")
    return version


def _safe_reference(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ReleaseMetadataError(f"{field} must be a non-empty filename without a path")
    return value


def _git_revision(repo_root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseMetadataError("Unable to determine the source Git revision") from exc


def _build_timestamp() -> str:
    source_date_epoch = os.getenv("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        try:
            return datetime.fromtimestamp(int(source_date_epoch), tz=timezone.utc).isoformat()
        except ValueError as exc:
            raise ReleaseMetadataError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    return datetime.now(timezone.utc).isoformat()


def validate_sbom(path: str | Path) -> Mapping[str, Any]:
    sbom_path = Path(path)
    if not sbom_path.is_file():
        raise ReleaseMetadataError(f"SBOM file is missing: {sbom_path}")
    try:
        value = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseMetadataError(f"SBOM is not valid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ReleaseMetadataError("SBOM root must be a JSON object")
    if value.get("bomFormat") != "CycloneDX":
        raise ReleaseMetadataError("SBOM must use the CycloneDX format")
    if not isinstance(value.get("specVersion"), str) or not value["specVersion"]:
        raise ReleaseMetadataError("SBOM must declare a CycloneDX specVersion")
    if not isinstance(value.get("components"), list):
        raise ReleaseMetadataError("SBOM must contain a components list generated from dependencies")
    return value


def dependency_state(repo_root: str | Path) -> list[dict[str, str]]:
    root = Path(repo_root).resolve()
    state = []
    for relative_path in DEPENDENCY_FILES:
        path = root / relative_path
        if not path.is_file():
            raise ReleaseMetadataError(f"Release dependency input is missing: {relative_path}")
        state.append({"path": relative_path, "sha256": sha256_file(path)})
    return state


def create_manifest(
    *,
    version_file: str | Path,
    artifact: str | Path,
    sbom: str | Path,
    component: str,
    build_identity: str,
    signing_status: str,
    signing_identity: str | None,
    repo_root: str | Path,
    source_revision: str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    artifact_path = Path(artifact).resolve()
    sbom_path = Path(sbom).resolve()
    version = read_version(version_file)
    if not artifact_path.is_file():
        raise ReleaseMetadataError(f"Release artifact is missing: {artifact_path}")
    validate_sbom(sbom_path)
    if not component.strip():
        raise ReleaseMetadataError("Release component is required")
    if not build_identity.strip():
        raise ReleaseMetadataError("Build workflow/run identity is required")
    if signing_status not in SIGNING_STATUSES:
        raise ReleaseMetadataError(f"signing_status must be one of {sorted(SIGNING_STATUSES)}")
    if signing_status == "signed" and not signing_identity:
        raise ReleaseMetadataError("A signed release must identify its signing identity")
    if signing_status == "unsigned" and signing_identity:
        raise ReleaseMetadataError("An unsigned release cannot claim a signing identity")
    revision = source_revision or _git_revision(root)
    if not re.fullmatch(r"[0-9a-f]{7,64}", revision):
        raise ReleaseMetadataError("source revision must be a Git SHA")
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "product": PRODUCT_NAME,
        "component": component,
        "version": version,
        "source_revision": revision,
        "artifact": {
            "name": artifact_path.name,
            "sha256": sha256_file(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
        },
        "sbom": {
            "name": sbom_path.name,
            "sha256": sha256_file(sbom_path),
            "format": "CycloneDX",
        },
        "provenance": {
            "build_identity": build_identity,
            "build_timestamp": _build_timestamp(),
            "build_environment": {
                "runner_os": os.getenv("RUNNER_OS", platform.system()),
                "python": platform.python_version(),
            },
            "dependency_state": dependency_state(root),
        },
        "signing": {"status": signing_status, "identity": signing_identity or None},
    }


def _required_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseMetadataError(f"Release manifest field '{field}' must be an object")
    return value


def validate_manifest(
    manifest_path: str | Path,
    *,
    version_file: str | Path,
    repo_root: str | Path,
) -> dict[str, Any]:
    path = Path(manifest_path).resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseMetadataError(f"Release manifest is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReleaseMetadataError(f"Release manifest is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseMetadataError("Release manifest root must be a JSON object")
    required = {"schema_version", "product", "component", "version", "source_revision", "artifact", "sbom", "provenance", "signing"}
    missing = sorted(name for name in required if value.get(name) in (None, "", {}))
    if missing:
        raise ReleaseMetadataError("Release manifest is missing required fields: " + ", ".join(missing))
    if value["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ReleaseMetadataError("Release manifest schema version is unsupported")
    if value["product"] != PRODUCT_NAME:
        raise ReleaseMetadataError("Release manifest product is not CyberSage")
    if value["version"] != read_version(version_file):
        raise ReleaseMetadataError("Release manifest version does not match VERSION")
    if not re.fullmatch(r"[0-9a-f]{7,64}", str(value["source_revision"])):
        raise ReleaseMetadataError("Release manifest source_revision must be a Git SHA")

    artifact = _required_mapping(value["artifact"], "artifact")
    artifact_name = _safe_reference(artifact.get("name"), "artifact.name")
    artifact_path = path.parent / artifact_name
    if not artifact_path.is_file():
        raise ReleaseMetadataError("Release artifact referenced by manifest is missing")
    if artifact.get("sha256") != sha256_file(artifact_path):
        raise ReleaseMetadataError("Release artifact SHA-256 does not match manifest")
    if artifact.get("size_bytes") != artifact_path.stat().st_size:
        raise ReleaseMetadataError("Release artifact size does not match manifest")

    sbom = _required_mapping(value["sbom"], "sbom")
    sbom_name = _safe_reference(sbom.get("name"), "sbom.name")
    sbom_path = path.parent / sbom_name
    if sbom.get("format") != "CycloneDX":
        raise ReleaseMetadataError("Release manifest must reference a CycloneDX SBOM")
    validate_sbom(sbom_path)
    if sbom.get("sha256") != sha256_file(sbom_path):
        raise ReleaseMetadataError("SBOM SHA-256 does not match manifest")

    provenance = _required_mapping(value["provenance"], "provenance")
    if not isinstance(provenance.get("build_identity"), str) or not provenance["build_identity"]:
        raise ReleaseMetadataError("Release provenance must record build_identity")
    if not isinstance(provenance.get("build_timestamp"), str) or not provenance["build_timestamp"]:
        raise ReleaseMetadataError("Release provenance must record build_timestamp")
    if not isinstance(provenance.get("build_environment"), Mapping):
        raise ReleaseMetadataError("Release provenance must record build_environment")
    expected_dependencies = dependency_state(repo_root)
    if provenance.get("dependency_state") != expected_dependencies:
        raise ReleaseMetadataError("Release dependency state does not match the checked-out source")

    signing = _required_mapping(value["signing"], "signing")
    status = signing.get("status")
    identity = signing.get("identity")
    if status not in SIGNING_STATUSES:
        raise ReleaseMetadataError("Release signing status is unsupported")
    if status == "signed" and not isinstance(identity, str):
        raise ReleaseMetadataError("Signed release manifest must record signing identity")
    if status == "unsigned" and identity is not None:
        raise ReleaseMetadataError("Unsigned release manifest must not record signing identity")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or validate CyberSage release provenance metadata")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create a release manifest from real artifact and SBOM files")
    create.add_argument("--version-file", default="VERSION")
    create.add_argument("--artifact", required=True)
    create.add_argument("--sbom", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--component", default="Portable Assessment")
    create.add_argument("--build-identity", required=True)
    create.add_argument("--signing-status", choices=sorted(SIGNING_STATUSES), required=True)
    create.add_argument("--signing-identity")
    create.add_argument("--repo-root", default=".")
    create.add_argument("--source-revision")
    validate = commands.add_parser("validate", help="Validate a release manifest against its files and source inputs")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--version-file", default="VERSION")
    validate.add_argument("--repo-root", default=".")
    validate_sbom_command = commands.add_parser("validate-sbom", help="Validate a generated CycloneDX SBOM")
    validate_sbom_command.add_argument("--sbom", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "create":
            manifest = create_manifest(
                version_file=args.version_file,
                artifact=args.artifact,
                sbom=args.sbom,
                component=args.component,
                build_identity=args.build_identity,
                signing_status=args.signing_status,
                signing_identity=args.signing_identity,
                repo_root=args.repo_root,
                source_revision=args.source_revision,
            )
            output = Path(args.output)
            output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            validate_manifest(output, version_file=args.version_file, repo_root=args.repo_root)
            print(f"Created and validated release manifest: {output}")
        elif args.command == "validate":
            validate_manifest(args.manifest, version_file=args.version_file, repo_root=args.repo_root)
            print(f"Validated release manifest: {args.manifest}")
        else:
            validate_sbom(args.sbom)
            print(f"Validated CycloneDX SBOM: {args.sbom}")
    except ReleaseMetadataError as exc:
        raise SystemExit(f"release metadata validation failed: {exc}") from exc


if __name__ == "__main__":
    main()
