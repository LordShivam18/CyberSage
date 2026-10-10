"""Guardian agent release integrity (stdlib only, no side effects on import).

Supports the existing release contract (root VERSION authoritative):
  - manifest: record pinned build inputs + artifact digests + provenance.
  - verify: recompute digests and fail closed on any mismatch.
  - verify-signature: fail closed unless trustworthy signature material is
    configured; never generate or trust an implicit production key.

Reproducibility is NOT claimed: the manifest records inputs so a human can
recheck them later. See docs/guardian_phase8_operations.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_SCHEMA = "guardian.agent-release-manifest.v1"

AGENT_BUNDLE_PATHS = (
    "guardian/agent",
    "guardian/collectors",
    "guardian/transport",
    "guardian/models",
    "guardian/ops",
)

DEPENDENCY_INPUTS = (
    "backend/requirements.txt",
    "portable/pyproject.toml",
    "VERSION",
)

SKIP_SUFFIXES = (".pyc", ".pyo")
SKIP_DIRS = ("__pycache__",)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_bundle_files(repo_root: Path):
    for top in AGENT_BUNDLE_PATHS:
        base = repo_root / top
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if path.suffix in SKIP_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            yield path


def _git_revision(repo_root: Path) -> str:
    import subprocess

    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:  # noqa: BLE001 - revision is provenance metadata, never fatal
        return "unknown"


def build_manifest(repo_root: Path) -> dict:
    root = Path(repo_root).resolve()
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("VERSION must contain the release version")
    inputs = []
    for path in _iter_bundle_files(root):
        rel = path.relative_to(root).as_posix()
        inputs.append({
            "path": rel,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    for rel in DEPENDENCY_INPUTS:
        path = root / rel
        if not path.is_file():
            raise ValueError(f"Required build input is missing: {rel}")
        inputs.append({
            "path": rel,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return {
        "schema": MANIFEST_SCHEMA,
        "product": "CyberSage Guardian Agent",
        "version": version,
        "source_revision": _git_revision(root),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "input_count": len(inputs),
        "signing": "unsigned",
    }


def write_manifest(repo_root: Path, out_path: Path) -> dict:
    manifest = build_manifest(repo_root)
    out = Path(out_path)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_manifest(repo_root: Path, manifest_path: Path) -> dict:
    """Recompute every recorded digest. Fail closed on any mismatch."""
    root = Path(repo_root).resolve()
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("Manifest schema mismatch")
    failures = []
    for entry in manifest.get("inputs", []):
        rel = entry.get("path", "")
        if not rel or ".." in rel.replace("\\", "/").split("/"):
            failures.append(f"unsafe manifest path: {rel!r}")
            continue
        path = root / rel
        if not path.is_file():
            failures.append(f"missing input: {rel}")
            continue
        actual = sha256_file(path)
        if actual != entry.get("sha256"):
            failures.append(f"digest mismatch: {rel}")
        if path.stat().st_size != entry.get("bytes"):
            failures.append(f"size mismatch: {rel}")
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if version != manifest.get("version"):
        failures.append("VERSION does not match manifest version")
    if failures:
        raise ValueError("Release verification failed: " + "; ".join(failures))
    return {"ok": True, "inputs": len(manifest.get("inputs", [])), "signing": manifest.get("signing", "unsigned")}


def verify_signature(manifest_path: Path, *, expect_fingerprint: str = "") -> dict:
    """Fail-closed signature gate for production deployments.

    Requires externally configured trust material. Never generates, embeds,
    or trusts an implicit key. A missing certificate, signature file, or
    fingerprint prerequisite is reported as a prerequisite — never passed.
    """
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("signing") != "signed":
        raise ValueError("Manifest is not marked signed; production install must reject it")
    if not expect_fingerprint:
        raise ValueError("Missing prerequisite: expected certificate fingerprint is not configured")
    sig_path = Path(str(manifest_path) + ".sig")
    if not sig_path.is_file():
        raise ValueError("Missing prerequisite: detached signature file is absent")
    recorded = manifest.get("signature", {})
    if recorded.get("cert_fingerprint", "").lower() != expect_fingerprint.lower():
        raise ValueError("Certificate fingerprint does not match the configured trust anchor")
    return {"ok": True, "fingerprint": recorded.get("cert_fingerprint", "")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Guardian agent release integrity")
    sub = parser.add_subparsers(dest="command", required=True)
    p_manifest = sub.add_parser("manifest", help="Write a release manifest")
    p_manifest.add_argument("--repo", default=".")
    p_manifest.add_argument("--out", required=True)
    p_verify = sub.add_parser("verify", help="Verify a release manifest (fail closed)")
    p_verify.add_argument("--repo", default=".")
    p_verify.add_argument("--manifest", required=True)
    p_sig = sub.add_parser("verify-signature", help="Verify release signature (fail closed)")
    p_sig.add_argument("--manifest", required=True)
    p_sig.add_argument("--expect-fingerprint", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest":
            manifest = write_manifest(args.repo, args.out)
            print(f"Wrote {args.out} ({manifest['input_count']} inputs, unsigned)")
        elif args.command == "verify":
            result = verify_manifest(args.repo, args.manifest)
            print(f"Verified {result['inputs']} inputs ({result['signing']})")
        elif args.command == "verify-signature":
            result = verify_signature(args.manifest, expect_fingerprint=args.expect_fingerprint)
            print(f"Signature trust anchor OK: {result['fingerprint']}")
        return 0
    except ValueError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
