# Release Security and Distribution

## Release Contract

`VERSION` is the authoritative CyberSage release version. The frontend package
must match it, the portable package derives its version from it, and the
backend API reads it at runtime. `python scripts/version_contract.py` fails
when these sources disagree.

The Windows portable workflow creates a versioned archive, adjacent SHA-256
checksum, CycloneDX SBOM, and JSON release manifest. The manifest records the
archive checksum and size, SBOM checksum, source revision, workflow/run
identity, build timestamp and environment, and hashes of release dependency
inputs. `scripts/release_metadata.py validate` rechecks every recorded file and
source input before evidence is uploaded.

## Supply-Chain Controls

- Backend, portable build, and security-tool declarations use exact versions.
- Frontend installation uses the committed `frontend/package-lock.json` and
  `npm ci`.
- Workflows use immutable commit SHAs for third-party actions and request only
  `contents: read` permissions.
- The runtime gate scans committed content with Gitleaks, runs Bandit on Python
  application code, audits Python requirements with `pip-audit --strict`,
  audits production frontend dependencies with `npm audit --omit=dev`, and
  checks workflow hardening with zizmor.
- The portable release environment generates a CycloneDX SBOM from its actual
  installed environment and validates that it includes a component list.

`pip-audit --strict` and high-or-greater production `npm audit` findings block
the gate. There is no hidden ignore list or automatic vulnerability exception.

## Verification Procedure

Obtain the archive, `.sha256`, `.sbom.cdx.json`, and
`.release-manifest.json` from the same GitHub Actions artifact. Calculate the
archive SHA-256 and compare it with both the checksum file and manifest. Then
validate the manifest against the source revision it names and inspect the SBOM
and its checksum. This links source revision to dependency inputs, build
identity, SBOM, and distributed archive.

The workflow makes dependency and metadata resolution repeatable, but it does
not claim byte-for-byte reproducible PyInstaller binaries across runner images
or build times. Docker base-image tags are controlled configuration inputs but
are not digest-pinned or image-scanned yet.

## Windows Signing Status

Portable artifacts are `unsigned` by default. No placeholder certificate,
self-signing, or fabricated signature status is used. A manually dispatched
build with `require_signing=true` fails closed unless a certificate, its
password, a signing identity, and `signtool.exe` are available. The workflow
then validates the Authenticode signature before recording `signed` and its
identity in the manifest. Certificate material is scoped to that step and
removed from the runner temporary directory afterwards.

Repository administrators must configure protected GitHub secrets for the PFX
and password and a non-secret signing-identity variable before requesting a
signed release. This repository does not claim that signing infrastructure is
currently configured.
