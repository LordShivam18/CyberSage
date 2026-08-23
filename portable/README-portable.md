# CyberSage Portable Assessment

CyberSage Portable Assessment is a Windows-first, offline defensive posture
scanner. It collects only the system facts required for its checks, does not
remediate the device, and does not upload telemetry automatically.

The repository-root `VERSION` file is authoritative. The Windows release
workflow creates a checksum, CycloneDX SBOM, and release manifest beside the
archive. A build is explicitly `unsigned` unless the workflow was manually run
with signing required and a configured certificate was successfully validated.

See `docs/portable-assessment.md` and `docs/release-security.md` from the
repository root for use and release-verification guidance.
