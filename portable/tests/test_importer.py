"""Tests for backend import validation (client-side importer only)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .conftest import minimal_valid_report
from cybersage_portable.models import verify_checksum


class TestImporterClientValidation:
    """Test local validation in importer.py (no real HTTP calls)."""

    def test_tampered_report_checksum_fails(self):
        """A tampered report must fail checksum verification before transmission."""
        report = minimal_valid_report()
        report["privilege_level"] = "administrator"  # tamper
        assert not verify_checksum(report)

    def test_wrong_schema_version_rejected(self):
        """Importer should reject unknown schema versions."""
        from unittest.mock import patch
        report = minimal_valid_report()
        report["schema_version"] = "assessment.v99"
        # Update checksum for the tampered report
        from cybersage_portable.models import compute_checksum
        report["checksum"] = compute_checksum(report)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name

        from cybersage_portable.importer import import_to_server
        try:
            import_to_server("https://localhost", "dummy-token", Path(fh_name))
            assert False, "Should have raised"
        except ValueError as exc:
            assert "schema_version" in str(exc).lower() or "Unsupported" in str(exc)

    def test_file_too_large_rejected(self):
        """Files over 10 MB must be rejected without transmission."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            fh.write(b"x" * (10 * 1024 * 1024 + 1))
            fh_name = fh.name

        from cybersage_portable.importer import import_to_server
        try:
            import_to_server("https://localhost", "dummy-token", Path(fh_name))
            assert False, "Should have raised"
        except ValueError as exc:
            assert "10 MB" in str(exc)

    def test_missing_server_raises(self):
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        try:
            import_to_server("", "token", Path(fh_name))
            assert False
        except ValueError:
            pass

    def test_checksum_same_content_idempotent(self):
        """Same assessment_id + same checksum produces same canonical payload."""
        report1 = minimal_valid_report("ffffffff-ffff-4fff-afff-ffffffffffff")
        report2 = minimal_valid_report("ffffffff-ffff-4fff-afff-ffffffffffff")
        from cybersage_portable.models import compute_checksum
        assert compute_checksum(report1) == compute_checksum(report2)

    def test_create_alerts_defaults_false(self):
        """The importer must default create_alerts to False."""
        import inspect
        from cybersage_portable.importer import import_to_server
        sig = inspect.signature(import_to_server)
        param = sig.parameters.get("create_alerts")
        assert param is not None
        assert param.default is False
