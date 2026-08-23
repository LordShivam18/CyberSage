"""Tests for backend import validation (client-side importer only)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

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


# ---------------------------------------------------------------------------
# URL scheme validation (B310 remediation)
# ---------------------------------------------------------------------------


class TestURLSchemeValidation:
    """Ensure _validate_url_scheme rejects dangerous URL schemes."""

    # -- Allowed schemes --

    def test_https_allowed(self):
        """https scheme must be accepted."""
        from cybersage_portable.importer import _validate_url_scheme
        _validate_url_scheme("https://cybersage.example.com/api/v1/assessments/import")

    def test_http_allowed(self):
        """http scheme must be accepted."""
        from cybersage_portable.importer import _validate_url_scheme
        _validate_url_scheme("http://cybersage.example.com/api/v1/assessments/import")

    # -- Rejected schemes --

    def test_file_scheme_rejected(self):
        """file:// must be rejected."""
        from cybersage_portable.importer import _validate_url_scheme
        with pytest.raises(ValueError, match="not permitted"):
            _validate_url_scheme("file:///etc/passwd")

    def test_ftp_scheme_rejected(self):
        """ftp:// must be rejected."""
        from cybersage_portable.importer import _validate_url_scheme
        with pytest.raises(ValueError, match="not permitted"):
            _validate_url_scheme("ftp://server.example.com/report.json")

    def test_custom_scheme_rejected(self):
        """Arbitrary custom scheme must be rejected."""
        from cybersage_portable.importer import _validate_url_scheme
        with pytest.raises(ValueError, match="not permitted"):
            _validate_url_scheme("myscheme://example.com/path")

    def test_empty_scheme_rejected(self):
        """Empty/missing scheme must be rejected."""
        from cybersage_portable.importer import _validate_url_scheme
        with pytest.raises(ValueError, match="not permitted"):
            _validate_url_scheme("//example.com/path")

    def test_empty_string_rejected(self):
        """Empty string must be rejected."""
        from cybersage_portable.importer import _validate_url_scheme
        with pytest.raises(ValueError, match="not permitted"):
            _validate_url_scheme("")

    # -- Rejected schemes never reach urlopen --

    def test_file_scheme_never_reaches_urlopen(self):
        """Rejected file:// scheme must not trigger a real network request."""
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        with patch("cybersage_portable.importer.urllib.request.urlopen") as mock_urlopen:
            try:
                import_to_server("file:///etc/passwd", "token", Path(fh_name))
                assert False, "Should have raised"
            except ValueError as exc:
                assert "not permitted" in str(exc).lower()
            mock_urlopen.assert_not_called()

    def test_ftp_scheme_never_reaches_urlopen(self):
        """Rejected ftp:// scheme must not trigger a real network request."""
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        with patch("cybersage_portable.importer.urllib.request.urlopen") as mock_urlopen:
            try:
                import_to_server("ftp://server.example.com", "token", Path(fh_name))
                assert False, "Should have raised"
            except ValueError as exc:
                assert "not permitted" in str(exc).lower()
            mock_urlopen.assert_not_called()

    def test_custom_scheme_never_reaches_urlopen(self):
        """Rejected custom scheme must not trigger a real network request."""
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        with patch("cybersage_portable.importer.urllib.request.urlopen") as mock_urlopen:
            try:
                import_to_server("gopher://example.com", "token", Path(fh_name))
                assert False, "Should have raised"
            except ValueError as exc:
                assert "not permitted" in str(exc).lower()
            mock_urlopen.assert_not_called()

    def test_malformed_url_never_reaches_urlopen(self):
        """Malformed URL must not trigger a real network request."""
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        with patch("cybersage_portable.importer.urllib.request.urlopen") as mock_urlopen:
            try:
                import_to_server("not-a-url", "token", Path(fh_name))
                assert False, "Should have raised"
            except ValueError as exc:
                assert "not permitted" in str(exc).lower()
            mock_urlopen.assert_not_called()

    def test_allowed_scheme_calls_urlopen(self):
        """Valid https:// must proceed to urlopen (which is mocked here)."""
        from cybersage_portable.importer import import_to_server
        report = minimal_valid_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as fh:
            json.dump(report, fh)
            fh_name = fh.name
        fake_response = json.dumps({"status": "ok"}).encode("utf-8")
        with patch("cybersage_portable.importer.urllib.request.urlopen") as mock_urlopen:
            from unittest.mock import MagicMock
            mock_resp = MagicMock()
            mock_resp.read.return_value = fake_response
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            result = import_to_server("https://cybersage.example.com", "token", Path(fh_name))
            assert result == {"status": "ok"}
            mock_urlopen.assert_called_once()
