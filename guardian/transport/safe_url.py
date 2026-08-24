"""Safe URL construction for Guardian HTTP calls.

Provides explicit URL parsing and scheme validation to ensure
only http:// and https:// URLs reach urlopen.
"""

from __future__ import annotations

from urllib.parse import urlparse


ALLOWED_SCHEMES = frozenset({"http", "https"})
REJECTED_SCHEMES = frozenset({"file", "ftp", "ftps", "data", "javascript"})


class InvalidSchemeError(Exception):
    """Raised when a URL uses a disallowed scheme."""


def validate_url_scheme(url: str) -> str:
    """Validate that a URL uses only http or https scheme.

    Args:
        url: The URL to validate.

    Returns:
        The validated URL unchanged.

    Raises:
        InvalidSchemeError: If the scheme is not http or https.
        ValueError: If the URL is empty or unparseable.
    """
    if not url or not url.strip():
        raise ValueError("URL must not be empty")

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        raise InvalidSchemeError(
            f"URL scheme '{scheme}' is not allowed. "
            f"Only {sorted(ALLOWED_SCHEMES)} are permitted."
        )

    return url


def build_api_url(base_url: str, path: str) -> str:
    """Build an API URL from a base URL and path.

    Validates that the base URL uses an allowed scheme before construction.

    Args:
        base_url: The backend base URL (e.g., 'http://localhost:8000').
        path: The API path (e.g., 'api/v1/guardian/events').

    Returns:
        The constructed URL.
    """
    validate_url_scheme(base_url)
    normalized = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return normalized + path
