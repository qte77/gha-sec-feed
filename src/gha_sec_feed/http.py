"""HTTP client with egress allowlist, identity headers, and retry policy.

All outbound HTTP from the producer flows through :func:`get`. The host
allowlist (:data:`_ALLOWED_HOSTS`) is the choke point: anything not on
the list raises :class:`ValueError` at the validator, before any socket
is opened. The pattern is borrowed from
``qte77/gha-rxiv-feed-action/src/fetchers/common.py``.
"""

from __future__ import annotations

from os import environ
from time import sleep
from typing import Final
from urllib.parse import urlparse

import httpx

from . import __version__

_ALLOWED_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "services.nvd.nist.gov",
        "www.cisa.gov",
    }
)

_DEFAULT_UA: Final[str] = f"gha-sec-feed/{__version__} (+https://github.com/qte77/gha-sec-feed)"
_DEFAULT_ACCEPT: Final[str] = "application/json"

_RETRY_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})
_DEFAULT_TIMEOUT: Final[float] = 30.0
_DEFAULT_RETRIES: Final[int] = 3
_BACKOFF_BASE: Final[float] = 0.2
_BACKOFF_FACTOR: Final[float] = 2.0

_NVD_HOST: Final[str] = "services.nvd.nist.gov"


def _sleep(seconds: float) -> None:
    """Indirection over :func:`time.sleep` so tests can intercept retry waits."""
    sleep(seconds)


def _validate_url(url: str) -> None:
    """Reject URLs that violate the egress policy.

    Raises:
        ValueError: scheme is not ``https``, port is not 443, userinfo or
            fragment is present, or host is not in :data:`_ALLOWED_HOSTS`.
    """
    parts = urlparse(url)
    if parts.scheme != "https":
        raise ValueError(f"Only HTTPS URLs allowed, got: {url[:80]}")
    if parts.username or parts.password:
        raise ValueError(f"Userinfo not allowed in URL: {url[:80]}")
    if parts.fragment:
        raise ValueError(f"Fragment not allowed in URL: {url[:80]}")
    if parts.port not in (None, 443):
        raise ValueError(f"Non-443 port not allowed: {url[:80]}")
    if parts.hostname not in _ALLOWED_HOSTS:
        raise ValueError(f"Host not in allowlist: {parts.hostname}")


def _build_headers(url: str, headers: dict[str, str] | None) -> dict[str, str]:
    """Merge caller headers with identity defaults + conditional NVD apiKey."""
    merged: dict[str, str] = dict(headers) if headers else {}
    keys_lower = {k.lower() for k in merged}
    if "user-agent" not in keys_lower:
        merged["User-Agent"] = _DEFAULT_UA
    if "accept" not in keys_lower:
        merged["Accept"] = _DEFAULT_ACCEPT
    if urlparse(url).hostname == _NVD_HOST and "apikey" not in keys_lower:
        nvd_key = environ.get("NVD_API_KEY")
        if nvd_key:
            merged["apiKey"] = nvd_key
    return merged


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    """Compute next sleep duration: Retry-After if present, else exponential."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return float(retry_after)
        except ValueError:
            pass
    return _BACKOFF_BASE * (_BACKOFF_FACTOR**attempt)


def get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    max_retries: int = _DEFAULT_RETRIES,
    _transport: httpx.BaseTransport | None = None,
) -> bytes:
    """Fetch ``url`` through the allowlisted HTTP client.

    Args:
        url: HTTPS URL whose host is in :data:`_ALLOWED_HOSTS`.
        headers: Optional caller headers; merged with identity defaults.
            Caller-supplied keys win (case-insensitive).
        timeout: Per-attempt timeout in seconds.
        max_retries: Total attempts before raising.
        _transport: Test seam — production callers leave unset.

    Returns:
        Response body on the first ``2xx``.

    Raises:
        ValueError: URL violates egress policy.
        RuntimeError: Non-retryable status, or retries exhausted.
    """
    _validate_url(url)
    merged_headers = _build_headers(url, headers)
    last_status: int | None = None
    with httpx.Client(transport=_transport, timeout=timeout) as client:
        for attempt in range(max_retries):
            resp = client.get(url, headers=merged_headers)
            if resp.status_code < 400:
                return resp.content
            last_status = resp.status_code
            if resp.status_code not in _RETRY_STATUS:
                raise RuntimeError(f"HTTP {resp.status_code} for {url}")
            if attempt < max_retries - 1:
                _sleep(_retry_delay(resp, attempt))
    raise RuntimeError(f"HTTP {last_status} after {max_retries} attempts: {url}")
