"""HTTP client with egress allowlist, identity headers, and retry policy.

All outbound HTTP from the producer flows through :func:`get`. The host
allowlist (:data:`_ALLOWED_HOSTS`) is the choke point: anything not on
the list raises :class:`ValueError` at the validator, before any socket
is opened. The pattern is borrowed from
``qte77/gha-rxiv-feed-action/src/fetchers/common.py``.

Tunable knobs (User-Agent, timeout, retry budget, NVD API key) come from
:class:`gha_sec_feed.config.AppSettings`. Security-critical invariants
(allowlist, retryable status codes, backoff math) stay as code constants
— an env var that adds an outbound host or silences the retry policy
would be exactly the threat the allowlist defends against.
"""

from __future__ import annotations

from time import sleep
from typing import Final
from urllib.parse import urlparse

import httpx

from gha_sec_feed.config import settings

_ALLOWED_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "services.nvd.nist.gov",
        "www.cisa.gov",
    }
)

_DEFAULT_ACCEPT: Final[str] = "application/json"

# Server-to-server API clients have no "referring page" semantics —
# Referer is a browser concept describing the page that linked to the
# current request. Sending one from a non-browser caller is at best
# meaningless and at worst trips bot-detection heuristics that look
# for browser-like header shapes paired with non-browser User-Agents.
# This module therefore does NOT auto-inject a default Referer. The
# constant is retained only as a generic placeholder value for the
# rare caller that explicitly opts in via the `headers` parameter; a
# topic-neutral host (google.com) is used so the value carries no
# identity signal about this project or any of its forks.
_DEFAULT_REFERER: Final[str] = "https://google.com"

_RETRY_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})
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
    """Merge caller headers with identity defaults + conditional NVD apiKey.

    Defaults injected only when the caller has not already supplied the
    same header (case-insensitive). NVD ``apiKey`` is added only for the
    NVD host when ``NVD_API_KEY`` is set via :class:`AppSettings`.
    """
    s = settings()
    merged: dict[str, str] = dict(headers) if headers else {}
    keys_lower = {k.lower() for k in merged}
    if "user-agent" not in keys_lower:
        merged["User-Agent"] = s.user_agent
    if "accept" not in keys_lower:
        merged["Accept"] = _DEFAULT_ACCEPT
    # Referer is intentionally NOT auto-injected — see module docstring.
    if urlparse(url).hostname == _NVD_HOST and "apikey" not in keys_lower:
        if s.nvd_api_key is not None:
            merged["apiKey"] = s.nvd_api_key.get_secret_value()
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
    params: dict[str, str] | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
    _transport: httpx.BaseTransport | None = None,
) -> bytes:
    """Fetch ``url`` through the allowlisted HTTP client.

    Args:
        url: HTTPS URL whose host is in :data:`_ALLOWED_HOSTS`.
        headers: Optional caller headers; merged with identity defaults.
            Caller-supplied keys win (case-insensitive).
        timeout: Per-attempt timeout in seconds. Defaults to
            ``AppSettings.http_timeout`` (30s).
        max_retries: Total attempts before raising. Defaults to
            ``AppSettings.http_max_retries`` (3).
        _transport: Test seam — production callers leave unset.

    Returns:
        Response body on the first ``2xx``.

    Raises:
        ValueError: URL violates egress policy.
        RuntimeError: Non-retryable status, or retries exhausted.
    """
    _validate_url(url)
    s = settings()
    effective_timeout = s.http_timeout if timeout is None else timeout
    effective_retries = s.http_max_retries if max_retries is None else max_retries
    merged_headers = _build_headers(url, headers)
    last_status: int | None = None
    with httpx.Client(transport=_transport, timeout=effective_timeout) as client:
        for attempt in range(effective_retries):
            resp = client.get(url, params=params, headers=merged_headers)
            if resp.status_code < 400:
                return resp.content
            last_status = resp.status_code
            if resp.status_code not in _RETRY_STATUS:
                raise RuntimeError(f"HTTP {resp.status_code} for {url}")
            if attempt < effective_retries - 1:
                _sleep(_retry_delay(resp, attempt))
    raise RuntimeError(f"HTTP {last_status} after {effective_retries} attempts: {url}")
